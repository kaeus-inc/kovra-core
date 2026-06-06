//! Embedded metadata index (ADR-0001 §A.4–6): a redb store treated as a
//! **rebuildable cache**, never the source of truth.
//!
//! It holds **metadata only** — coordinate, environment/component/key,
//! sensitivity, mode (literal/reference) + ref scheme, the **truncated**
//! fingerprint (§10.4), timestamps, origin vault, and the record path. It
//! **never** holds a value and never a full fingerprint (I12). The entries are
//! AEAD-sealed at rest (the ADR's default lean), so the redb file carries no
//! cleartext coordinates either.
//!
//! Because it is derived, losing or corrupting it is never data loss: it is
//! rebuilt by scanning the records ([`Index::rebuild_from`]). The resolution
//! path never reads it (ADR-0001 §A.5) — it serves enumeration only (`list`,
//! Web UI inventory, shadowing, `doctor`).

use std::path::Path;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::crypto::{KEY_LEN, SealedRecord, open_bytes, seal_bytes};
use crate::error::CoreError;
use crate::fingerprint::fingerprint;
use crate::record::SecretRecord;
use crate::sensitivity::Sensitivity;
use crate::store;

/// Default index filename within a vault directory.
pub const INDEX_FILE: &str = "index.redb";

/// id (blake3 storage id) → sealed `IndexEntry` JSON.
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
/// Index-wide generation counter (rebuild marker). Not sensitive.
const GEN: TableDefinition<&str, u64> = TableDefinition::new("generation");
const GEN_KEY: &str = "g";

/// Whether a record stores its value inline or points elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordMode {
    /// Value lives (encrypted) in the record.
    Literal,
    /// Record is a pointer to an external provider.
    Reference,
    /// An asymmetric keypair (KOV-12): a sealed private half (optional) and an
    /// OpenSSH public half.
    Keypair,
    /// A TOTP enrollment (KOV-11): a sealed seed + non-secret params.
    Totp,
}

/// One metadata row. Carries no value and only the truncated fingerprint (I12).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IndexEntry {
    /// Blake3 storage id (also the index key).
    pub id: String,
    /// Environment segment.
    pub environment: String,
    /// Component segment.
    pub component: String,
    /// Key segment.
    pub key: String,
    /// Sensitivity level.
    pub sensitivity: Sensitivity,
    /// Literal or reference.
    pub mode: RecordMode,
    /// Provider scheme for references (e.g. `azure-kv`); `None` for literals.
    pub ref_scheme: Option<String>,
    /// Truncated fingerprint of the value (§10.4); literals only, never full.
    pub fingerprint: Option<String>,
    /// Creation timestamp (from the record).
    pub created: String,
    /// Last-update timestamp (from the record).
    pub updated: String,
    /// Origin vault label, e.g. `global` or `projects/<name>`.
    pub origin: String,
    /// Path of the backing `.sec` record.
    pub record_path: String,
}

impl IndexEntry {
    /// Derive a metadata entry from an opened record. The value is read only to
    /// compute the **truncated** fingerprint; it is not retained.
    pub fn from_record(id: &str, record: &SecretRecord, origin: &str, record_path: &str) -> Self {
        // Fields common to all modalities (same names and types in each arm).
        let (sensitivity, environment, component, key, created, updated) = match record {
            SecretRecord::Literal {
                sensitivity,
                environment,
                component,
                key,
                created,
                updated,
                ..
            }
            | SecretRecord::Reference {
                sensitivity,
                environment,
                component,
                key,
                created,
                updated,
                ..
            }
            | SecretRecord::Keypair {
                sensitivity,
                environment,
                component,
                key,
                created,
                updated,
                ..
            }
            | SecretRecord::Totp {
                sensitivity,
                environment,
                component,
                key,
                created,
                updated,
                ..
            } => (sensitivity, environment, component, key, created, updated),
        };
        // The fields that distinguish the modalities. The keypair's fingerprint
        // is of its **public** key (public material — safe to index, lets an
        // operator confirm the key without ever touching the private half, I12);
        // the private half is never fingerprinted into the index.
        let (mode, ref_scheme, fingerprint) = match record {
            SecretRecord::Literal { value, .. } => {
                (RecordMode::Literal, None, Some(fingerprint(value.expose())))
            }
            SecretRecord::Reference { reference, .. } => {
                (RecordMode::Reference, ref_scheme(reference), None)
            }
            SecretRecord::Keypair { public, .. } => (
                RecordMode::Keypair,
                None,
                Some(fingerprint(public.as_bytes())),
            ),
            // The TOTP fingerprint is of the **non-secret parameters** only
            // (algorithm/digits/period) — never the seed (I12). It lets an
            // operator tell two enrollments apart without ever touching the seed.
            SecretRecord::Totp {
                algorithm,
                digits,
                period,
                ..
            } => (
                RecordMode::Totp,
                None,
                Some(fingerprint(
                    format!("totp:{}:{digits}:{period}", algorithm.as_str()).as_bytes(),
                )),
            ),
        };
        IndexEntry {
            id: id.to_string(),
            environment: environment.clone(),
            component: component.clone(),
            key: key.clone(),
            sensitivity: *sensitivity,
            mode,
            ref_scheme,
            fingerprint,
            created: created.clone(),
            updated: updated.clone(),
            origin: origin.to_string(),
            record_path: record_path.to_string(),
        }
    }

    /// The canonical coordinate path `<env>/<component>/<key>` — derived, not
    /// stored (it is exactly the three segment fields joined).
    pub fn coordinate(&self) -> String {
        format!("{}/{}/{}", self.environment, self.component, self.key)
    }
}

/// The scheme of a reference URI (`azure-kv://...` → `azure-kv`).
fn ref_scheme(reference: &str) -> Option<String> {
    reference
        .split_once("://")
        .map(|(scheme, _)| scheme.to_string())
}

/// An embedded metadata index over one vault directory.
pub struct Index {
    db: Database,
}

impl Index {
    /// Open (or create) the index at `dir/index.redb`.
    pub fn open(dir: &Path) -> Result<Self, CoreError> {
        store::ensure_dir(dir)?;
        let path = dir.join(INDEX_FILE);
        let existed = path.exists();
        let db = Database::create(&path).map_err(|e| CoreError::Index(e.to_string()))?;
        if !existed {
            store::restrict(&path, 0o600)?;
        }
        Ok(Self { db })
    }

    /// Insert or replace an entry. The entry is sealed before it touches disk.
    pub fn upsert(&self, entry: &IndexEntry, key: &[u8; KEY_LEN]) -> Result<(), CoreError> {
        let plaintext =
            serde_json::to_vec(entry).map_err(|e| CoreError::Serialization(e.to_string()))?;
        let sealed = seal_bytes(&plaintext, key)?;
        let blob =
            serde_json::to_vec(&sealed).map_err(|e| CoreError::Serialization(e.to_string()))?;

        let txn = self.db.begin_write().map_err(idx)?;
        {
            let mut table = txn.open_table(META).map_err(idx)?;
            table
                .insert(entry.id.as_str(), blob.as_slice())
                .map_err(idx)?;
        }
        txn.commit().map_err(idx)?;
        Ok(())
    }

    /// Remove an entry by id (no-op if absent).
    pub fn remove(&self, id: &str) -> Result<(), CoreError> {
        let txn = self.db.begin_write().map_err(idx)?;
        {
            let mut table = txn.open_table(META).map_err(idx)?;
            table.remove(id).map_err(idx)?;
        }
        txn.commit().map_err(idx)?;
        Ok(())
    }

    /// Enumerate all metadata entries (unsealing each). Never decrypts a value —
    /// values live only in `.sec` records.
    pub fn list(&self, key: &[u8; KEY_LEN]) -> Result<Vec<IndexEntry>, CoreError> {
        let txn = self.db.begin_read().map_err(idx)?;
        let table = match txn.open_table(META) {
            Ok(t) => t,
            // No table yet → empty index.
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(CoreError::Index(e.to_string())),
        };
        let mut out = Vec::new();
        for row in table.iter().map_err(idx)? {
            let (_id, blob) = row.map_err(idx)?;
            let sealed: SealedRecord = serde_json::from_slice(blob.value())
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
            let plaintext = open_bytes(&sealed, key)?;
            let entry: IndexEntry = serde_json::from_slice(&plaintext)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
            out.push(entry);
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    /// The current generation counter (0 until the first rebuild).
    pub fn generation(&self) -> Result<u64, CoreError> {
        let txn = self.db.begin_read().map_err(idx)?;
        let table = match txn.open_table(GEN) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(e) => return Err(CoreError::Index(e.to_string())),
        };
        Ok(table
            .get(GEN_KEY)
            .map_err(idx)?
            .map(|v| v.value())
            .unwrap_or(0))
    }

    /// Rebuild the index from the records in `store_dir`, tolerantly: corrupt
    /// records are skipped (already quarantined by the loader). Clears the
    /// existing table and bumps the generation counter. Self-healing — a stale
    /// or lost index is reconstructed from the source of truth (ADR-0001 §A.6).
    pub fn rebuild_from(
        &self,
        store_dir: &Path,
        origin: &str,
        key: &[u8; KEY_LEN],
    ) -> Result<store::LoadOutcome, CoreError> {
        let outcome = store::load_all(store_dir, key)?;
        let next_gen = self.generation()?.saturating_add(1);

        let txn = self.db.begin_write().map_err(idx)?;
        // Clear by dropping and recreating the table.
        txn.delete_table(META).map_err(idx)?;
        {
            let mut table = txn.open_table(META).map_err(idx)?;
            for (id, record) in &outcome.records {
                let path = store::record_path_for_id(store_dir, id);
                let entry = IndexEntry::from_record(id, record, origin, &path.to_string_lossy());
                let plaintext = serde_json::to_vec(&entry)
                    .map_err(|e| CoreError::Serialization(e.to_string()))?;
                let sealed = seal_bytes(&plaintext, key)?;
                let blob = serde_json::to_vec(&sealed)
                    .map_err(|e| CoreError::Serialization(e.to_string()))?;
                table.insert(id.as_str(), blob.as_slice()).map_err(idx)?;
            }
            let mut gen_table = txn.open_table(GEN).map_err(idx)?;
            gen_table.insert(GEN_KEY, next_gen).map_err(idx)?;
        }
        txn.commit().map_err(idx)?;
        Ok(outcome)
    }
}

/// Map any redb error to the opaque index error.
fn idx<E: std::fmt::Display>(e: E) -> CoreError {
    CoreError::Index(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinate::Coordinate;
    use crate::crypto::seal;
    use crate::secret::SecretValue;

    fn key() -> [u8; KEY_LEN] {
        [0x33; KEY_LEN]
    }

    fn literal(value: &str, k: &str) -> SecretRecord {
        SecretRecord::Literal {
            value: SecretValue::from(value),
            sensitivity: Sensitivity::Medium,
            revealable: false,
            environment: "prod".to_string(),
            component: "db".to_string(),
            key: k.to_string(),
            description: None,
            created: "2026-05-30T00:00:00Z".to_string(),
            updated: "2026-05-30T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn upsert_then_list_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(dir.path()).unwrap();
        let entry = IndexEntry::from_record(
            "abc",
            &literal("hunter2", "password"),
            "global",
            "/x/abc.sec",
        );
        index.upsert(&entry, &key()).unwrap();

        let listed = index.list(&key()).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0], entry);
        assert_eq!(listed[0].mode, RecordMode::Literal);
        assert!(listed[0].fingerprint.is_some());
    }

    #[test]
    fn remove_drops_entry() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(dir.path()).unwrap();
        let entry = IndexEntry::from_record("abc", &literal("v", "k"), "global", "/x/abc.sec");
        index.upsert(&entry, &key()).unwrap();
        index.remove("abc").unwrap();
        assert!(index.list(&key()).unwrap().is_empty());
    }

    #[test]
    fn reference_entry_has_scheme_and_no_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(dir.path()).unwrap();
        let record = SecretRecord::Reference {
            reference: "azure-kv://corp-kv/db-url".to_string(),
            sensitivity: Sensitivity::High,
            revealable: false,
            environment: "prod".to_string(),
            component: "db".to_string(),
            key: "url".to_string(),
            description: None,
            created: "2026-05-30T00:00:00Z".to_string(),
            updated: "2026-05-30T00:00:00Z".to_string(),
        };
        let entry = IndexEntry::from_record("ref1", &record, "global", "/x/ref1.sec");
        index.upsert(&entry, &key()).unwrap();
        let listed = index.list(&key()).unwrap();
        assert_eq!(listed[0].mode, RecordMode::Reference);
        assert_eq!(listed[0].ref_scheme.as_deref(), Some("azure-kv"));
        assert!(listed[0].fingerprint.is_none());
    }

    #[test]
    fn rebuild_reconstructs_and_bumps_generation() {
        let dir = tempfile::tempdir().unwrap();
        // Two records on disk.
        let a: Coordinate = "secret:prod/db/a".parse().unwrap();
        let b: Coordinate = "secret:prod/db/b".parse().unwrap();
        store::write_record(dir.path(), &a, &seal(&literal("va", "a"), &key()).unwrap()).unwrap();
        store::write_record(dir.path(), &b, &seal(&literal("vb", "b"), &key()).unwrap()).unwrap();

        let index = Index::open(dir.path()).unwrap();
        assert_eq!(index.generation().unwrap(), 0);

        let outcome = index.rebuild_from(dir.path(), "global", &key()).unwrap();
        assert_eq!(outcome.records.len(), 2);
        assert_eq!(index.list(&key()).unwrap().len(), 2);
        assert_eq!(index.generation().unwrap(), 1);

        // Rebuilding again is idempotent in content but bumps the generation.
        index.rebuild_from(dir.path(), "global", &key()).unwrap();
        assert_eq!(index.list(&key()).unwrap().len(), 2);
        assert_eq!(index.generation().unwrap(), 2);
    }

    #[test]
    fn raw_index_bytes_hold_no_plaintext_or_full_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(dir.path()).unwrap();
        let value = "super-secret-value";
        let entry =
            IndexEntry::from_record("abc", &literal(value, "password"), "global", "/x/abc.sec");
        index.upsert(&entry, &key()).unwrap();
        drop(index); // flush

        let raw = std::fs::read(dir.path().join(INDEX_FILE)).unwrap();
        // No plaintext value (I12) — it is never even in the entry.
        assert!(!contains(&raw, value.as_bytes()));
        // No cleartext coordinate (sealed at rest).
        assert!(!contains(&raw, b"prod/db/password"));
        // No full fingerprint — only the truncated one exists, and it is sealed.
        let full = blake3::hash(value.as_bytes()).to_hex().to_string();
        assert!(!contains(&raw, full.as_bytes()));
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
