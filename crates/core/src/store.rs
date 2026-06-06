//! Per-secret sealed-file store: the source of truth (ADR-0001 §A.1–3).
//!
//! Each secret is one independently AEAD-sealed record, filed as a single file
//! named `BLAKE3(coordinate).sec` under a vault directory. This is the
//! durability boundary: one corrupt file loses **one** secret, never the whole
//! vault.
//!
//! On-disk frame: a fixed header (magic [`FRAME_MAGIC`] + little-endian
//! [`FRAME_VERSION`]) followed by the JSON-serialized
//! [`SealedRecord`](crate::crypto::SealedRecord). The header lets the loader
//! reject foreign/garbage files cleanly and version the frame independently of
//! the sealed payload.
//!
//! Writes are atomic (temp → `fsync` → rotate previous to `.bak` → `rename`)
//! and files are `0600`. The loader is **tolerant**: a record that fails its
//! frame or its AEAD tag is quarantined and skipped, never aborting the scan.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::coordinate::Coordinate;
use crate::crypto::{KEY_LEN, SealedRecord, open};
use crate::error::CoreError;
use crate::record::SecretRecord;

/// Frame magic: marks a file as a kovra sealed record.
pub const FRAME_MAGIC: &[u8; 4] = b"KOVR";
/// On-disk frame version (independent of the vault schema version).
pub const FRAME_VERSION: u32 = 1;
/// Extension for a sealed record file.
pub const RECORD_EXT: &str = "sec";

const HEADER_LEN: usize = 4 + 4; // magic + u32 version

/// A record that could not be loaded, surfaced rather than aborting the scan.
/// The reason is a coordinate-free description (I12) — never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quarantined {
    /// The record id (file stem) that failed to load.
    pub id: String,
    /// Why it was quarantined (frame mismatch, AEAD failure, I/O error).
    pub reason: String,
}

/// Outcome of [`load_all`]: every decryptable record plus the quarantined ones.
#[derive(Debug, Default)]
pub struct LoadOutcome {
    /// Successfully opened records, keyed by record id (file stem).
    pub records: Vec<(String, SecretRecord)>,
    /// Records skipped because they failed to load (ADR-0001 §A.3).
    pub quarantined: Vec<Quarantined>,
}

/// The on-disk path of a record within `dir`, given its storage id (the
/// `<id>.sec` naming convention, owned here so callers never re-derive it).
pub fn record_path_for_id(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.{RECORD_EXT}"))
}

/// The on-disk path of a coordinate's record within `dir`.
pub fn record_path(dir: &Path, coord: &Coordinate) -> Result<PathBuf, CoreError> {
    Ok(record_path_for_id(dir, &coord.storage_id()?))
}

/// Frame a sealed record for storage: header + JSON payload.
fn frame(sealed: &SealedRecord) -> Result<Vec<u8>, CoreError> {
    let payload =
        serde_json::to_vec(sealed).map_err(|e| CoreError::Serialization(e.to_string()))?;
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(FRAME_MAGIC);
    out.extend_from_slice(&FRAME_VERSION.to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Parse a framed record back into a sealed record, validating the header.
fn unframe(bytes: &[u8]) -> Result<SealedRecord, CoreError> {
    if bytes.len() < HEADER_LEN || &bytes[..4] != FRAME_MAGIC {
        return Err(CoreError::Serialization(
            "not a kovra record frame".to_string(),
        ));
    }
    let version = u32::from_le_bytes(bytes[4..8].try_into().expect("checked length"));
    if version != FRAME_VERSION {
        return Err(CoreError::Serialization(format!(
            "unsupported record frame version {version}"
        )));
    }
    serde_json::from_slice(&bytes[HEADER_LEN..])
        .map_err(|e| CoreError::Serialization(e.to_string()))
}

/// Set restrictive permissions on a freshly created path. `0600` for files,
/// `0700` for directories. No-op on non-unix targets (Windows is L13). The
/// single owner of kovra's on-disk permission policy — the index reuses it for
/// `index.redb`.
#[cfg(unix)]
pub(crate) fn restrict(path: &Path, mode: u32) -> Result<(), CoreError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| CoreError::Io(format!("chmod {mode:o}: {e}")))
}

#[cfg(not(unix))]
pub(crate) fn restrict(_path: &Path, _mode: u32) -> Result<(), CoreError> {
    Ok(())
}

/// Create a vault directory (and parents) at `0700` if missing.
pub fn ensure_dir(dir: &Path) -> Result<(), CoreError> {
    if !dir.exists() {
        fs::create_dir_all(dir).map_err(|e| CoreError::Io(format!("create {dir:?}: {e}")))?;
        restrict(dir, 0o700)?;
    }
    Ok(())
}

/// Write a sealed record atomically: temp file → `fsync` → rotate any existing
/// record to `.bak` → `rename` into place. The result is `0600`.
pub fn write_record(
    dir: &Path,
    coord: &Coordinate,
    sealed: &SealedRecord,
) -> Result<(), CoreError> {
    ensure_dir(dir)?;
    let path = record_path(dir, coord)?;
    let tmp = path.with_extension(format!("{RECORD_EXT}.tmp"));
    let bytes = frame(sealed)?;

    {
        let mut f = File::create(&tmp).map_err(|e| CoreError::Io(format!("create tmp: {e}")))?;
        f.write_all(&bytes)
            .map_err(|e| CoreError::Io(format!("write tmp: {e}")))?;
        f.sync_all()
            .map_err(|e| CoreError::Io(format!("fsync tmp: {e}")))?;
    }
    restrict(&tmp, 0o600)?;

    if path.exists() {
        let bak = path.with_extension(format!("{RECORD_EXT}.bak"));
        fs::rename(&path, &bak).map_err(|e| CoreError::Io(format!("rotate .bak: {e}")))?;
    }
    fs::rename(&tmp, &path).map_err(|e| CoreError::Io(format!("rename into place: {e}")))?;
    Ok(())
}

/// Read and decrypt a single record by coordinate — the O(1) point-lookup path
/// used by resolution (it never touches the index, ADR-0001 §A.5). Returns
/// `Ok(None)` when the record does not exist.
pub fn read_record(
    dir: &Path,
    coord: &Coordinate,
    key: &[u8; KEY_LEN],
) -> Result<Option<SecretRecord>, CoreError> {
    let path = record_path(dir, coord)?;
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).map_err(|e| CoreError::Io(format!("read record: {e}")))?;
    let sealed = unframe(&bytes)?;
    Ok(Some(open(&sealed, key)?))
}

/// Load every record in a vault directory, tolerantly (ADR-0001 §A.3). A file
/// that fails its frame or its AEAD tag is quarantined and skipped; the scan
/// never aborts, so one corrupt record cannot hide the rest.
pub fn load_all(dir: &Path, key: &[u8; KEY_LEN]) -> Result<LoadOutcome, CoreError> {
    let mut outcome = LoadOutcome::default();
    if !dir.exists() {
        return Ok(outcome);
    }
    let entries = fs::read_dir(dir).map_err(|e| CoreError::Io(format!("read_dir: {e}")))?;
    for entry in entries {
        let entry = entry.map_err(|e| CoreError::Io(format!("dir entry: {e}")))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some(RECORD_EXT) {
            continue; // skip .bak, .tmp, index, anything not a record
        }
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();

        let opened = fs::read(&path)
            .map_err(|e| CoreError::Io(format!("read: {e}")))
            .and_then(|bytes| unframe(&bytes))
            .and_then(|sealed| open(&sealed, key));

        match opened {
            Ok(record) => outcome.records.push((id, record)),
            Err(e) => outcome.quarantined.push(Quarantined {
                id,
                reason: e.to_string(),
            }),
        }
    }
    Ok(outcome)
}

/// Remove a record (its `.sec` file). The `.bak` rotation, if any, is left in
/// place. No-op if the record does not exist.
pub fn delete_record(dir: &Path, coord: &Coordinate) -> Result<(), CoreError> {
    let path = record_path(dir, coord)?;
    if path.exists() {
        fs::remove_file(&path).map_err(|e| CoreError::Io(format!("remove record: {e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::seal;
    use crate::secret::SecretValue;
    use crate::sensitivity::Sensitivity;

    fn key() -> [u8; KEY_LEN] {
        [0x11; KEY_LEN]
    }

    fn coord(s: &str) -> Coordinate {
        s.parse().unwrap()
    }

    fn literal(value: &str) -> SecretRecord {
        SecretRecord::Literal {
            value: SecretValue::from(value),
            sensitivity: Sensitivity::Medium,
            revealable: false,
            environment: "prod".to_string(),
            component: "db".to_string(),
            key: "password".to_string(),
            description: None,
            created: "2026-05-30T00:00:00Z".to_string(),
            updated: "2026-05-30T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn write_then_read_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let c = coord("secret:prod/db/password");
        let sealed = seal(&literal("hunter2"), &key()).unwrap();
        write_record(dir.path(), &c, &sealed).unwrap();

        let got = read_record(dir.path(), &c, &key()).unwrap().unwrap();
        match got {
            SecretRecord::Literal { value, .. } => assert_eq!(value.expose(), b"hunter2"),
            other => panic!("expected literal, got {other:?}"),
        }
    }

    #[test]
    fn read_missing_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let c = coord("secret:prod/db/absent");
        assert!(read_record(dir.path(), &c, &key()).unwrap().is_none());
    }

    #[test]
    fn record_file_has_extension_and_hashed_name() {
        let dir = tempfile::tempdir().unwrap();
        let c = coord("secret:prod/db/password");
        write_record(dir.path(), &c, &seal(&literal("x"), &key()).unwrap()).unwrap();
        let path = record_path(dir.path(), &c).unwrap();
        assert!(path.exists());
        // filename is the blake3 hex id, never the cleartext coordinate
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(name.ends_with(".sec"));
        assert!(!name.contains("password"));
    }

    #[cfg(unix)]
    #[test]
    fn written_record_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let c = coord("secret:prod/db/password");
        write_record(dir.path(), &c, &seal(&literal("x"), &key()).unwrap()).unwrap();
        let mode = fs::metadata(record_path(dir.path(), &c).unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn overwrite_rotates_previous_to_bak() {
        let dir = tempfile::tempdir().unwrap();
        let c = coord("secret:prod/db/password");
        write_record(dir.path(), &c, &seal(&literal("v1"), &key()).unwrap()).unwrap();
        write_record(dir.path(), &c, &seal(&literal("v2"), &key()).unwrap()).unwrap();

        // current holds v2
        let current = read_record(dir.path(), &c, &key()).unwrap().unwrap();
        match current {
            SecretRecord::Literal { value, .. } => assert_eq!(value.expose(), b"v2"),
            other => panic!("expected literal, got {other:?}"),
        }
        // a .bak sibling exists
        let bak = record_path(dir.path(), &c)
            .unwrap()
            .with_extension(format!("{RECORD_EXT}.bak"));
        assert!(bak.exists());
    }

    #[test]
    fn load_all_quarantines_corrupt_and_loads_siblings() {
        let dir = tempfile::tempdir().unwrap();
        let good = coord("secret:prod/db/good");
        let bad = coord("secret:prod/db/bad");
        write_record(
            dir.path(),
            &good,
            &seal(&literal("good-val"), &key()).unwrap(),
        )
        .unwrap();
        write_record(
            dir.path(),
            &bad,
            &seal(&literal("bad-val"), &key()).unwrap(),
        )
        .unwrap();

        // Corrupt the ciphertext of the "bad" record (flip a byte past the frame
        // header, so the frame parses but the AEAD tag fails).
        let bad_path = record_path(dir.path(), &bad).unwrap();
        let mut bytes = fs::read(&bad_path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&bad_path, &bytes).unwrap();

        let outcome = load_all(dir.path(), &key()).unwrap();
        assert_eq!(outcome.records.len(), 1, "the good record still loads");
        assert_eq!(
            outcome.quarantined.len(),
            1,
            "the bad record is quarantined"
        );
        assert_eq!(outcome.quarantined[0].id, bad.storage_id().unwrap());
        // quarantine reason carries no value
        assert!(!outcome.quarantined[0].reason.contains("bad-val"));
    }

    #[test]
    fn load_all_quarantines_garbage_file() {
        let dir = tempfile::tempdir().unwrap();
        ensure_dir(dir.path()).unwrap();
        fs::write(dir.path().join("deadbeef.sec"), b"not a frame").unwrap();
        let outcome = load_all(dir.path(), &key()).unwrap();
        assert!(outcome.records.is_empty());
        assert_eq!(outcome.quarantined.len(), 1);
    }

    #[test]
    fn delete_removes_record() {
        let dir = tempfile::tempdir().unwrap();
        let c = coord("secret:prod/db/password");
        write_record(dir.path(), &c, &seal(&literal("x"), &key()).unwrap()).unwrap();
        delete_record(dir.path(), &c).unwrap();
        assert!(read_record(dir.path(), &c, &key()).unwrap().is_none());
    }

    #[test]
    fn placeholder_coordinate_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let c = coord("secret:${ENV}/db/password");
        assert!(matches!(
            write_record(dir.path(), &c, &seal(&literal("x"), &key()).unwrap()),
            Err(CoreError::NotStorable(_))
        ));
    }
}
