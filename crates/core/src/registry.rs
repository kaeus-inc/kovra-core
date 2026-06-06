//! The central vault registry and override resolution (spec §1.1, §10.3).
//!
//! Layout under the registry root (default `~/.vaults`):
//!
//! ```text
//! ~/.vaults/
//!   global/                 <- the global vault (per-secret .sec files + index.redb)
//!   projects/
//!     <name>/               <- one project vault per directory
//! ```
//!
//! Resolution follows the §1.1 table: a project vault **shadows** the global at
//! the exact coordinate; an explicit `secret://global/...` scope selector
//! bypasses the project vault and resolves only against the global. The
//! `.env.refs` fallback (step 3 of the table) and `${ENV}` substitution are L4
//! and out of scope here.

use std::path::{Path, PathBuf};

use crate::coordinate::{Coordinate, Scope};
use crate::error::CoreError;
use crate::keyring::Keyring;
use crate::record::SecretRecord;
use crate::store;

/// Directory name of the global vault under the registry root.
pub const GLOBAL_DIR: &str = "global";
/// Directory holding per-project vaults under the registry root.
pub const PROJECTS_DIR: &str = "projects";

/// Which vault a coordinate resolved against. (Distinct from
/// [`crate::scope::Origin`], which is the request *initiator* — agent vs human.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultOrigin {
    /// Resolved from the global vault.
    Global,
    /// Resolved from the named project vault (it shadowed the global, if any).
    Project(String),
}

/// The outcome of resolving a coordinate against the registry.
///
/// The `Found`/`NotFound` size disparity is inherent: a found resolution must
/// carry the decrypted [`SecretRecord`] (whose `Keypair` variant holds an
/// OpenSSH private key), while `NotFound` is empty. Resolutions are short-lived,
/// pattern-matched values on the stack — boxing the record would add an
/// allocation on the hot point-lookup path for no real benefit — so the
/// large-variant lint is intentionally allowed here.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Resolution {
    /// A record was found; carries it and where it came from.
    Found {
        /// The decrypted record.
        record: SecretRecord,
        /// The vault that produced it.
        origin: VaultOrigin,
    },
    /// No record at this coordinate in the applicable vault(s). (The `.env.refs`
    /// fallback — step 3 of the §1.1 table — is L4, not handled here.)
    NotFound,
}

/// The vault registry rooted at a directory (default `~/.vaults`).
pub struct Registry {
    root: PathBuf,
}

impl Registry {
    /// Open the registry at `root`, creating `global/` and `projects/` (each
    /// `0700`) if missing.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, CoreError> {
        let root = root.into();
        let registry = Self { root };
        store::ensure_dir(&registry.global_dir())?;
        store::ensure_dir(&registry.projects_root())?;
        Ok(registry)
    }

    /// The default registry root, `~/.vaults`. Errors if no home directory is
    /// known.
    pub fn default_root() -> Result<PathBuf, CoreError> {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .ok_or_else(|| CoreError::Io("no home directory ($HOME) set".to_string()))?;
        Ok(PathBuf::from(home).join(".vaults"))
    }

    /// The registry root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The global vault directory.
    pub fn global_dir(&self) -> PathBuf {
        self.root.join(GLOBAL_DIR)
    }

    /// The `projects/` parent directory.
    pub fn projects_root(&self) -> PathBuf {
        self.root.join(PROJECTS_DIR)
    }

    /// A specific project vault directory.
    pub fn project_dir(&self, name: &str) -> PathBuf {
        self.projects_root().join(name)
    }

    /// Enumerate project vault names (the `projects/*` directory entries),
    /// sorted. Used by the Web UI selector (§10.3) — a later layer.
    pub fn list_projects(&self) -> Result<Vec<String>, CoreError> {
        let dir = self.projects_root();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&dir).map_err(|e| CoreError::Io(format!("read_dir: {e}")))? {
            let entry = entry.map_err(|e| CoreError::Io(format!("dir entry: {e}")))?;
            if entry
                .file_type()
                .map_err(|e| CoreError::Io(format!("file_type: {e}")))?
                .is_dir()
                && let Some(name) = entry.file_name().to_str()
            {
                names.push(name.to_string());
            }
        }
        names.sort();
        Ok(names)
    }

    /// Resolve a coordinate per the §1.1 override table (steps 1–2; step 3 is
    /// L4). With [`Scope::Global`], only the global vault is consulted. With
    /// [`Scope::Default`] and a named project, the project record **wins** when
    /// present, otherwise the global is used.
    pub fn resolve(
        &self,
        coord: &Coordinate,
        project: Option<&str>,
        keyring: &dyn Keyring,
    ) -> Result<Resolution, CoreError> {
        let key = keyring.get_master_key()?;
        self.resolve_with_key(coord, project, key.expose())
    }

    /// Like [`Registry::resolve`] but with an already-materialized master key.
    /// The resolver (L4) fetches the key **once** and calls this per variable so
    /// a passphrase-derived key (`Argon2Keyring`) is not re-derived per lookup.
    pub fn resolve_with_key(
        &self,
        coord: &Coordinate,
        project: Option<&str>,
        key: &[u8; crate::crypto::KEY_LEN],
    ) -> Result<Resolution, CoreError> {
        // Step 1: project vault (only for default scope, only if a project is named).
        if coord.scope == Scope::Default
            && let Some(name) = project
            && let Some(record) = store::read_record(&self.project_dir(name), coord, key)?
        {
            return Ok(Resolution::Found {
                record,
                origin: VaultOrigin::Project(name.to_string()),
            });
        }

        // Step 2: global vault.
        if let Some(record) = store::read_record(&self.global_dir(), coord, key)? {
            return Ok(Resolution::Found {
                record,
                origin: VaultOrigin::Global,
            });
        }

        Ok(Resolution::NotFound)
    }

    /// Whether a coordinate is **shadowed**: defined in both the named project
    /// vault and the global vault (the project wins). Feeds the shadowing
    /// visibility surfaced by the Web UI / `doctor` in later layers. A
    /// `secret://global/...` coordinate is never shadowed (it ignores the
    /// project), so this returns `false` for [`Scope::Global`].
    pub fn shadows(&self, coord: &Coordinate, project: &str) -> Result<bool, CoreError> {
        if coord.scope == Scope::Global {
            return Ok(false);
        }
        let in_project = store::record_path(&self.project_dir(project), coord)?.exists();
        let in_global = store::record_path(&self.global_dir(), coord)?.exists();
        Ok(in_project && in_global)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::seal;
    use crate::keyring::MockKeyring;
    use crate::secret::SecretValue;
    use crate::sensitivity::Sensitivity;

    fn keyring() -> MockKeyring {
        MockKeyring::with_key([0x55; crate::crypto::KEY_LEN])
    }

    fn master() -> [u8; crate::crypto::KEY_LEN] {
        [0x55; crate::crypto::KEY_LEN]
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

    fn value_of(res: Resolution) -> (Vec<u8>, VaultOrigin) {
        match res {
            Resolution::Found { record, origin } => match record {
                SecretRecord::Literal { value, .. } => (value.expose().to_vec(), origin),
                other => panic!("expected literal, got {other:?}"),
            },
            Resolution::NotFound => panic!("expected found, got NotFound"),
        }
    }

    #[test]
    fn registry_creates_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = Registry::open(tmp.path()).unwrap();
        assert!(reg.global_dir().is_dir());
        assert!(reg.projects_root().is_dir());
    }

    #[test]
    fn project_shadows_global_at_exact_coordinate() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = Registry::open(tmp.path()).unwrap();
        let c: Coordinate = "secret:prod/db/password".parse().unwrap();

        store::write_record(
            &reg.global_dir(),
            &c,
            &seal(&literal("global-val"), &master()).unwrap(),
        )
        .unwrap();
        store::write_record(
            &reg.project_dir("api"),
            &c,
            &seal(&literal("project-val"), &master()).unwrap(),
        )
        .unwrap();

        let (val, origin) = value_of(reg.resolve(&c, Some("api"), &keyring()).unwrap());
        assert_eq!(val, b"project-val");
        assert_eq!(origin, VaultOrigin::Project("api".to_string()));
        assert!(reg.shadows(&c, "api").unwrap());
    }

    #[test]
    fn falls_back_to_global_when_project_lacks_coordinate() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = Registry::open(tmp.path()).unwrap();
        let c: Coordinate = "secret:prod/db/password".parse().unwrap();
        store::write_record(
            &reg.global_dir(),
            &c,
            &seal(&literal("global-val"), &master()).unwrap(),
        )
        .unwrap();

        let (val, origin) = value_of(reg.resolve(&c, Some("api"), &keyring()).unwrap());
        assert_eq!(val, b"global-val");
        assert_eq!(origin, VaultOrigin::Global);
        assert!(!reg.shadows(&c, "api").unwrap());
    }

    #[test]
    fn global_scope_selector_bypasses_project() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = Registry::open(tmp.path()).unwrap();
        // Both vaults define the same address; the project would normally win.
        let stored: Coordinate = "secret:prod/db/password".parse().unwrap();
        store::write_record(
            &reg.global_dir(),
            &stored,
            &seal(&literal("global-val"), &master()).unwrap(),
        )
        .unwrap();
        store::write_record(
            &reg.project_dir("api"),
            &stored,
            &seal(&literal("project-val"), &master()).unwrap(),
        )
        .unwrap();

        // The global scope selector must ignore the project vault.
        let global_coord: Coordinate = "secret://global/prod/db/password".parse().unwrap();
        let (val, origin) = value_of(reg.resolve(&global_coord, Some("api"), &keyring()).unwrap());
        assert_eq!(val, b"global-val");
        assert_eq!(origin, VaultOrigin::Global);
        assert!(!reg.shadows(&global_coord, "api").unwrap());
    }

    #[test]
    fn unknown_coordinate_is_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = Registry::open(tmp.path()).unwrap();
        let c: Coordinate = "secret:prod/db/absent".parse().unwrap();
        assert!(matches!(
            reg.resolve(&c, Some("api"), &keyring()).unwrap(),
            Resolution::NotFound
        ));
    }

    #[test]
    fn list_projects_enumerates_sorted() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = Registry::open(tmp.path()).unwrap();
        store::ensure_dir(&reg.project_dir("billing")).unwrap();
        store::ensure_dir(&reg.project_dir("api")).unwrap();
        assert_eq!(reg.list_projects().unwrap(), vec!["api", "billing"]);
    }
}
