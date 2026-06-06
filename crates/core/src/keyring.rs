//! Master-key acquisition behind a mockable trait (spec §10.2, decision §19).
//!
//! The 32-byte vault master key lives in the **OS keyring** (macOS Keychain,
//! Windows Credential Manager, Linux Secret Service) — never on a per-operation
//! passphrase, never in a Docker image (I9). When no keyring is available
//! (headless), it is derived from a passphrase with Argon2id.
//!
//! All of this sits behind the [`Keyring`] trait so core logic is tested with a
//! deterministic [`MockKeyring`]; the real OS backend ([`OsKeyring`]) is
//! validated on hardware in a later layer (`[host]`), not by unit tests.

use argon2::Argon2;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::KEY_LEN;
use crate::error::CoreError;

/// The vault master key (32 bytes), held in protected memory.
///
/// Zeroized on drop, redacted `Debug`, and — like [`crate::SecretValue`] — has
/// **no** `Display` and is not serializable. The bytes are reachable only via
/// [`MasterKey::expose`], for handing to [`crate::seal`]/[`crate::open`].
pub struct MasterKey([u8; KEY_LEN]);

impl MasterKey {
    /// Wrap raw key bytes.
    pub fn new(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the key bytes. Use deliberately — this is the one path out.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Redacted `Debug`: never reveals key material (I12). No `Display` impl exists.
impl core::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MasterKey(REDACTED)")
    }
}

/// Source of the vault master key. The store and registry depend on this trait,
/// not on any concrete backend, so they are testable without an OS keyring.
pub trait Keyring {
    /// Fetch the master key, materializing it (e.g. reading the OS keyring or
    /// deriving from a passphrase).
    fn get_master_key(&self) -> Result<MasterKey, CoreError>;

    /// Persist the master key (e.g. write it to the OS keyring). Backends that
    /// *derive* the key (see [`Argon2Keyring`]) have nothing to store and return
    /// an error.
    fn set_master_key(&self, key: &MasterKey) -> Result<(), CoreError>;
}

/// In-memory, deterministic keyring for tests. Never touches the OS.
#[derive(Default)]
pub struct MockKeyring {
    key: std::sync::Mutex<Option<[u8; KEY_LEN]>>,
}

impl MockKeyring {
    /// An empty keyring (no key yet); `get_master_key` errors until one is set.
    pub fn empty() -> Self {
        Self::default()
    }

    /// A keyring pre-seeded with a fixed key — convenient for tests.
    pub fn with_key(bytes: [u8; KEY_LEN]) -> Self {
        Self {
            key: std::sync::Mutex::new(Some(bytes)),
        }
    }
}

impl Keyring for MockKeyring {
    fn get_master_key(&self) -> Result<MasterKey, CoreError> {
        self.key
            .lock()
            .expect("mock keyring mutex poisoned")
            .map(MasterKey::new)
            .ok_or_else(|| CoreError::Keyring("no master key set".to_string()))
    }

    fn set_master_key(&self, key: &MasterKey) -> Result<(), CoreError> {
        *self.key.lock().expect("mock keyring mutex poisoned") = Some(*key.expose());
        Ok(())
    }
}

/// Real OS keyring backend (`[host]`). Stores the master key as a binary secret
/// under a fixed service/user. Compiled on every platform behind the trait, but
/// validated on real hardware in a later layer — unit tests use
/// [`MockKeyring`].
pub struct OsKeyring {
    service: String,
    user: String,
}

impl OsKeyring {
    /// The default kovra keyring entry (`service = "kovra"`, `user =
    /// "master-key"`).
    pub fn new() -> Self {
        Self {
            service: "kovra".to_string(),
            user: "master-key".to_string(),
        }
    }
}

impl Default for OsKeyring {
    fn default() -> Self {
        Self::new()
    }
}

impl Keyring for OsKeyring {
    fn get_master_key(&self) -> Result<MasterKey, CoreError> {
        let entry = keyring::Entry::new(&self.service, &self.user)
            .map_err(|e| CoreError::Keyring(e.to_string()))?;
        let secret = entry
            .get_secret()
            .map_err(|e| CoreError::Keyring(e.to_string()))?;
        let bytes: [u8; KEY_LEN] = secret
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::Keyring("stored key has wrong length".to_string()))?;
        Ok(MasterKey::new(bytes))
    }

    fn set_master_key(&self, key: &MasterKey) -> Result<(), CoreError> {
        let entry = keyring::Entry::new(&self.service, &self.user)
            .map_err(|e| CoreError::Keyring(e.to_string()))?;
        entry
            .set_secret(key.expose())
            .map_err(|e| CoreError::Keyring(e.to_string()))
    }
}

/// Headless fallback (spec §10.2): derive the master key from a passphrase with
/// Argon2id. Deterministic given the same passphrase and salt, so the same
/// vault unlocks across runs without an OS keyring. There is nothing to
/// *store* — `set_master_key` is unsupported.
pub struct Argon2Keyring {
    passphrase: Zeroizing<Vec<u8>>,
    salt: Vec<u8>,
}

/// Minimum Argon2 salt length (the crate rejects shorter salts).
pub const MIN_SALT_LEN: usize = 8;

impl Argon2Keyring {
    /// Build a fallback keyring from a passphrase and a salt. The salt is not
    /// secret but must be **stable** for a given vault (store it alongside the
    /// vault) and at least [`MIN_SALT_LEN`] bytes.
    pub fn new(
        passphrase: impl Into<Vec<u8>>,
        salt: impl Into<Vec<u8>>,
    ) -> Result<Self, CoreError> {
        let salt = salt.into();
        if salt.len() < MIN_SALT_LEN {
            return Err(CoreError::Keyring(format!(
                "salt must be at least {MIN_SALT_LEN} bytes"
            )));
        }
        Ok(Self {
            passphrase: Zeroizing::new(passphrase.into()),
            salt,
        })
    }
}

impl Keyring for Argon2Keyring {
    fn get_master_key(&self) -> Result<MasterKey, CoreError> {
        let mut key = [0u8; KEY_LEN];
        Argon2::default()
            .hash_password_into(&self.passphrase, &self.salt, &mut key)
            .map_err(|e| CoreError::Keyring(e.to_string()))?;
        let master = MasterKey::new(key);
        key.zeroize();
        Ok(master)
    }

    fn set_master_key(&self, _key: &MasterKey) -> Result<(), CoreError> {
        Err(CoreError::Keyring(
            "passphrase-derived key cannot be stored; it is recomputed from the passphrase"
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_keyring_round_trips() {
        let kr = MockKeyring::empty();
        assert!(kr.get_master_key().is_err());
        kr.set_master_key(&MasterKey::new([5u8; KEY_LEN])).unwrap();
        assert_eq!(kr.get_master_key().unwrap().expose(), &[5u8; KEY_LEN]);
    }

    #[test]
    fn mock_with_key_seeds_value() {
        let kr = MockKeyring::with_key([9u8; KEY_LEN]);
        assert_eq!(kr.get_master_key().unwrap().expose(), &[9u8; KEY_LEN]);
    }

    #[test]
    fn master_key_debug_is_redacted() {
        let mk = MasterKey::new([1u8; KEY_LEN]);
        assert_eq!(format!("{mk:?}"), "MasterKey(REDACTED)");
    }

    #[test]
    fn argon2_is_deterministic_for_same_inputs() {
        let a =
            Argon2Keyring::new(b"correct horse".to_vec(), b"stable-salt-1234".to_vec()).unwrap();
        let b =
            Argon2Keyring::new(b"correct horse".to_vec(), b"stable-salt-1234".to_vec()).unwrap();
        assert_eq!(
            a.get_master_key().unwrap().expose(),
            b.get_master_key().unwrap().expose()
        );
    }

    #[test]
    fn argon2_differs_for_different_passphrase() {
        let salt = b"stable-salt-1234".to_vec();
        let a = Argon2Keyring::new(b"passphrase-a".to_vec(), salt.clone()).unwrap();
        let b = Argon2Keyring::new(b"passphrase-b".to_vec(), salt).unwrap();
        assert_ne!(
            a.get_master_key().unwrap().expose(),
            b.get_master_key().unwrap().expose()
        );
    }

    #[test]
    fn argon2_rejects_short_salt() {
        assert!(matches!(
            Argon2Keyring::new(b"pw".to_vec(), b"short".to_vec()),
            Err(CoreError::Keyring(_))
        ));
    }

    #[test]
    fn argon2_key_is_not_settable() {
        let kr = Argon2Keyring::new(b"pw".to_vec(), b"stable-salt-1234".to_vec()).unwrap();
        assert!(kr.set_master_key(&MasterKey::new([0u8; KEY_LEN])).is_err());
    }
}
