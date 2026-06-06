//! Vault recovery backup & restore (KOV-34, spec §10.2).
//!
//! A **mode-aware**, encrypted disaster-recovery backup of what a vault needs to
//! unlock, sealed into a **standard, ASCII-armored `age`** blob under a recovery
//! passphrase (age-scrypt). The plaintext never lands in a file or a log
//! (I7/I12) — only the encrypted blob is emitted; and because the blob is a
//! normal `age` file it stays recoverable with any age implementation (`age -d`)
//! even if kovra is unavailable.
//!
//! The blob is **self-describing** ([`BackupKind`]): `import` restores it to the
//! right backend regardless of the machine's current mode, and **respects the
//! vault's mode** — it never silently migrates one mode to another:
//!
//! - **keyring** vaults store the 32-byte master key → backup carries the key,
//!   restored into the OS keyring.
//! - **passphrase** vaults *derive* the key (`Argon2(passphrase, salt)`), so an
//!   arbitrary key cannot be stored; the recoverable material kovra holds is the
//!   **`kdf.salt`** → backup carries the salt, restored to `kdf.salt`. The
//!   passphrase stays with the user and is never exported.
//!
//! Round-tripping a backup in the same mode is **idempotent** (the same key/salt
//! is restored).
//!
//! This module is **pure**: it knows nothing about the keyring backend or the
//! filesystem. The CLI wires `export`/`import` around it.

use age::secrecy::SecretString;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::CoreError;

/// What a backup blob carries, so `import` restores it to the right backend
/// (KOV-34). Serialized inside the encrypted payload, never in the clear.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupKind {
    /// A stored 32-byte master key (keyring-mode vaults) → the OS keyring.
    #[serde(rename = "master-key")]
    MasterKey,
    /// The Argon2 `kdf.salt` (passphrase-mode vaults) → the `kdf.salt` file. The
    /// passphrase is the user's and is never part of the backup.
    #[serde(rename = "kdf-salt")]
    KdfSalt,
}

impl BackupKind {
    /// A human label for prompts / audit (never a value).
    pub fn label(self) -> &'static str {
        match self {
            BackupKind::MasterKey => "master key",
            BackupKind::KdfSalt => "kdf salt",
        }
    }
}

/// Versioned, self-describing backup payload (encrypted before it ever exists on
/// the wire).
#[derive(Serialize, Deserialize)]
struct Backup {
    v: u8,
    kind: BackupKind,
    data: Vec<u8>,
}

const BACKUP_VERSION: u8 = 1;

/// Encrypt `data` (a master key or a kdf salt, per `kind`) into an ASCII-armored
/// `age` blob under `passphrase` (age-scrypt). The transient plaintext is wiped
/// at the end of the call; only the encrypted blob is returned (I7/I12).
pub fn export_backup(kind: BackupKind, data: &[u8], passphrase: &str) -> Result<String, CoreError> {
    let payload = Backup {
        v: BACKUP_VERSION,
        kind,
        data: data.to_vec(),
    };
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&payload)
            .map_err(|e| CoreError::Keyring(format!("backup encode: {e}")))?,
    );
    let recipient = age::scrypt::Recipient::new(SecretString::from(passphrase.to_owned()));
    age::encrypt_and_armor(&recipient, plaintext.as_slice())
        .map_err(|e| CoreError::Keyring(format!("backup export failed: {e}")))
}

/// Decrypt an [`export_backup`] blob with `passphrase`, returning what it carries
/// (the caller restores it to the right backend). A wrong passphrase, a tampered
/// blob, or an unknown format fails cleanly — never a panic, never the bytes.
pub fn import_backup(
    armored: &str,
    passphrase: &str,
) -> Result<(BackupKind, Zeroizing<Vec<u8>>), CoreError> {
    let identity = age::scrypt::Identity::new(SecretString::from(passphrase.to_owned()));
    let plaintext = Zeroizing::new(age::decrypt(&identity, armored.as_bytes()).map_err(|_| {
        CoreError::Keyring("backup import failed: wrong passphrase or corrupt backup".into())
    })?);
    let payload: Backup = serde_json::from_slice(&plaintext)
        .map_err(|_| CoreError::Keyring("backup import failed: not a kovra key backup".into()))?;
    if payload.v != BACKUP_VERSION {
        return Err(CoreError::Keyring(format!(
            "backup import failed: unsupported backup version {}",
            payload.v
        )));
    }
    Ok((payload.kind, Zeroizing::new(payload.data)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Round-trip both kinds: export then import recovers the same kind + bytes.
    #[test]
    fn export_import_round_trips_both_kinds() {
        for (kind, data) in [
            (BackupKind::MasterKey, vec![0x42u8; 32]),
            (BackupKind::KdfSalt, vec![0x9au8; 16]),
        ] {
            let armored = export_backup(kind, &data, "recover-me-please").unwrap();
            assert!(armored.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
            let (got_kind, got_data) = import_backup(&armored, "recover-me-please").unwrap();
            assert_eq!(got_kind, kind);
            assert_eq!(got_data.as_slice(), data.as_slice());
        }
    }

    // A wrong passphrase fails cleanly (no panic, no bytes).
    #[test]
    fn wrong_passphrase_fails() {
        let armored = export_backup(BackupKind::MasterKey, &[7u8; 32], "the-real-one").unwrap();
        let err = import_backup(&armored, "not-the-one").unwrap_err();
        assert!(format!("{err}").contains("wrong passphrase or corrupt backup"));
    }

    // A tampered blob fails (AEAD integrity).
    #[test]
    fn tampered_blob_fails() {
        let mut armored = export_backup(BackupKind::KdfSalt, &[0x11u8; 16], "pw").unwrap();
        let mid = armored.len() / 2;
        let b = armored.as_bytes()[mid];
        let repl = if b == b'A' { 'B' } else { 'A' };
        armored.replace_range(mid..mid + 1, &repl.to_string());
        assert!(import_backup(&armored, "pw").is_err());
    }

    // I7/I12 — the raw payload bytes never appear in the exported blob.
    #[test]
    fn export_does_not_leak_payload_bytes() {
        let data = [0x42u8; 32];
        let armored = export_backup(BackupKind::MasterKey, &data, "pw").unwrap();
        assert!(
            !armored.as_bytes().windows(32).any(|w| w == data),
            "the armored backup must not contain the raw payload"
        );
    }
}
