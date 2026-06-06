//! AEAD encryption at rest (spec §10.1; ADR-0001).
//!
//! Each record is independently sealed with ChaCha20-Poly1305 under a fresh
//! random nonce (unique nonce per write), sealing metadata + value together so
//! no plaintext — and no coordinate — is exposed on disk. The 32-byte master
//! key is supplied by the caller; key management (OS keyring / Argon2 fallback)
//! is L2's concern, not this layer's.

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::CoreError;
use crate::record::SecretRecord;

/// AEAD key length in bytes (ChaCha20-Poly1305).
pub const KEY_LEN: usize = 32;
/// AEAD nonce length in bytes.
pub const NONCE_LEN: usize = 12;

/// A sealed record: AEAD nonce + ciphertext (the ciphertext includes the
/// Poly1305 authentication tag). Safe to persist or serialize — it contains no
/// plaintext.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SealedRecord {
    /// The unique nonce used for this record.
    pub nonce: Vec<u8>,
    /// Ciphertext + authentication tag.
    pub ciphertext: Vec<u8>,
}

/// Seal arbitrary plaintext bytes under a fresh random nonce. The single AEAD
/// path used by both [`seal`] (secret records) and the metadata index
/// (ADR-0001 §A.4 sealed-at-rest). The caller's buffer is the caller's to
/// zeroize; this function does not retain it.
pub fn seal_bytes(plaintext: &[u8], key: &[u8; KEY_LEN]) -> Result<SealedRecord, CoreError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CoreError::Crypto)?;
    Ok(SealedRecord {
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

/// Open bytes sealed by [`seal_bytes`]. Fails (without detail) on a wrong key,
/// a tampered ciphertext, or a malformed nonce — opaque so it cannot act as an
/// oracle.
pub fn open_bytes(sealed: &SealedRecord, key: &[u8; KEY_LEN]) -> Result<Vec<u8>, CoreError> {
    if sealed.nonce.len() != NONCE_LEN {
        return Err(CoreError::Crypto);
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(&sealed.nonce);
    cipher
        .decrypt(nonce, sealed.ciphertext.as_slice())
        .map_err(|_| CoreError::Crypto)
}

/// Seal a record: serialize it, then AEAD-encrypt metadata + value together.
///
/// A fresh random nonce is generated on every call, so two seals of the same
/// record always differ. The transient plaintext buffer is zeroized.
pub fn seal(record: &SecretRecord, key: &[u8; KEY_LEN]) -> Result<SealedRecord, CoreError> {
    let mut plaintext =
        serde_json::to_vec(record).map_err(|e| CoreError::Serialization(e.to_string()))?;
    let sealed = seal_bytes(&plaintext, key);
    plaintext.zeroize();
    sealed
}

/// Open a sealed record: AEAD-decrypt then deserialize. Fails (without detail)
/// on a wrong key, a tampered ciphertext, or a malformed nonce. The transient
/// plaintext buffer is zeroized before returning.
pub fn open(sealed: &SealedRecord, key: &[u8; KEY_LEN]) -> Result<SecretRecord, CoreError> {
    let mut plaintext = open_bytes(sealed, key)?;
    let record = serde_json::from_slice::<SecretRecord>(&plaintext)
        .map_err(|e| CoreError::Serialization(e.to_string()));
    plaintext.zeroize();
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretValue;
    use crate::sensitivity::Sensitivity;

    fn key() -> [u8; KEY_LEN] {
        [7u8; KEY_LEN]
    }

    fn literal(value: &str) -> SecretRecord {
        SecretRecord::Literal {
            value: SecretValue::from(value),
            sensitivity: Sensitivity::High,
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
    fn seal_open_round_trip() {
        let record = literal("hunter2");
        let sealed = seal(&record, &key()).unwrap();
        let opened = open(&sealed, &key()).unwrap();
        assert_eq!(opened, record);
    }

    #[test]
    fn nonce_is_unique_per_write() {
        let record = literal("hunter2");
        let a = seal(&record, &key()).unwrap();
        let b = seal(&record, &key()).unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn sealed_bytes_do_not_contain_plaintext() {
        let sealed = seal(&literal("hunter2"), &key()).unwrap();
        assert!(!sealed.ciphertext.windows(7).any(|w| w == b"hunter2"));
        // and the coordinate metadata is sealed too (not exposed)
        assert!(!sealed.ciphertext.windows(8).any(|w| w == b"password"));
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let sealed = seal(&literal("hunter2"), &key()).unwrap();
        let err = open(&sealed, &[9u8; KEY_LEN]).unwrap_err();
        assert!(matches!(err, CoreError::Crypto));
    }

    #[test]
    fn tampered_ciphertext_fails_to_open() {
        let mut sealed = seal(&literal("hunter2"), &key()).unwrap();
        sealed.ciphertext[0] ^= 0xff;
        assert!(matches!(open(&sealed, &key()), Err(CoreError::Crypto)));
    }

    #[test]
    fn malformed_nonce_fails_to_open() {
        let mut sealed = seal(&literal("hunter2"), &key()).unwrap();
        sealed.nonce.truncate(4);
        assert!(matches!(open(&sealed, &key()), Err(CoreError::Crypto)));
    }
}
