//! Error types for `kovra-core`.

use thiserror::Error;

/// Errors produced by the core model, coordinate parsing, and crypto-at-rest.
///
/// Crypto failures are deliberately opaque (no inner detail) so they cannot act
/// as an oracle, and no variant ever carries secret material (I12).
#[derive(Debug, Error)]
pub enum CoreError {
    /// A `secret:` coordinate URI was malformed (wrong segment count, illegal
    /// interpolation, empty segment, or bad scope authority).
    #[error("invalid coordinate URI: {0}")]
    InvalidCoordinate(String),

    /// AEAD sealing/opening failed: wrong key, corrupted record, or bad tag.
    #[error("crypto operation failed")]
    Crypto,

    /// (De)serialization of a record payload failed.
    #[error("record serialization failed: {0}")]
    Serialization(String),

    /// A filesystem operation against the vault store failed. Carries an
    /// operation/context string only — never a secret value (I12).
    #[error("vault I/O failed: {0}")]
    Io(String),

    /// Master-key acquisition via the keyring (or the Argon2 fallback) failed.
    /// Carries no key material (I12).
    #[error("keyring operation failed: {0}")]
    Keyring(String),

    /// The metadata index (redb) could not be opened, written, or rebuilt. The
    /// index is a rebuildable cache, so this is recoverable by a rebuild and is
    /// never data loss (ADR-0001 §A.6).
    #[error("metadata index failed: {0}")]
    Index(String),

    /// The requested coordinate cannot be addressed by the store: it carries an
    /// unresolved `${ENV}` placeholder (placeholders resolve at L4, not here).
    #[error("coordinate is not storable: {0}")]
    NotStorable(String),

    /// A policy operation could not be carried out (e.g. building a decision
    /// from malformed inputs). Carries no secret material (I12).
    #[error("policy error: {0}")]
    Policy(String),

    /// The audit log could not be written. Carries no secret material (I12).
    #[error("audit error: {0}")]
    Audit(String),

    /// A `.env.refs` line was malformed, or a value could not be resolved
    /// (unresolved placeholder, prod fallback, missing passthrough, …). Carries
    /// no secret material (I12).
    #[error("env-refs error: {0}")]
    EnvRefs(String),

    /// An asymmetric-key operation failed: key generation, parsing an OpenSSH
    /// key, signing, verifying, encrypting, decrypting, or loading into the
    /// ssh-agent. Carries an operation description only — never key material
    /// (I12). Sign/verify/decrypt failures are deliberately coarse so they
    /// cannot act as an oracle.
    #[error("keypair operation failed: {0}")]
    Keypair(String),

    /// A TOTP operation failed: a malformed base32 seed, an `otpauth://` URI
    /// that could not be parsed, or an out-of-range parameter (digits/period).
    /// Carries an operation description only — never the seed bytes (I12).
    #[error("totp operation failed: {0}")]
    Totp(String),

    /// An external provider failed to materialize a reference: a malformed
    /// reference URI, an unsupported scheme, the provider CLI being absent or
    /// unauthenticated, the secret not existing, or a timeout (§6). Carries an
    /// operation/diagnostic description only — never the materialized value
    /// (I12); failures are deliberately specific so a misconfiguration is clear
    /// rather than a silent empty value.
    #[error("provider error: {0}")]
    Provider(String),

    /// An encrypted-package or access-token operation failed (L7, §7): a
    /// foreign/garbage package frame, an expired package/token, a `prod` secret
    /// refused at packaging (I4a) or under a token (I4b), or a token that does
    /// not match its package. Carries a coordinate/diagnostic description only —
    /// never a value, and crypto failures are deliberately opaque (I12).
    #[error("package error: {0}")]
    Package(String),

    /// A removable-media format operation failed or was refused (KOV-40): the
    /// target is not external/ejectable (the hard safety rail), the wipe was
    /// denied/timed out at the broker, or the OS formatter errored. Carries a
    /// device-node/diagnostic description only — never a secret value (I12).
    #[error("format error: {0}")]
    Format(String),
}
