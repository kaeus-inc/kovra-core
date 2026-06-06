//! Encrypted package + access token — offline non-prod secret sharing (L7,
//! KOV-21; spec §7, §17 L7; invariants I4a/I4b/I8/I12).
//!
//! A **package** lets a developer hand a bundle of non-production secrets to a
//! peer (or to another of their own machines) without putting a vault master
//! key on the recipient. It is a sealed `age` box (X25519 under the hood, via
//! the existing [`crate::keypair::encrypt_to`] ed25519-recipient path) plus a
//! small cleartext header carrying the package's `expires_at`. The sealed
//! payload is a list of [`SecretRecord`]s — **every** modality (literal,
//! reference, keypair, totp) travels, each sealed exactly as it lives in the
//! vault. A `Reference` carries only its pointer URI; its value is **never**
//! resolved at packaging time and is materialized by the recipient's own
//! provider identity or not at all (I8).
//!
//! A separate **access token** authorizes *unattended* consumption of the
//! package's `high` entries on a machine with no human to confirm (§7.2). It is
//! a distinct artifact, delivered over a second channel. Possession of the
//! package alone is **not** enough to mint a token: `seal` embeds a
//! `token_commitment = BLAKE3(token_secret)` *inside the sealed payload*, so an
//! unattended open requires **both** the recipient identity (factor 1 — to
//! decrypt and read the commitment) **and** the separately delivered token
//! secret (factor 2 — the preimage of that commitment). The token's TTL equals
//! the package's `expires_at` (one clock, one expiry — rotation/expiry are a
//! single event; regenerating the package mints a new token).
//!
//! ## What this module enforces
//! - **I4a** — a `prod` secret may not be packaged. [`seal`] refuses a payload
//!   containing any `prod` entry with an explicit error naming the coordinate;
//!   it is never silently omitted.
//! - **I4b** — a `prod` secret may not be delivered via the unattended token.
//!   [`open_unattended`] re-checks every decrypted entry (defense in depth: even
//!   a forged package that bypassed I4a cannot yield `prod` under a token).
//! - **I8** — references travel as pointers; the provider is never invoked here.
//! - **I12** — no plaintext value is ever logged or placed in an error. Crypto
//!   failures are opaque ([`CoreError::Package`]); the secret-bearing types defer
//!   their `Debug` to [`SecretValue`]/[`SecretRecord`], which redact.
//!
//! ## Honest limits (ADR-07)
//! The package is **confidentiality only**. The `age` AEAD tag gives integrity
//! (a tampered package fails to open), but there is **no signing** — a package
//! carries no proof of origin. Recipient identities are **ed25519** (the closed
//! encryption decision; [`crate::keypair::encrypt_to`] rejects RSA recipients).

use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::clock::Clock;
use crate::confirm::{ConfirmOutcome, ConfirmRequest, Confirmer};
use crate::error::CoreError;
use crate::keypair;
use crate::policy;
use crate::record::SecretRecord;
use crate::secret::SecretValue;

/// Current package payload / on-the-wire schema version.
pub const PACKAGE_SCHEMA_VERSION: u32 = 1;

/// Magic prefixing a serialized [`Package`] frame. Lets a reader reject a
/// foreign/garbage file before attempting decryption.
pub const PACKAGE_MAGIC: &[u8; 4] = b"KVPK";

/// Bytes of the random token secret minted per package.
const TOKEN_SECRET_LEN: usize = 32;

const HEADER_LEN: usize = 4 + 4 + 8; // magic + u32 version + u64 expires_at

/// The plaintext that gets sealed into a [`Package`].
///
/// `Debug` is safe: the only secret-bearing material lives inside the `entries`
/// (a literal's `value`, a keypair's `private`, a totp's `seed`), all
/// [`SecretValue`]s whose `Debug` is redacted (I12). The `token_commitment` is a
/// BLAKE3 **hash** of the token secret — not the secret itself.
#[derive(Debug, Serialize, Deserialize)]
pub struct PackagePayload {
    /// Schema version of this payload.
    pub schema_version: u32,
    /// The environment scope the package was cut for (e.g. `dev`). All entries
    /// share it; never `prod` (I4a).
    pub environment: String,
    /// RFC-3339 creation timestamp (provenance metadata, not a secret).
    pub created: String,
    /// Expiry as Unix seconds. Mirrored in the cleartext [`Package`] header so a
    /// reader can reject an expired package before attempting decryption.
    pub expires_at: u64,
    /// `BLAKE3(token_secret)` — the commitment an unattended open checks the
    /// presented token secret against (factor 2). Set by [`seal`].
    pub token_commitment: String,
    /// The packaged records, each in its stored modality. Literals carry their
    /// value; references carry **only** the pointer URI (I8); keypair/totp carry
    /// their sealed private half / seed.
    pub entries: Vec<SecretRecord>,
}

impl PackagePayload {
    /// Build a payload for `environment`, expiring at `expires_at` (Unix secs),
    /// over `entries`. `token_commitment` is left empty; [`seal`] fills it.
    pub fn new(
        environment: impl Into<String>,
        created: impl Into<String>,
        expires_at: u64,
        entries: Vec<SecretRecord>,
    ) -> Self {
        Self {
            schema_version: PACKAGE_SCHEMA_VERSION,
            environment: environment.into(),
            created: created.into(),
            expires_at,
            token_commitment: String::new(),
            entries,
        }
    }
}

/// The on-the-wire package: a cleartext header + the `age`-sealed payload bytes.
///
/// The sealed bytes are an `age` ciphertext of the JSON-serialized
/// [`PackagePayload`]; only the recipient's ed25519 private key opens them. The
/// header (magic, version, `expires_at`) is cleartext so a reader can reject an
/// expired or foreign package without the recipient key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// Schema version.
    pub version: u32,
    /// Expiry (Unix seconds), mirrored from the sealed payload.
    pub expires_at: u64,
    /// The `age`-sealed payload bytes (ciphertext; never plaintext).
    sealed: Vec<u8>,
}

impl Package {
    /// Construct a package from already-sealed bytes (used by [`seal`] and by
    /// readers reconstructing from [`Package::from_bytes`]).
    fn new(version: u32, expires_at: u64, sealed: Vec<u8>) -> Self {
        Self {
            version,
            expires_at,
            sealed,
        }
    }

    /// The package fingerprint: a full BLAKE3 hex of the sealed ciphertext. Used
    /// to bind an [`AccessToken`] to exactly this package. The input is
    /// ciphertext, not a value, so the full hash is safe to surface (I12).
    pub fn fingerprint(&self) -> String {
        blake3::hash(&self.sealed).to_hex().to_string()
    }

    /// Serialize to the on-disk frame: magic + version + `expires_at` + sealed.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.sealed.len());
        out.extend_from_slice(PACKAGE_MAGIC);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.expires_at.to_le_bytes());
        out.extend_from_slice(&self.sealed);
        out
    }

    /// Parse an on-disk frame back into a package, validating the header. Does
    /// **not** decrypt — that needs the recipient identity (see [`open_attended`]).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() < HEADER_LEN || &bytes[..4] != PACKAGE_MAGIC {
            return Err(CoreError::Package("not a kovra package frame".to_string()));
        }
        let version = u32::from_le_bytes(bytes[4..8].try_into().expect("checked length"));
        if version != PACKAGE_SCHEMA_VERSION {
            return Err(CoreError::Package(format!(
                "unsupported package version {version}"
            )));
        }
        let expires_at = u64::from_le_bytes(bytes[8..16].try_into().expect("checked length"));
        Ok(Self::new(version, expires_at, bytes[HEADER_LEN..].to_vec()))
    }
}

/// A bearer access token authorizing unattended consumption of one package
/// (§7.2). Bound to its package by `package_fingerprint`, time-boxed by
/// `expires_at`, and proven by `secret` (whose BLAKE3 matches the
/// `token_commitment` sealed inside the package payload).
///
/// `Debug` is safe: `secret` is a [`SecretValue`] (redacted); the fingerprint
/// and expiry are not secrets.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessToken {
    /// Schema version.
    pub version: u32,
    /// Full BLAKE3 hex of the package's sealed bytes — binds this token to
    /// exactly one package.
    pub package_fingerprint: String,
    /// Expiry (Unix seconds) — equals the package `expires_at`.
    pub expires_at: u64,
    /// The random token secret (factor 2). Serialized into the token artifact
    /// (which IS this credential), never into the package.
    pub secret: SecretValue,
}

impl AccessToken {
    /// Serialize the token to its artifact bytes (JSON). This file IS the
    /// bearer credential — deliver it over a channel separate from the package.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CoreError> {
        serde_json::to_vec(self).map_err(|e| CoreError::Serialization(e.to_string()))
    }

    /// Parse a token artifact produced by [`AccessToken::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        serde_json::from_slice(bytes).map_err(|e| CoreError::Serialization(e.to_string()))
    }
}

/// Seal `payload` to an ed25519 recipient, returning the package and a freshly
/// minted [`AccessToken`] bound to it.
///
/// **I4a**: refuses (with an explicit error naming the coordinate) if any entry
/// is a `prod` secret — a `prod` value never reaches the sealed bytes.
///
/// `recipient_public_openssh` must be an **ed25519** OpenSSH public key;
/// [`crate::keypair::encrypt_to`] rejects RSA (encryption is ed25519-only).
pub fn seal(
    mut payload: PackagePayload,
    recipient_public_openssh: &str,
) -> Result<(Package, AccessToken), CoreError> {
    // I4a — refuse to package any prod secret. Checked here in core so no face
    // can bypass it; the value never enters the sealed buffer.
    for entry in &payload.entries {
        if policy::prod_not_packageable(entry.environment()) {
            return Err(CoreError::Package(format!(
                "refusing to package prod secret `{}` (I4a: prod is never packaged)",
                entry.canonical_path()
            )));
        }
    }

    // Mint the token secret and commit to it inside the (sealed) payload, so an
    // unattended open requires the separately-delivered secret (factor 2).
    let mut secret = Zeroizing::new(vec![0u8; TOKEN_SECRET_LEN]);
    rand::rngs::OsRng.fill_bytes(&mut secret);
    payload.token_commitment = blake3::hash(&secret).to_hex().to_string();
    payload.schema_version = PACKAGE_SCHEMA_VERSION;

    let expires_at = payload.expires_at;
    // The serialized payload is plaintext (it contains the secret values) and is
    // wiped as soon as it has been sealed — it is only ever fed to `encrypt_to`.
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&payload).map_err(|e| CoreError::Serialization(e.to_string()))?,
    );
    let sealed = keypair::encrypt_to(recipient_public_openssh, &plaintext)?;
    let package = Package::new(PACKAGE_SCHEMA_VERSION, expires_at, sealed);

    let token = AccessToken {
        version: PACKAGE_SCHEMA_VERSION,
        package_fingerprint: package.fingerprint(),
        expires_at,
        secret: SecretValue::new(secret.to_vec()),
    };
    Ok((package, token))
}

/// Open a package **attended** — decrypt with the recipient ed25519 private key
/// after checking the package has not expired.
///
/// Returns the full payload (literals as values, references as pointers the
/// recipient must still materialize with its own identity — I8). This is the
/// path a human drives; `high` entries are gated by the caller's broker.
pub fn open_attended(
    package: &Package,
    recipient_private_openssh: &str,
    clock: &dyn Clock,
) -> Result<PackagePayload, CoreError> {
    if clock.unix_secs() > package.expires_at {
        return Err(CoreError::Package("package has expired".to_string()));
    }
    let plaintext = keypair::decrypt(recipient_private_openssh, &package.sealed)?;
    let payload: PackagePayload =
        serde_json::from_slice(&plaintext).map_err(|e| CoreError::Serialization(e.to_string()))?;
    Ok(payload)
}

/// Open a package **unattended** — decrypt with the recipient identity (the
/// first factor) and authorize delivery with a valid `token` (the second
/// factor). This is the only path that yields `high` entries on a machine with
/// no human to confirm (§7.2).
///
/// Rejects when: the package or token has expired; the token is not bound to
/// this package; the token secret does not match the sealed commitment; or —
/// **I4b**, defense in depth — any decrypted entry is a `prod` secret (a forged
/// package that bypassed I4a still cannot yield `prod` under a token).
pub fn open_unattended(
    package: &Package,
    token: &AccessToken,
    recipient_private_openssh: &str,
    clock: &dyn Clock,
) -> Result<PackagePayload, CoreError> {
    let payload = open_attended(package, recipient_private_openssh, clock)?;
    verify_token(package, &payload, token, clock)?;
    enforce_no_prod_unattended(&payload)?;
    Ok(payload)
}

/// Verify a token against a decrypted package: not expired, bound to this
/// package, and the secret matches the sealed commitment. Errors are opaque
/// (I12) — they name *why* the token is rejected, never any value.
pub fn verify_token(
    package: &Package,
    payload: &PackagePayload,
    token: &AccessToken,
    clock: &dyn Clock,
) -> Result<(), CoreError> {
    if clock.unix_secs() > token.expires_at {
        return Err(CoreError::Package("access token has expired".to_string()));
    }
    if token.package_fingerprint != package.fingerprint() {
        return Err(CoreError::Package(
            "access token does not match this package".to_string(),
        ));
    }
    let presented = blake3::hash(token.secret.expose()).to_hex().to_string();
    if presented != payload.token_commitment {
        return Err(CoreError::Package(
            "access token secret is not valid for this package".to_string(),
        ));
    }
    Ok(())
}

/// I4b — refuse if any entry is a `prod` secret. Used by [`open_unattended`] and
/// exposed so a face can pre-check a decrypted payload before unattended use.
pub fn enforce_no_prod_unattended(payload: &PackagePayload) -> Result<(), CoreError> {
    for entry in &payload.entries {
        if policy::prod_blocks_unattended(entry.environment()) {
            return Err(CoreError::Package(format!(
                "prod secret `{}` cannot be delivered unattended (I4b)",
                entry.canonical_path()
            )));
        }
    }
    Ok(())
}

/// A [`Confirmer`] backed by an access token — the third broker impl beside
/// `CliApproveConfirmer`/`BiometricConfirmer`. It lets the unattended consume
/// path funnel `high` entries through the **same** broker abstraction the
/// attended path uses: a valid, unexpired, package-bound token approves; an
/// invalid one denies. It never blocks and never prompts.
pub struct TokenConfirmer {
    approved: bool,
}

impl TokenConfirmer {
    /// Build a confirmer that approves iff `token` is valid for `package`/
    /// `payload` at `clock` (see [`verify_token`]).
    pub fn new(
        package: &Package,
        payload: &PackagePayload,
        token: &AccessToken,
        clock: &dyn Clock,
    ) -> Self {
        Self {
            approved: verify_token(package, payload, token, clock).is_ok(),
        }
    }
}

impl Confirmer for TokenConfirmer {
    fn confirm(&self, _req: &ConfirmRequest, _timeout: std::time::Duration) -> ConfirmOutcome {
        if self.approved {
            ConfirmOutcome::Approved
        } else {
            ConfirmOutcome::Denied
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::MockClock;
    use crate::keypair::{KeyAlgorithm, generate};
    use crate::sensitivity::Sensitivity;

    const HOUR: u64 = 3600;

    fn now() -> u64 {
        MockClock::default().unix_secs()
    }

    fn literal(env: &str, key: &str, value: &str) -> SecretRecord {
        SecretRecord::Literal {
            value: SecretValue::from(value),
            sensitivity: Sensitivity::Medium,
            revealable: false,
            environment: env.to_string(),
            component: "app".to_string(),
            key: key.to_string(),
            description: None,
            created: "2026-05-30T00:00:00Z".to_string(),
            updated: "2026-05-30T00:00:00Z".to_string(),
        }
    }

    fn reference(env: &str, key: &str, uri: &str) -> SecretRecord {
        SecretRecord::Reference {
            reference: uri.to_string(),
            sensitivity: Sensitivity::Medium,
            revealable: false,
            environment: env.to_string(),
            component: "app".to_string(),
            key: key.to_string(),
            description: None,
            created: "2026-05-30T00:00:00Z".to_string(),
            updated: "2026-05-30T00:00:00Z".to_string(),
        }
    }

    fn payload(entries: Vec<SecretRecord>) -> PackagePayload {
        PackagePayload::new("dev", "2026-05-30T00:00:00Z", now() + HOUR, entries)
    }

    // Round-trip (exit criterion): seal then open_attended with the matching
    // identity returns the same literal values; a wrong identity fails to open.
    #[test]
    fn seal_open_round_trips_and_wrong_identity_fails() {
        let recipient = generate(KeyAlgorithm::Ed25519).unwrap();
        let clock = MockClock::default();
        let (package, _token) = seal(
            payload(vec![literal("dev", "token", "s3cr3t-dev-value")]),
            &recipient.public_openssh,
        )
        .unwrap();

        let opened = open_attended(&package, &recipient.private_openssh, &clock).unwrap();
        match &opened.entries[0] {
            SecretRecord::Literal { value, .. } => assert_eq!(value.expose(), b"s3cr3t-dev-value"),
            other => panic!("expected literal, got {other:?}"),
        }

        // A different recipient cannot open it (no plaintext leak).
        let other = generate(KeyAlgorithm::Ed25519).unwrap();
        assert!(open_attended(&package, &other.private_openssh, &clock).is_err());
    }

    // All four modalities survive the round-trip — keypair/totp included.
    #[test]
    fn all_modalities_round_trip() {
        let recipient = generate(KeyAlgorithm::Ed25519).unwrap();
        let clock = MockClock::default();
        let shared = generate(KeyAlgorithm::Ed25519).unwrap();
        let entries = vec![
            literal("dev", "db", "db-pass"),
            reference("dev", "api", "azure-kv://corp-kv/api-key"),
            SecretRecord::Keypair {
                algorithm: KeyAlgorithm::Ed25519,
                private: Some(SecretValue::from(shared.private_openssh.as_str())),
                public: shared.public_openssh.clone(),
                sensitivity: Sensitivity::High,
                revealable: false,
                environment: "dev".to_string(),
                component: "ssh".to_string(),
                key: "deploy".to_string(),
                description: None,
                created: "2026-05-30T00:00:00Z".to_string(),
                updated: "2026-05-30T00:00:00Z".to_string(),
            },
            SecretRecord::Totp {
                seed: SecretValue::from("totp-seed-bytes"),
                algorithm: crate::totp::TotpAlgorithm::Sha1,
                digits: 6,
                period: 30,
                sensitivity: Sensitivity::High,
                revealable: false,
                environment: "dev".to_string(),
                component: "auth".to_string(),
                key: "mfa".to_string(),
                description: None,
                created: "2026-05-30T00:00:00Z".to_string(),
                updated: "2026-05-30T00:00:00Z".to_string(),
            },
        ];
        let (package, _token) = seal(payload(entries), &recipient.public_openssh).unwrap();
        let opened = open_attended(&package, &recipient.private_openssh, &clock).unwrap();
        assert_eq!(opened.entries.len(), 4);
        // The keypair private half survived sealed.
        match &opened.entries[2] {
            SecretRecord::Keypair { private, .. } => {
                assert_eq!(
                    private.as_ref().unwrap().expose(),
                    shared.private_openssh.as_bytes()
                );
            }
            other => panic!("expected keypair, got {other:?}"),
        }
        // The totp seed survived sealed.
        match &opened.entries[3] {
            SecretRecord::Totp { seed, .. } => assert_eq!(seed.expose(), b"totp-seed-bytes"),
            other => panic!("expected totp, got {other:?}"),
        }
    }

    // I4a — packaging a prod secret fails with an explicit error naming the
    // coordinate, and the prod value never reaches the sealed bytes.
    #[test]
    fn i4a_packaging_a_prod_secret_is_refused() {
        let recipient = generate(KeyAlgorithm::Ed25519).unwrap();
        let entries = vec![
            literal("dev", "ok", "fine"),
            literal("prod", "db", "prod-only-value"),
        ];
        let err = seal(payload(entries), &recipient.public_openssh).unwrap_err();
        match err {
            CoreError::Package(msg) => {
                assert!(msg.contains("prod/app/db"), "names the coordinate: {msg}");
                assert!(msg.contains("I4a"));
                assert!(
                    !msg.contains("prod-only-value"),
                    "error must not carry the value"
                );
            }
            other => panic!("expected Package error, got {other:?}"),
        }
    }

    // I4b — a (forged) package containing a prod entry cannot be consumed via a
    // valid token. We seal it bypassing the I4a check to simulate a hand-crafted
    // package, then assert open_unattended refuses on I4b even with a good token.
    #[test]
    fn i4b_prod_entry_refused_under_a_valid_token() {
        let recipient = generate(KeyAlgorithm::Ed25519).unwrap();
        let clock = MockClock::default();
        // Forge a package with a prod entry by sealing the payload directly,
        // bypassing `seal`'s I4a gate (simulating a maliciously crafted package).
        let (package, token) =
            seal_forged_with_prod(&recipient.public_openssh, now() + HOUR).unwrap();

        // The token is valid (right package, right secret, unexpired)…
        let payload = open_attended(&package, &recipient.private_openssh, &clock).unwrap();
        assert!(verify_token(&package, &payload, &token, &clock).is_ok());

        // …yet unattended open still refuses, on I4b.
        let err =
            open_unattended(&package, &token, &recipient.private_openssh, &clock).unwrap_err();
        match err {
            CoreError::Package(msg) => {
                assert!(msg.contains("I4b"), "I4b denial: {msg}");
                assert!(msg.contains("prod/app/secret"));
            }
            other => panic!("expected Package error, got {other:?}"),
        }
    }

    /// Seal a payload containing a prod entry, bypassing the I4a gate in `seal`.
    /// Test-only: simulates a package a non-kovra (or compromised) tool produced.
    fn seal_forged_with_prod(
        recipient_public_openssh: &str,
        expires_at: u64,
    ) -> Result<(Package, AccessToken), CoreError> {
        let mut p = PackagePayload::new(
            "prod",
            "2026-05-30T00:00:00Z",
            expires_at,
            vec![literal("prod", "secret", "forged-prod-value")],
        );
        let mut secret = vec![0u8; TOKEN_SECRET_LEN];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        p.token_commitment = blake3::hash(&secret).to_hex().to_string();
        let plaintext = serde_json::to_vec(&p).unwrap();
        let sealed = keypair::encrypt_to(recipient_public_openssh, &plaintext)?;
        let package = Package::new(PACKAGE_SCHEMA_VERSION, expires_at, sealed);
        let token = AccessToken {
            version: PACKAGE_SCHEMA_VERSION,
            package_fingerprint: package.fingerprint(),
            expires_at,
            secret: SecretValue::new(secret),
        };
        Ok((package, token))
    }

    // I8 — a reference is packaged as its pointer only: the sealed payload holds
    // the URI, never a materialized value, and `seal` invokes no provider (it
    // takes none — there is no path to one).
    #[test]
    fn i8_reference_travels_as_pointer_only() {
        let recipient = generate(KeyAlgorithm::Ed25519).unwrap();
        let clock = MockClock::default();
        let (package, _token) = seal(
            payload(vec![reference("dev", "api", "azure-kv://corp-kv/api-key")]),
            &recipient.public_openssh,
        )
        .unwrap();
        let opened = open_attended(&package, &recipient.private_openssh, &clock).unwrap();
        match &opened.entries[0] {
            SecretRecord::Reference { reference, .. } => {
                assert_eq!(reference, "azure-kv://corp-kv/api-key");
            }
            other => panic!("expected reference, got {other:?}"),
        }
        // The pointer is the address; there is no value field anywhere.
        assert_eq!(
            opened.entries[0].reference(),
            Some("azure-kv://corp-kv/api-key")
        );
    }

    // Token TTL: past expires_at, both attended and unattended opens reject, and
    // a fingerprint-mismatched token is refused.
    #[test]
    fn token_ttl_and_fingerprint_binding() {
        let recipient = generate(KeyAlgorithm::Ed25519).unwrap();
        let (package, token) = seal(
            payload(vec![literal("dev", "k", "v")]),
            &recipient.public_openssh,
        )
        .unwrap();

        // Before expiry: the token verifies.
        let early = MockClock::default();
        let payload = open_attended(&package, &recipient.private_openssh, &early).unwrap();
        assert!(verify_token(&package, &payload, &token, &early).is_ok());

        // After expiry: package + token both reject.
        let late = MockClock::at(now() + 2 * HOUR);
        assert!(open_attended(&package, &recipient.private_openssh, &late).is_err());
        assert!(verify_token(&package, &payload, &token, &late).is_err());

        // A token minted for a different package does not match this one.
        let (_other_pkg, other_token) =
            seal(payload_for_other(), &recipient.public_openssh).unwrap();
        assert!(verify_token(&package, &payload, &other_token, &early).is_err());
    }

    fn payload_for_other() -> PackagePayload {
        PackagePayload::new(
            "dev",
            "2026-05-30T00:00:00Z",
            now() + HOUR,
            vec![literal("dev", "other", "other")],
        )
    }

    // Two-factor: TokenConfirmer approves only with a valid token; a bad secret
    // is denied (the attended path would instead prompt a human).
    #[test]
    fn token_confirmer_is_two_factor() {
        let recipient = generate(KeyAlgorithm::Ed25519).unwrap();
        let clock = MockClock::default();
        let (package, token) = seal(
            payload(vec![literal("dev", "k", "v")]),
            &recipient.public_openssh,
        )
        .unwrap();
        let payload = open_attended(&package, &recipient.private_openssh, &clock).unwrap();

        let good = TokenConfirmer::new(&package, &payload, &token, &clock);
        assert!(
            good.confirm(
                &ConfirmRequest::new(
                    "dev/app/k",
                    Sensitivity::High,
                    "dev",
                    crate::scope::Origin::Human
                ),
                std::time::Duration::ZERO
            )
            .is_approved()
        );

        // A token whose secret does not match the sealed commitment is denied.
        let forged = AccessToken {
            version: PACKAGE_SCHEMA_VERSION,
            package_fingerprint: package.fingerprint(),
            expires_at: token.expires_at,
            secret: SecretValue::from("not-the-real-secret"),
        };
        let bad = TokenConfirmer::new(&package, &payload, &forged, &clock);
        assert_eq!(
            bad.confirm(
                &ConfirmRequest::new(
                    "dev/app/k",
                    Sensitivity::High,
                    "dev",
                    crate::scope::Origin::Human
                ),
                std::time::Duration::ZERO
            ),
            ConfirmOutcome::Denied
        );
    }

    // Tamper: flipping a byte of the sealed ciphertext makes open fail (AEAD
    // integrity — no signing needed).
    #[test]
    fn tampered_package_fails_to_open() {
        let recipient = generate(KeyAlgorithm::Ed25519).unwrap();
        let clock = MockClock::default();
        let (package, _token) = seal(
            payload(vec![literal("dev", "k", "v")]),
            &recipient.public_openssh,
        )
        .unwrap();
        let mut bytes = package.to_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        let tampered = Package::from_bytes(&bytes).unwrap();
        assert!(open_attended(&tampered, &recipient.private_openssh, &clock).is_err());
    }

    // I12 — neither the payload nor the token leak a secret through Debug, and
    // the on-the-wire frame round-trips.
    #[test]
    fn debug_is_redacted_and_frame_round_trips() {
        let recipient = generate(KeyAlgorithm::Ed25519).unwrap();
        let (package, token) = seal(
            payload(vec![literal("dev", "k", "top-secret-literal")]),
            &recipient.public_openssh,
        )
        .unwrap();

        let opened = {
            let clock = MockClock::default();
            open_attended(&package, &recipient.private_openssh, &clock).unwrap()
        };
        let dbg = format!("{opened:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("top-secret-literal"));

        let token_dbg = format!("{token:?}");
        assert!(token_dbg.contains("REDACTED"));

        // The serialized package frame round-trips through from_bytes.
        let back = Package::from_bytes(&package.to_bytes()).unwrap();
        assert_eq!(back, package);

        // The token artifact round-trips and preserves the secret.
        let token2 = AccessToken::from_bytes(&token.to_bytes().unwrap()).unwrap();
        assert_eq!(token2.secret.expose(), token.secret.expose());
        assert_eq!(token2.package_fingerprint, token.package_fingerprint);
    }

    // A non-kovra/garbage file is rejected by the frame parser before any
    // decryption is attempted.
    #[test]
    fn foreign_frame_is_rejected() {
        assert!(Package::from_bytes(b"not a package").is_err());
    }
}
