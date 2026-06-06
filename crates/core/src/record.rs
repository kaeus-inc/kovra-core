//! Secret records and the vault format (spec §1.3, §10.1; ADR-0001).
//!
//! A secret is **literal** (value lives encrypted in the vault) or **reference**
//! (the vault holds only a pointer to an external provider; the value is
//! materialized at run time and never stored — I8).
//!
//! Per ADR-0001 the vault is not a single JSON blob: each secret is an
//! independently AEAD-sealed record (see [`crate::crypto`]) sealing **metadata +
//! value together**. The [`Vault`] persisted format therefore maps an opaque
//! record id to a [`SealedRecord`](crate::crypto::SealedRecord); the plaintext
//! [`SecretRecord`] is what `seal`/`open` convert to and from.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crypto::SealedRecord;
use crate::keypair::KeyAlgorithm;
use crate::secret::SecretValue;
use crate::sensitivity::Sensitivity;
use crate::totp::TotpAlgorithm;

/// Current vault schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// A single secret record, in one of four modalities. Internally tagged by
/// `mode` to mirror the spec §10.1 on-the-wire shape.
///
/// `Debug` is safe: the only secret-bearing fields are `value` (literal),
/// `private` (keypair), and `seed` (totp) — all [`SecretValue`]s whose own
/// `Debug` is redacted (I12). The `public` half of a keypair and the TOTP
/// parameters (algorithm/digits/period) are not secrets.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum SecretRecord {
    /// The value lives (encrypted) in the vault.
    Literal {
        /// The secret value.
        value: SecretValue,
        /// Sensitivity level (spec §3.1).
        sensitivity: Sensitivity,
        /// Whether the secret is opted into reveal (the §3.1 "revealable" flag).
        ///
        /// Sourced into [`crate::AccessRequest::revealable`] so the policy
        /// funnel (I11) reads it from the **stored secret**, never from caller
        /// intent. Defaults to `false` so pre-L9 vaults (and any record that
        /// never opted in) are non-revealable — the safe default.
        #[serde(default)]
        revealable: bool,
        /// Environment segment, e.g. `prod`.
        environment: String,
        /// Component segment.
        component: String,
        /// Key segment.
        key: String,
        /// Optional human description.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        /// Creation timestamp (RFC 3339; a `Clock` trait arrives in a later layer).
        created: String,
        /// Last-update timestamp.
        updated: String,
    },
    /// The vault holds only a pointer to an external secret manager.
    Reference {
        /// Provider URI, e.g. `azure-kv://corp-kv/db-url`.
        #[serde(rename = "ref")]
        reference: String,
        /// Sensitivity level.
        sensitivity: Sensitivity,
        /// Whether the secret is opted into reveal (see the `Literal` variant).
        #[serde(default)]
        revealable: bool,
        /// Environment segment.
        environment: String,
        /// Component segment.
        component: String,
        /// Key segment.
        key: String,
        /// Optional human description.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        /// Creation timestamp.
        created: String,
        /// Last-update timestamp.
        updated: String,
    },
    /// An asymmetric keypair (KOV-12). The **private** half (when present) is a
    /// sealed [`SecretValue`] custodied exactly like a literal — never exported,
    /// used only *through* operations (sign / decrypt / ssh-add), mirroring
    /// injection. The **public** half is not a secret and is shown freely. A
    /// `private: None` record is a *public-only* entry: a peer's/recipient's
    /// public key for `encrypt`/`verify`.
    Keypair {
        /// The key algorithm (ed25519 or RSA).
        algorithm: KeyAlgorithm,
        /// The OpenSSH-format private key, sealed. `None` for a public-only
        /// entry. Born non-revealable by default (I11), like a `high` secret.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        private: Option<SecretValue>,
        /// The OpenSSH-format public key (`ssh-ed25519 …` / `ssh-rsa …`). Public
        /// material — safe to serialize and display.
        public: String,
        /// Sensitivity level. A keypair *with* a private half is born `high`
        /// when its environment is `prod` (I5), like any other secret; a
        /// public-only entry is typically `low` (it holds no secret).
        sensitivity: Sensitivity,
        /// Whether the secret is opted into reveal (see the `Literal` variant).
        /// A keypair's private half is never returned to a model regardless;
        /// this only governs whether the CLI/UI may show it (I11).
        #[serde(default)]
        revealable: bool,
        /// Environment segment.
        environment: String,
        /// Component segment.
        component: String,
        /// Key segment.
        key: String,
        /// Optional human description.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        /// Creation timestamp.
        created: String,
        /// Last-update timestamp.
        updated: String,
    },
    /// A TOTP enrollment (KOV-11). The **seed** (the shared secret) is a sealed
    /// [`SecretValue`] custodied exactly like a literal — never exported, used
    /// only *through* deriving a short-lived RFC-6238 code (`kovra code`),
    /// mirroring how a keypair's private half is used only through sign/decrypt.
    /// The seed is **never** returned to a model (I11/I14) regardless of the
    /// `revealable` flag; only the derived code is produced, on demand.
    Totp {
        /// The base32-decoded shared-secret seed, sealed. Born non-revealable by
        /// default (I11), like a `high` secret.
        seed: SecretValue,
        /// The HMAC hash algorithm (SHA1 default). Not a secret.
        #[serde(default)]
        algorithm: TotpAlgorithm,
        /// Code length in digits (typically 6). Not a secret.
        digits: u8,
        /// Time step in seconds (typically 30). Not a secret.
        period: u8,
        /// Sensitivity level. A TOTP enrollment is born `high` when its
        /// environment is `prod` (I5), like any other secret.
        sensitivity: Sensitivity,
        /// Whether the secret is opted into reveal (see the `Literal` variant).
        /// A TOTP seed is never returned to a model regardless; this only governs
        /// whether the CLI/UI may show it (I11) — and even the CLI shows the
        /// derived code, never the seed.
        #[serde(default)]
        revealable: bool,
        /// Environment segment.
        environment: String,
        /// Component segment.
        component: String,
        /// Key segment.
        key: String,
        /// Optional human description.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        /// Creation timestamp.
        created: String,
        /// Last-update timestamp.
        updated: String,
    },
}

impl SecretRecord {
    /// The secret's sensitivity, regardless of modality.
    pub fn sensitivity(&self) -> Sensitivity {
        match self {
            SecretRecord::Literal { sensitivity, .. }
            | SecretRecord::Reference { sensitivity, .. }
            | SecretRecord::Keypair { sensitivity, .. }
            | SecretRecord::Totp { sensitivity, .. } => *sensitivity,
        }
    }

    /// Whether the secret is opted into reveal (the §3.1 "revealable" flag).
    ///
    /// Faces that build a [`crate::AccessRequest`] read it from here so the
    /// I11 reveal gate is sourced from the stored record, never caller intent.
    pub fn revealable(&self) -> bool {
        match self {
            SecretRecord::Literal { revealable, .. }
            | SecretRecord::Reference { revealable, .. }
            | SecretRecord::Keypair { revealable, .. }
            | SecretRecord::Totp { revealable, .. } => *revealable,
        }
    }

    /// The environment segment, regardless of modality.
    pub fn environment(&self) -> &str {
        match self {
            SecretRecord::Literal { environment, .. }
            | SecretRecord::Reference { environment, .. }
            | SecretRecord::Keypair { environment, .. }
            | SecretRecord::Totp { environment, .. } => environment,
        }
    }

    /// The component segment, regardless of modality.
    pub fn component(&self) -> &str {
        match self {
            SecretRecord::Literal { component, .. }
            | SecretRecord::Reference { component, .. }
            | SecretRecord::Keypair { component, .. }
            | SecretRecord::Totp { component, .. } => component,
        }
    }

    /// The key segment, regardless of modality.
    pub fn key(&self) -> &str {
        match self {
            SecretRecord::Literal { key, .. }
            | SecretRecord::Reference { key, .. }
            | SecretRecord::Keypair { key, .. }
            | SecretRecord::Totp { key, .. } => key,
        }
    }

    /// The canonical `<env>/<component>/<key>` path this record files under.
    pub fn canonical_path(&self) -> String {
        format!("{}/{}/{}", self.environment(), self.component(), self.key())
    }

    /// The external reference URI for a `Reference` record (e.g.
    /// `azure-kv://vault/name`), or `None` for any other modality. Carries an
    /// address, never a value.
    pub fn reference(&self) -> Option<&str> {
        match self {
            SecretRecord::Reference { reference, .. } => Some(reference),
            _ => None,
        }
    }
}

/// The persisted vault: a versioned map of record id → sealed record.
///
/// In L2 the id is `BLAKE3(coordinate)`; at this layer it is any opaque string.
/// Every value lives inside a [`SealedRecord`], so this structure can be
/// serialized freely without exposing plaintext.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Vault {
    /// Schema version of this vault file.
    pub schema_version: u32,
    /// Sealed records keyed by opaque id.
    pub secrets: BTreeMap<String, SealedRecord>,
}

impl Default for Vault {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            secrets: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn literal() -> SecretRecord {
        SecretRecord::Literal {
            value: SecretValue::from("hunter2"),
            sensitivity: Sensitivity::High,
            revealable: false,
            environment: "prod".to_string(),
            component: "db".to_string(),
            key: "password".to_string(),
            description: Some("primary db".to_string()),
            created: "2026-05-30T00:00:00Z".to_string(),
            updated: "2026-05-30T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn literal_debug_is_redacted() {
        let dbg = format!("{:?}", literal());
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("hunter2"));
    }

    #[test]
    fn reference_carries_no_value() {
        let r = SecretRecord::Reference {
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
        // A reference is a pointer; serializing it (it holds no value) is safe.
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"mode\":\"reference\""));
        assert!(json.contains("azure-kv://corp-kv/db-url"));
        assert!(!json.contains("\"value\""));
    }

    #[test]
    fn revealable_defaults_false_on_legacy_records() {
        // A pre-L9 vault record has no `revealable` key; it must deserialize to
        // the safe default (`false`) rather than failing — additive schema.
        let legacy = r#"{
            "mode":"literal","value":[104,111,108,97],
            "sensitivity":"medium","environment":"dev",
            "component":"app","key":"token",
            "created":"2026-05-30T00:00:00Z","updated":"2026-05-30T00:00:00Z"
        }"#;
        let rec: SecretRecord = serde_json::from_str(legacy).unwrap();
        assert!(!rec.revealable());
        assert_eq!(rec.sensitivity(), Sensitivity::Medium);
        assert_eq!(rec.environment(), "dev");
    }

    #[test]
    fn revealable_round_trips_when_set() {
        let rec = SecretRecord::Literal {
            value: SecretValue::from("v"),
            sensitivity: Sensitivity::Medium,
            revealable: true,
            environment: "dev".to_string(),
            component: "app".to_string(),
            key: "token".to_string(),
            description: None,
            created: "2026-05-30T00:00:00Z".to_string(),
            updated: "2026-05-30T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"revealable\":true"));
        let back: SecretRecord = serde_json::from_str(&json).unwrap();
        assert!(back.revealable());
    }

    fn keypair(private: Option<&str>) -> SecretRecord {
        SecretRecord::Keypair {
            algorithm: KeyAlgorithm::Ed25519,
            private: private.map(SecretValue::from),
            public: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test".to_string(),
            sensitivity: Sensitivity::High,
            revealable: false,
            environment: "prod".to_string(),
            component: "ssh".to_string(),
            key: "deploy".to_string(),
            description: None,
            created: "2026-06-01T00:00:00Z".to_string(),
            updated: "2026-06-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn keypair_private_debug_is_redacted() {
        // The private half is a SecretValue, so its Debug never prints the bytes.
        let dbg = format!("{:?}", keypair(Some("PRIVATE-KEY-MATERIAL")));
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("PRIVATE-KEY-MATERIAL"));
        // The public half is not a secret and is shown.
        assert!(dbg.contains("ssh-ed25519"));
    }

    #[test]
    fn keypair_accessors_and_public_only_round_trip() {
        let full = keypair(Some("priv"));
        assert_eq!(full.sensitivity(), Sensitivity::High);
        assert_eq!(full.environment(), "prod");
        assert!(!full.revealable());

        // A public-only entry serializes without a `private` field.
        let public_only = keypair(None);
        let json = serde_json::to_string(&public_only).unwrap();
        assert!(json.contains("\"mode\":\"keypair\""));
        assert!(!json.contains("\"private\""));
        let back: SecretRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, public_only);
    }

    fn totp() -> SecretRecord {
        SecretRecord::Totp {
            seed: SecretValue::from("TOTP-SEED-MATERIAL"),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            sensitivity: Sensitivity::High,
            revealable: false,
            environment: "prod".to_string(),
            component: "auth".to_string(),
            key: "mfa".to_string(),
            description: None,
            created: "2026-06-01T00:00:00Z".to_string(),
            updated: "2026-06-01T00:00:00Z".to_string(),
        }
    }

    // I12 — the seed is a SecretValue, so its Debug never prints the bytes; the
    // non-secret params (algorithm/digits/period) are shown.
    #[test]
    fn totp_seed_debug_is_redacted() {
        let dbg = format!("{:?}", totp());
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("TOTP-SEED-MATERIAL"));
        assert!(dbg.contains("Sha1"));
    }

    #[test]
    fn totp_accessors_and_round_trip() {
        let t = totp();
        assert_eq!(t.sensitivity(), Sensitivity::High);
        assert_eq!(t.environment(), "prod");
        assert!(!t.revealable());
        let json = serde_json::to_string(&t).unwrap();
        assert!(json.contains("\"mode\":\"totp\""));
        // The seed serializes (only ever into the buffer that is AEAD-sealed);
        // the params are present as plain numbers.
        assert!(json.contains("\"digits\":6"));
        assert!(json.contains("\"period\":30"));
        let back: SecretRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn default_vault_is_empty_and_versioned() {
        let v = Vault::default();
        assert_eq!(v.schema_version, SCHEMA_VERSION);
        assert!(v.secrets.is_empty());
    }
}
