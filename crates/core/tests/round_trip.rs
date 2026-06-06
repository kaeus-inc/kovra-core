//! Integration test — AC: encrypt/decrypt round-trip over the vault format with
//! a unique nonce per write (spec §17 L1).

use std::collections::BTreeMap;

use kovra_core::{SCHEMA_VERSION, SecretRecord, SecretValue, Sensitivity, Vault, open, seal};

fn key() -> [u8; kovra_core::KEY_LEN] {
    [0x42; kovra_core::KEY_LEN]
}

fn literal(value: &str, key_name: &str) -> SecretRecord {
    SecretRecord::Literal {
        value: SecretValue::from(value),
        sensitivity: Sensitivity::High,
        revealable: false,
        environment: "prod".to_string(),
        component: "db".to_string(),
        key: key_name.to_string(),
        description: None,
        created: "2026-05-30T00:00:00Z".to_string(),
        updated: "2026-05-30T00:00:00Z".to_string(),
    }
}

#[test]
fn vault_round_trip_through_serde_and_aead() {
    // Build a vault with two sealed literal records.
    let mut secrets = BTreeMap::new();
    secrets.insert(
        "prod/db/password".to_string(),
        seal(&literal("hunter2", "password"), &key()).unwrap(),
    );
    secrets.insert(
        "prod/db/url".to_string(),
        seal(&literal("postgres://localhost", "url"), &key()).unwrap(),
    );
    let vault = Vault {
        schema_version: SCHEMA_VERSION,
        secrets,
    };

    // Persist the whole vault format to JSON and back (serde round-trip).
    let json = serde_json::to_string(&vault).unwrap();
    assert!(
        !json.contains("hunter2"),
        "ciphertext must not leak plaintext"
    );
    let restored: Vault = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, vault);

    // Open each sealed record and confirm the plaintext value is recovered.
    let opened = open(restored.secrets.get("prod/db/password").unwrap(), &key()).unwrap();
    match opened {
        SecretRecord::Literal { value, .. } => assert_eq!(value.expose(), b"hunter2"),
        other => panic!("expected literal, got {other:?}"),
    }
}

#[test]
fn unique_nonce_per_write() {
    let a = seal(&literal("same", "k"), &key()).unwrap();
    let b = seal(&literal("same", "k"), &key()).unwrap();
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.ciphertext, b.ciphertext);
}
