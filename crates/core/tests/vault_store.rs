//! Integration tests for KOV-4 (L2) — the vault store, `~/.vaults` registry,
//! project→global override, truncated fingerprint, tolerant loader, and the
//! rebuildable redb index, exercised end-to-end through the crate's public API.
//!
//! Each test maps to an L2 exit criterion / invariant (spec §17, §10, §1.1;
//! ADR-0001). A `TempDir` stands in for `~/.vaults`; a `MockKeyring` supplies
//! the master key — no real OS keyring, no real secrets.

use std::str::FromStr;

use kovra_core::{
    Coordinate, Index, IndexEntry, KEY_LEN, Keyring, MockKeyring, RecordMode, Registry, Resolution,
    SecretRecord, SecretValue, Sensitivity, VaultOrigin, fingerprint, seal, store,
};

const MASTER: [u8; KEY_LEN] = [0x7c; KEY_LEN];

fn keyring() -> MockKeyring {
    MockKeyring::with_key(MASTER)
}

fn literal(value: &str, env: &str, component: &str, key: &str) -> SecretRecord {
    SecretRecord::Literal {
        value: SecretValue::from(value),
        sensitivity: Sensitivity::Medium,
        revealable: false,
        environment: env.to_string(),
        component: component.to_string(),
        key: key.to_string(),
        description: None,
        created: "2026-05-30T00:00:00Z".to_string(),
        updated: "2026-05-30T00:00:00Z".to_string(),
    }
}

fn write(vault_dir: std::path::PathBuf, c: &Coordinate, record: &SecretRecord) {
    store::write_record(&vault_dir, c, &seal(record, &MASTER).unwrap()).unwrap();
}

fn found_value(res: Resolution) -> (Vec<u8>, VaultOrigin) {
    match res {
        Resolution::Found { record, origin } => match record {
            SecretRecord::Literal { value, .. } => (value.expose().to_vec(), origin),
            other => panic!("expected literal, got {other:?}"),
        },
        Resolution::NotFound => panic!("expected Found, got NotFound"),
    }
}

// L2 exit: project→global override + shadowing.
#[test]
fn override_and_shadowing_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::open(tmp.path()).unwrap();
    let kr = keyring();

    let coord = Coordinate::from_str("secret:prod/db/password").unwrap();
    write(
        reg.global_dir(),
        &coord,
        &literal("global", "prod", "db", "password"),
    );
    write(
        reg.project_dir("api"),
        &coord,
        &literal("project", "prod", "db", "password"),
    );

    // Project shadows global at the exact coordinate.
    let (val, origin) = found_value(reg.resolve(&coord, Some("api"), &kr).unwrap());
    assert_eq!(val, b"project");
    assert_eq!(origin, VaultOrigin::Project("api".into()));
    assert!(reg.shadows(&coord, "api").unwrap());

    // A coordinate present only in global resolves to global, unshadowed.
    let global_only = Coordinate::from_str("secret:prod/cache/url").unwrap();
    write(
        reg.global_dir(),
        &global_only,
        &literal("g", "prod", "cache", "url"),
    );
    let (val, origin) = found_value(reg.resolve(&global_only, Some("api"), &kr).unwrap());
    assert_eq!(val, b"g");
    assert_eq!(origin, VaultOrigin::Global);
    assert!(!reg.shadows(&global_only, "api").unwrap());

    // The global scope selector bypasses the project even when it shadows.
    let global_scoped = Coordinate::from_str("secret://global/prod/db/password").unwrap();
    let (val, origin) = found_value(reg.resolve(&global_scoped, Some("api"), &kr).unwrap());
    assert_eq!(val, b"global");
    assert_eq!(origin, VaultOrigin::Global);
}

// L2 exit: stable truncated fingerprint (literals only); never the full hash (I12).
#[test]
fn fingerprint_is_stable_and_truncated() {
    let a = fingerprint(b"hunter2");
    let b = fingerprint(b"hunter2");
    assert_eq!(a, b, "same value → same fingerprint across calls");
    assert_ne!(fingerprint(b"hunter2"), fingerprint(b"other"));

    // It is a strict, short prefix of the full BLAKE3 digest — not the whole hash.
    let full = blake3::hash(b"hunter2").to_hex().to_string();
    assert!(full.starts_with(&a));
    assert!(a.len() < full.len());
}

// ADR-0001 §A.3: a corrupt record is quarantined; siblings still load.
#[test]
fn tolerant_loader_quarantines_corrupt_record() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::open(tmp.path()).unwrap();
    let good = Coordinate::from_str("secret:prod/db/good").unwrap();
    let bad = Coordinate::from_str("secret:prod/db/bad").unwrap();
    write(
        reg.global_dir(),
        &good,
        &literal("good", "prod", "db", "good"),
    );
    write(reg.global_dir(), &bad, &literal("bad", "prod", "db", "bad"));

    // Corrupt the AEAD tag of one record.
    let bad_path = store::record_path(&reg.global_dir(), &bad).unwrap();
    let mut bytes = std::fs::read(&bad_path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&bad_path, &bytes).unwrap();

    let outcome = store::load_all(&reg.global_dir(), &MASTER).unwrap();
    assert_eq!(outcome.records.len(), 1);
    assert_eq!(outcome.quarantined.len(), 1);
    // The good record is still resolvable directly (point lookup unaffected).
    assert!(matches!(
        reg.resolve(&good, None, &keyring()).unwrap(),
        Resolution::Found { .. }
    ));
}

// ADR-0001 §A.6: the index is a rebuildable cache — losing it is not data loss.
#[test]
fn index_rebuilds_from_records_after_loss() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::open(tmp.path()).unwrap();
    let coords = [
        "secret:prod/db/a",
        "secret:prod/db/b",
        "secret:prod/api/token",
    ];
    for s in coords {
        let c = Coordinate::from_str(s).unwrap();
        let env = c.canonical_path().unwrap();
        let parts: Vec<&str> = env.split('/').collect();
        write(
            reg.global_dir(),
            &c,
            &literal("v", parts[0], parts[1], parts[2]),
        );
    }

    // Build the index, then simulate total index loss.
    {
        let index = Index::open(&reg.global_dir()).unwrap();
        index
            .rebuild_from(&reg.global_dir(), "global", &MASTER)
            .unwrap();
        assert_eq!(index.list(&MASTER).unwrap().len(), 3);
    }
    std::fs::remove_file(reg.global_dir().join(kovra_core::INDEX_FILE)).unwrap();

    // Reopen and rebuild from the records (the source of truth).
    let index = Index::open(&reg.global_dir()).unwrap();
    assert!(index.list(&MASTER).unwrap().is_empty());
    let outcome = index
        .rebuild_from(&reg.global_dir(), "global", &MASTER)
        .unwrap();
    assert_eq!(outcome.records.len(), 3);
    let entries = index.list(&MASTER).unwrap();
    assert_eq!(entries.len(), 3);
    // Every entry carries a truncated fingerprint and no value field exists.
    assert!(
        entries
            .iter()
            .all(|e| e.mode == RecordMode::Literal && e.fingerprint.is_some())
    );
}

// I12: the index persists neither a value nor a full fingerprint, even on disk.
#[test]
fn index_never_persists_value_or_full_fingerprint() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::open(tmp.path()).unwrap();
    let value = "top-secret-credential";
    let coord = Coordinate::from_str("secret:prod/db/password").unwrap();
    write(
        reg.global_dir(),
        &coord,
        &literal(value, "prod", "db", "password"),
    );

    let index = Index::open(&reg.global_dir()).unwrap();
    index
        .rebuild_from(&reg.global_dir(), "global", &MASTER)
        .unwrap();

    // The in-memory entry holds only the truncated fingerprint, never the value.
    let entry: &IndexEntry = &index.list(&MASTER).unwrap()[0];
    assert_eq!(
        entry.fingerprint.as_deref(),
        Some(fingerprint(value.as_bytes()).as_str())
    );

    // The raw index file leaks neither the value nor the full hash (sealed at rest).
    drop(index);
    let raw = std::fs::read(reg.global_dir().join(kovra_core::INDEX_FILE)).unwrap();
    assert!(!windows_contains(&raw, value.as_bytes()));
    let full = blake3::hash(value.as_bytes()).to_hex().to_string();
    assert!(!windows_contains(&raw, full.as_bytes()));
}

// Master key is reached only through the Keyring trait (mock in tests).
#[test]
fn resolution_uses_keyring_supplied_master_key() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::open(tmp.path()).unwrap();
    let coord = Coordinate::from_str("secret:dev/app/key").unwrap();
    write(reg.global_dir(), &coord, &literal("v", "dev", "app", "key"));

    // Right key resolves.
    assert!(matches!(
        reg.resolve(&coord, None, &keyring()).unwrap(),
        Resolution::Found { .. }
    ));
    // A keyring with the wrong key fails opaque (AEAD), never silently returns garbage.
    let wrong = MockKeyring::with_key([0x00; KEY_LEN]);
    assert!(reg.resolve(&coord, None, &wrong).is_err());
    // An empty keyring surfaces a keyring error.
    let empty = MockKeyring::empty();
    assert!(empty.get_master_key().is_err());
    assert!(reg.resolve(&coord, None, &empty).is_err());
}

fn windows_contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
