//! Integration tests for KOV-10 (L4) — the `.env.refs` grammar and the §4.3
//! single-pass resolver, end-to-end through the public API over a `tempfile`
//! registry with `MockKeyring` / `MockEnvSource` / `MockProvider`. No real
//! secrets, no real provider, no network.

use std::str::FromStr;

use kovra_core::{
    Coordinate, EnvRefs, EnvSource, KEY_LEN, Keyring, MockClock, MockEnvSource, MockKeyring,
    MockProvider, Origin, Registry, Resolved, SecretProvider, SecretRecord, SecretValue,
    Sensitivity, resolve, seal, store,
};

const MASTER: [u8; KEY_LEN] = [0x5a; KEY_LEN];

fn keyring() -> MockKeyring {
    MockKeyring::with_key(MASTER)
}

/// Test shim for the original 7-arg resolve shape: the audit/clock/origin
/// plumbing (KOV-16) is filled with a no-op sink, a mock clock, and a human
/// origin so these L4 tests stay focused on resolution semantics. The audit
/// emission itself is covered by the dedicated provider/audit tests below.
#[allow(clippy::too_many_arguments)]
fn run_resolve(
    refs: &EnvRefs,
    env: &str,
    registry: &Registry,
    keyring: &dyn Keyring,
    env_source: &dyn EnvSource,
    provider: &dyn SecretProvider,
    project_override: Option<&str>,
) -> Result<Resolved, kovra_core::CoreError> {
    let audit = kovra_core::MockAuditSink::new();
    let clock = MockClock::default();
    resolve(
        refs,
        env,
        registry,
        keyring,
        env_source,
        provider,
        &audit,
        &clock,
        Origin::Human,
        project_override,
    )
}

fn write(dir: std::path::PathBuf, coord: &str, record: SecretRecord) {
    let c = Coordinate::from_str(coord).unwrap();
    store::write_record(&dir, &c, &seal(&record, &MASTER).unwrap()).unwrap();
}

fn lit(value: &str, env: &str, comp: &str, key: &str) -> SecretRecord {
    SecretRecord::Literal {
        value: SecretValue::from(value),
        sensitivity: Sensitivity::Medium,
        revealable: false,
        environment: env.to_string(),
        component: comp.to_string(),
        key: key.to_string(),
        description: None,
        created: "2026-05-30T00:00:00Z".to_string(),
        updated: "2026-05-30T00:00:00Z".to_string(),
    }
}

fn reference(reference: &str, env: &str, comp: &str, key: &str) -> SecretRecord {
    SecretRecord::Reference {
        reference: reference.to_string(),
        sensitivity: Sensitivity::High,
        revealable: false,
        environment: env.to_string(),
        component: comp.to_string(),
        key: key.to_string(),
        description: None,
        created: "2026-05-30T00:00:00Z".to_string(),
        updated: "2026-05-30T00:00:00Z".to_string(),
    }
}

/// Resolve and return (name -> exposed value) for easy assertions.
fn values(resolved: &kovra_core::Resolved) -> std::collections::HashMap<String, String> {
    resolved
        .vars
        .iter()
        .map(|v| {
            (
                v.name.clone(),
                String::from_utf8_lossy(v.value.expose()).into_owned(),
            )
        })
        .collect()
}

// `${ENV}` substitution + project→global override through the resolver.
#[test]
fn resolves_uri_with_env_substitution_and_override() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::open(tmp.path()).unwrap();
    write(
        reg.global_dir(),
        "secret:dev/db/password",
        lit("global", "dev", "db", "password"),
    );
    write(
        reg.project_dir("api"),
        "secret:dev/db/password",
        lit("project", "dev", "db", "password"),
    );

    let refs = EnvRefs::parse("DB=secret:${ENV}/db/password\nproject = api").unwrap();
    let resolved = run_resolve(
        &refs,
        "dev",
        &reg,
        &keyring(),
        &MockEnvSource::new(),
        &MockProvider::new(),
        None,
    )
    .unwrap();

    let v = values(&resolved);
    assert_eq!(
        v["DB"], "project",
        "project shadows global through the resolver"
    );
    // metadata for L5
    let db = &resolved.vars[0];
    assert_eq!(db.sensitivity, Some(Sensitivity::Medium));
    assert_eq!(db.coordinate.as_deref(), Some("dev/db/password"));
}

// project_override wins over the `.env.refs` project= line.
#[test]
fn project_override_beats_file_project() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::open(tmp.path()).unwrap();
    write(
        reg.global_dir(),
        "secret:dev/db/password",
        lit("global", "dev", "db", "password"),
    );
    write(
        reg.project_dir("api"),
        "secret:dev/db/password",
        lit("api-val", "dev", "db", "password"),
    );
    write(
        reg.project_dir("billing"),
        "secret:dev/db/password",
        lit("billing-val", "dev", "db", "password"),
    );

    let refs = EnvRefs::parse("DB=secret:dev/db/password\nproject = api").unwrap();
    let resolved = run_resolve(
        &refs,
        "dev",
        &reg,
        &keyring(),
        &MockEnvSource::new(),
        &MockProvider::new(),
        Some("billing"),
    )
    .unwrap();
    assert_eq!(values(&resolved)["DB"], "billing-val");
}

// I4c — a prod coordinate with a `| fallback` errors; non-prod uses the fallback.
#[test]
fn i4c_prod_forbids_fallback() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::open(tmp.path()).unwrap();

    let prod = EnvRefs::parse("H=secret:${ENV}/db/host | localhost").unwrap();
    assert!(
        run_resolve(
            &prod,
            "prod",
            &reg,
            &keyring(),
            &MockEnvSource::new(),
            &MockProvider::new(),
            None
        )
        .is_err(),
        "prod + fallback must error (I4c)"
    );

    // Same contract under dev: the vault misses, so the fallback applies.
    let resolved = run_resolve(
        &prod,
        "dev",
        &reg,
        &keyring(),
        &MockEnvSource::new(),
        &MockProvider::new(),
        None,
    )
    .unwrap();
    assert_eq!(values(&resolved)["H"], "localhost");
}

// `${env:}` passthrough: present returns the value; missing+no-fallback errors
// (never empty); missing+fallback uses the fallback.
#[test]
fn env_passthrough_never_injects_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::open(tmp.path()).unwrap();
    let env = MockEnvSource::new().with("CI_TOKEN", "tok-123");

    let present = EnvRefs::parse("CI=${env:CI_TOKEN}").unwrap();
    let resolved = run_resolve(
        &present,
        "dev",
        &reg,
        &keyring(),
        &env,
        &MockProvider::new(),
        None,
    )
    .unwrap();
    assert_eq!(values(&resolved)["CI"], "tok-123");

    let missing = EnvRefs::parse("CI=${env:NOPE}").unwrap();
    assert!(
        run_resolve(
            &missing,
            "dev",
            &reg,
            &keyring(),
            &env,
            &MockProvider::new(),
            None
        )
        .is_err(),
        "missing passthrough with no fallback must error, never inject empty"
    );

    let missing_fb = EnvRefs::parse("LVL=${env:NOPE | info}").unwrap();
    let resolved = run_resolve(
        &missing_fb,
        "dev",
        &reg,
        &keyring(),
        &env,
        &MockProvider::new(),
        None,
    )
    .unwrap();
    assert_eq!(values(&resolved)["LVL"], "info");
}

// Literal passthrough.
#[test]
fn literal_passes_through() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::open(tmp.path()).unwrap();
    let refs = EnvRefs::parse("PORT=8080").unwrap();
    let resolved = run_resolve(
        &refs,
        "dev",
        &reg,
        &keyring(),
        &MockEnvSource::new(),
        &MockProvider::new(),
        None,
    )
    .unwrap();
    assert_eq!(values(&resolved)["PORT"], "8080");
    assert_eq!(resolved.vars[0].sensitivity, None);
}

// I8 + dedup-by-ref: two vars on the same reference materialize the provider once.
#[test]
fn references_materialize_at_runtime_deduped_by_ref() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::open(tmp.path()).unwrap();
    // Two distinct coordinates that both point at the SAME external reference.
    write(
        reg.global_dir(),
        "secret:dev/db/url",
        reference("azure-kv://kv/db-url", "dev", "db", "url"),
    );
    write(
        reg.global_dir(),
        "secret:dev/api/url",
        reference("azure-kv://kv/db-url", "dev", "api", "url"),
    );

    let provider = MockProvider::new().with("azure-kv://kv/db-url", "postgres://h/db");
    let refs = EnvRefs::parse("A=secret:dev/db/url\nB=secret:dev/api/url").unwrap();
    let resolved = run_resolve(
        &refs,
        "dev",
        &reg,
        &keyring(),
        &MockEnvSource::new(),
        &provider,
        None,
    )
    .unwrap();

    let v = values(&resolved);
    assert_eq!(v["A"], "postgres://h/db");
    assert_eq!(v["B"], "postgres://h/db");
    assert_eq!(
        provider.call_count("azure-kv://kv/db-url"),
        1,
        "provider invoked once per ref"
    );
    assert!(
        resolved
            .vars
            .iter()
            .all(|rv| rv.reference.as_deref() == Some("azure-kv://kv/db-url"))
    );
}

// A coordinate that does not resolve and has no fallback errors (never empty).
#[test]
fn unresolved_uri_without_fallback_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::open(tmp.path()).unwrap();
    let refs = EnvRefs::parse("X=secret:dev/db/absent").unwrap();
    assert!(
        run_resolve(
            &refs,
            "dev",
            &reg,
            &keyring(),
            &MockEnvSource::new(),
            &MockProvider::new(),
            None
        )
        .is_err()
    );
}

// Resolved values are SecretValue — their Debug is redacted (no plaintext leak).
#[test]
fn resolved_values_have_redacted_debug() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::open(tmp.path()).unwrap();
    let refs = EnvRefs::parse("PORT=8080").unwrap();
    let resolved = run_resolve(
        &refs,
        "dev",
        &reg,
        &keyring(),
        &MockEnvSource::new(),
        &MockProvider::new(),
        None,
    )
    .unwrap();
    let dbg = format!("{:?}", resolved.vars[0].value);
    assert!(dbg.contains("REDACTED"));
    assert!(!dbg.contains("8080"));
}

// The grammar suite is also exercised here at the API boundary.
#[test]
fn grammar_rejects_cross_variable_interpolation() {
    assert!(matches!(
        EnvRefs::parse("DSN=postgres://u:${DB_PASSWORD}@h"),
        Err(kovra_core::CoreError::EnvRefs(_))
    ));
}

// ───────────────────────── keypair half-selector (KOV-12) ─────────────────────────

fn keypair(env: &str, comp: &str, key: &str, sens: Sensitivity) -> SecretRecord {
    SecretRecord::Keypair {
        algorithm: kovra_core::KeyAlgorithm::Ed25519,
        private: Some(SecretValue::from("PRIVATE-OPENSSH-KEY")),
        public: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 kovra-test".to_string(),
        sensitivity: sens,
        revealable: false,
        environment: env.to_string(),
        component: comp.to_string(),
        key: key.to_string(),
        description: None,
        created: "2026-06-01T00:00:00Z".to_string(),
        updated: "2026-06-01T00:00:00Z".to_string(),
    }
}

// `#public` injects the public key as a non-secret (no coordinate ⇒ no gating,
// not masked); `#private` injects the private half carrying the record's
// sensitivity + coordinate (so the Wrapper gates it like any inject).
#[test]
fn keypair_half_selector_injects_chosen_half() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::open(tmp.path()).unwrap();
    write(
        reg.global_dir(),
        "secret:dev/ssh/deploy",
        keypair("dev", "ssh", "deploy", Sensitivity::High),
    );

    let refs =
        EnvRefs::parse("PUB=secret:dev/ssh/deploy#public\nPRIV=secret:dev/ssh/deploy#private")
            .unwrap();
    let resolved = run_resolve(
        &refs,
        "dev",
        &reg,
        &keyring(),
        &MockEnvSource::new(),
        &MockProvider::new(),
        None,
    )
    .unwrap();

    let v = values(&resolved);
    assert_eq!(v["PUB"], "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 kovra-test");
    assert_eq!(v["PRIV"], "PRIVATE-OPENSSH-KEY");

    let pub_var = resolved.vars.iter().find(|x| x.name == "PUB").unwrap();
    let priv_var = resolved.vars.iter().find(|x| x.name == "PRIV").unwrap();
    // public half: not a secret — no coordinate, no sensitivity ⇒ ungated, unmasked.
    assert_eq!(pub_var.coordinate, None);
    assert_eq!(pub_var.sensitivity, None);
    // private half: carries the record's sensitivity + coordinate ⇒ the Wrapper
    // gates it (high here) exactly like any inject (I3/I15).
    assert_eq!(priv_var.coordinate.as_deref(), Some("dev/ssh/deploy"));
    assert_eq!(priv_var.sensitivity, Some(Sensitivity::High));
}

// An unspecified half defaults to the public key (the safe, non-secret default).
#[test]
fn keypair_unspecified_half_defaults_to_public() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::open(tmp.path()).unwrap();
    write(
        reg.global_dir(),
        "secret:dev/ssh/deploy",
        keypair("dev", "ssh", "deploy", Sensitivity::High),
    );
    let refs = EnvRefs::parse("K=secret:dev/ssh/deploy").unwrap();
    let resolved = run_resolve(
        &refs,
        "dev",
        &reg,
        &keyring(),
        &MockEnvSource::new(),
        &MockProvider::new(),
        None,
    )
    .unwrap();
    assert_eq!(
        values(&resolved)["K"],
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 kovra-test"
    );
    assert_eq!(resolved.vars[0].coordinate, None);
}

// `#private` against a public-only entry is an explicit error, never empty.
#[test]
fn keypair_private_on_public_only_entry_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::open(tmp.path()).unwrap();
    let public_only = SecretRecord::Keypair {
        algorithm: kovra_core::KeyAlgorithm::Ed25519,
        private: None,
        public: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 peer".to_string(),
        sensitivity: Sensitivity::Low,
        revealable: false,
        environment: "dev".to_string(),
        component: "peer".to_string(),
        key: "recipient".to_string(),
        description: None,
        created: "2026-06-01T00:00:00Z".to_string(),
        updated: "2026-06-01T00:00:00Z".to_string(),
    };
    write(reg.global_dir(), "secret:dev/peer/recipient", public_only);
    let refs = EnvRefs::parse("P=secret:dev/peer/recipient#private").unwrap();
    let res = run_resolve(
        &refs,
        "dev",
        &reg,
        &keyring(),
        &MockEnvSource::new(),
        &MockProvider::new(),
        None,
    );
    assert!(matches!(res, Err(kovra_core::CoreError::EnvRefs(_))));
}

// ───────────────────────── totp out of `.env.refs` (KOV-11) ─────────────────────────

// A TOTP coordinate is NOT resolvable via `.env.refs`: a code is time-varying /
// single-use, and the seed must never be injected (I11/I14). The resolver
// returns a clear `EnvRefs` error — never a silent empty, never the seed bytes.
#[test]
fn totp_coordinate_in_env_refs_is_an_explicit_error_not_the_seed() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::open(tmp.path()).unwrap();
    let seed_marker = "SEED-MATERIAL-MUST-NOT-INJECT";
    let totp = SecretRecord::Totp {
        seed: SecretValue::from(seed_marker),
        algorithm: kovra_core::TotpAlgorithm::Sha1,
        digits: 6,
        period: 30,
        sensitivity: Sensitivity::High,
        revealable: false,
        environment: "dev".to_string(),
        component: "auth".to_string(),
        key: "mfa".to_string(),
        description: None,
        created: "2026-06-01T00:00:00Z".to_string(),
        updated: "2026-06-01T00:00:00Z".to_string(),
    };
    write(reg.global_dir(), "secret:dev/auth/mfa", totp);
    let refs = EnvRefs::parse("OTP=secret:dev/auth/mfa").unwrap();
    let res = run_resolve(
        &refs,
        "dev",
        &reg,
        &keyring(),
        &MockEnvSource::new(),
        &MockProvider::new(),
        None,
    );
    match res {
        Err(kovra_core::CoreError::EnvRefs(msg)) => {
            // the seed must never appear in the error (I12)
            assert!(!msg.contains(seed_marker));
            assert!(msg.contains("TOTP") || msg.contains("totp") || msg.contains("kovra code"));
        }
        other => panic!("expected an EnvRefs error for a TOTP coordinate, got {other:?}"),
    }
}

// ───────────────────────── provider audit (KOV-16 / I12) ─────────────────────────

// I12 — materializing a reference emits a `ProviderInvocation` audit event that
// records the coordinate + environment + URI scheme, and NEVER the value. The
// per-run dedup means one event per distinct reference even with two vars.
#[test]
fn i12_provider_invocation_is_audited_with_scheme_not_value() {
    use kovra_core::{AuditAction, MockAuditSink};

    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::open(tmp.path()).unwrap();
    write(
        reg.global_dir(),
        "secret:dev/db/url",
        reference("azure-kv://corp-kv/db-url", "dev", "db", "url"),
    );
    write(
        reg.global_dir(),
        "secret:dev/api/url",
        reference("azure-kv://corp-kv/db-url", "dev", "api", "url"),
    );

    let value_marker = "postgres://h/db-VALUE-MUST-NOT-BE-AUDITED";
    let provider = MockProvider::new().with("azure-kv://corp-kv/db-url", value_marker);
    let refs = EnvRefs::parse("A=secret:dev/db/url\nB=secret:dev/api/url").unwrap();
    let audit = MockAuditSink::new();
    let clock = MockClock::default();
    let resolved = resolve(
        &refs,
        "dev",
        &reg,
        &keyring(),
        &MockEnvSource::new(),
        &provider,
        &audit,
        &clock,
        Origin::Human,
        None,
    )
    .unwrap();

    // the value did materialize into the resolved vars
    assert_eq!(values(&resolved)["A"], value_marker);

    let events = audit.events();
    let invocations: Vec<_> = events
        .iter()
        .filter(|e| e.action == AuditAction::ProviderInvocation)
        .collect();
    // deduped: one invocation event for the single distinct reference
    assert_eq!(
        invocations.len(),
        1,
        "one ProviderInvocation per distinct reference (deduped)"
    );
    let ev = invocations[0];
    // coordinate + environment recorded (an address, never a value)
    assert_eq!(ev.coordinate.as_deref(), Some("dev/db/url"));
    assert_eq!(ev.environment.as_deref(), Some("dev"));
    // the scheme is recorded as the result; the value never is
    assert_eq!(ev.result, "scheme:azure-kv");
    let blob = serde_json::to_string(ev).unwrap();
    assert!(
        !blob.contains(value_marker),
        "the materialized value must never be audited (I12): {blob}"
    );
}

// A reference whose scheme has no registered provider is a clear error through
// the router — never a silent empty, never a fabricated value.
#[test]
fn unsupported_scheme_through_router_errors() {
    use kovra_core::SchemeRouter;

    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::open(tmp.path()).unwrap();
    write(
        reg.global_dir(),
        "secret:dev/db/url",
        reference("aws-sm://arn/db-url", "dev", "db", "url"),
    );
    // an empty router: no provider for `aws-sm`
    let router = SchemeRouter::new();
    let refs = EnvRefs::parse("A=secret:dev/db/url").unwrap();
    let res = run_resolve(
        &refs,
        "dev",
        &reg,
        &keyring(),
        &MockEnvSource::new(),
        &router,
        None,
    );
    assert!(matches!(res, Err(kovra_core::CoreError::Provider(_))));
}
