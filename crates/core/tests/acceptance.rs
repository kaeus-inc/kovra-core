//! Integration tests mapping each KOV-3 acceptance criterion end-to-end through
//! the crate's public API (complementing the inline unit/proptest coverage).

use std::str::FromStr;

use kovra_core::{
    Coordinate, CoreError, EnvSegment, Scope, SecretRecord, SecretValue, Sensitivity, seal,
};
// KOV-28 per-invariant acceptance gate (the reveal/inject funnel + package layer
// exercised through the *public* API, as an external consumer sees them).
use kovra_core::{
    AccessRequest, AgentScope, Clock, Decision, DenyReason, KeyAlgorithm, MockClock, Operation,
    Origin, PackagePayload, Surface, decide, enforce_no_prod_unattended, generate, open_attended,
    seal_package,
};

// AC: coordinate is always three segments; only ${ENV} interpolates.
#[test]
fn ac_coordinate_three_segments_and_env_only_interpolation() {
    // exactly three segments, default scope
    let c = Coordinate::from_str("secret:prod/db/password").unwrap();
    assert_eq!(c.scope, Scope::Default);
    assert_eq!(c.environment, EnvSegment::Literal("prod".to_string()));

    // ${ENV} placeholder in the environment segment
    let c = Coordinate::from_str("secret:${ENV}/db/password").unwrap();
    assert_eq!(c.environment, EnvSegment::Placeholder);

    // global scope selector
    let c = Coordinate::from_str("secret://global/prod/db/password").unwrap();
    assert_eq!(c.scope, Scope::Global);

    // wrong segment counts and stray interpolation are rejected
    for bad in [
        "secret:prod/db",                // 2 segments
        "secret:prod/db/password/extra", // 4 segments
        "secret:${FOO}/db/password",     // non-ENV interpolation
        "secret:prod/${COMPONENT}/pw",   // interpolation outside env
        "prod/db/password",              // missing scheme
        "secret://local/p/c/k",          // unknown scope authority
    ] {
        assert!(
            matches!(
                Coordinate::from_str(bad),
                Err(CoreError::InvalidCoordinate(_))
            ),
            "expected `{bad}` to be rejected"
        );
    }
}

// AC: malformed input fails, never silently resolves.
#[test]
fn ac_malformed_never_silently_resolves() {
    // an empty segment must error, not yield an empty-but-valid coordinate
    assert!(Coordinate::from_str("secret:prod//password").is_err());
    assert!(Coordinate::from_str("secret:").is_err());
    assert!(Coordinate::from_str("").is_err());
}

// AC: no secret-bearing type exposes the value via Debug; sealed bytes hide it.
#[test]
fn ac_anti_leak_i12() {
    let value = "s3cr3t-token";
    let sv = SecretValue::from(value);

    // SecretValue Debug is redacted.
    assert_eq!(format!("{sv:?}"), "SecretValue(REDACTED)");

    // A Literal record's Debug never prints the value.
    let record = SecretRecord::Literal {
        value: sv,
        sensitivity: Sensitivity::High,
        revealable: false,
        environment: "prod".to_string(),
        component: "api".to_string(),
        key: "token".to_string(),
        description: None,
        created: "2026-05-30T00:00:00Z".to_string(),
        updated: "2026-05-30T00:00:00Z".to_string(),
    };
    assert!(!format!("{record:?}").contains(value));

    // Sealed bytes do not contain the plaintext.
    let sealed = seal(&record, &[3u8; kovra_core::KEY_LEN]).unwrap();
    assert!(!contains(&sealed.ciphertext, value.as_bytes()));
}

// AC / I6: the coordinate grammar carries only the coordinate; the value is a
// separate SecretValue and is never part of any parsed URI.
#[test]
fn ac_i6_value_never_in_coordinate() {
    // There is no URI syntax that attaches a value: an attempt to smuggle one as
    // a fourth segment or a query is rejected, so the value can only travel as a
    // distinct SecretValue argument.
    assert!(Coordinate::from_str("secret:prod/db/password/hunter2").is_err());
    assert!(Coordinate::from_str("secret:prod/db/password=hunter2").is_ok());
    // ^ note: "password=hunter2" is a (weird) key, not a value binding — the
    //   parser has no concept of a value, which is exactly the I6 guarantee.
    let c = Coordinate::from_str("secret:prod/db/password=hunter2").unwrap();
    assert_eq!(c.key, "password=hunter2");
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// KOV-28 — per-invariant acceptance gate (§22.1 "Invariant ⇒ required test").
//
// Each test exercises one reveal/inject or package invariant through the public
// `decide` funnel / package API — the external-consumer altitude. They
// complement, not replace, the inline unit tests and the per-face tests in the
// wrapper/webui/ffi crates (mapped in the KOV-28 threat-model comment on the WI).
// ---------------------------------------------------------------------------

/// Build an [`AccessRequest`] over a full agent scope (scope is exercised
/// separately by `out_of_scope_is_unaddressable` in `policy.rs`).
fn req<'a>(
    coordinate: &'a Coordinate,
    sensitivity: Sensitivity,
    operation: Operation,
    surface: Surface,
    origin: Origin,
) -> AccessRequest<'a> {
    AccessRequest {
        coordinate,
        project: None,
        sensitivity,
        revealable: false,
        operation,
        surface,
        origin,
    }
}

fn lit_record(env: &str, key: &str, value: &str) -> SecretRecord {
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

// I1 — the Web UI never reveals a `high` plaintext: the funnel denies it
// (masked + fingerprint is the surface's job; the value never leaves core).
#[test]
fn ac_i1_webui_never_reveals_high() {
    let c = Coordinate::from_str("secret:dev/app/key").unwrap();
    let d = decide(
        &req(
            &c,
            Sensitivity::High,
            Operation::Reveal,
            Surface::WebUi,
            Origin::Human,
        ),
        &AgentScope::full(),
    );
    assert_eq!(d, Decision::Deny(DenyReason::WebUiCriticalMasked));
}

// I2 — an `inject-only` secret is never revealed on ANY surface.
#[test]
fn ac_i2_inject_only_never_revealed_on_any_surface() {
    let c = Coordinate::from_str("secret:dev/app/key").unwrap();
    for surface in [Surface::Cli, Surface::WebUi, Surface::Mcp] {
        let d = decide(
            &req(
                &c,
                Sensitivity::InjectOnly,
                Operation::Reveal,
                surface,
                Origin::Human,
            ),
            &AgentScope::full(),
        );
        assert_eq!(d, Decision::Deny(DenyReason::InjectOnlyNeverRevealed));
    }
}

// I11 — the MCP surface never reveals `high`/`prod` plaintext into the agent's
// context; the denial is a `DenyReason` (an enum — it structurally cannot carry
// a value, which is the anti-leak guarantee).
#[test]
fn ac_i11_mcp_never_reveals_critical_reason_only() {
    let prod = Coordinate::from_str("secret:prod/db/password").unwrap();
    let high = Coordinate::from_str("secret:dev/app/key").unwrap();
    // prod-at-any-sensitivity and high-anywhere are both denied on MCP.
    for (coord, sensitivity) in [(&prod, Sensitivity::Medium), (&high, Sensitivity::High)] {
        let d = decide(
            &req(
                coord,
                sensitivity,
                Operation::Reveal,
                Surface::Mcp,
                Origin::Agent,
            ),
            &AgentScope::full(),
        );
        assert_eq!(d, Decision::Deny(DenyReason::McpCriticalForbidden));
    }
}

// I14 — an agent may not pull `prod` plaintext into context; a human point-reveal
// is the deliberate, confirmation-gated door.
#[test]
fn ac_i14_prod_into_agent_denied_human_confirms() {
    let c = Coordinate::from_str("secret:prod/db/password").unwrap();
    assert_eq!(
        decide(
            &req(
                &c,
                Sensitivity::Medium,
                Operation::Reveal,
                Surface::Cli,
                Origin::Agent
            ),
            &AgentScope::full()
        ),
        Decision::Deny(DenyReason::ProdRevealIntoAgentContext)
    );
    assert_eq!(
        decide(
            &req(
                &c,
                Sensitivity::High,
                Operation::Reveal,
                Surface::Cli,
                Origin::Human
            ),
            &AgentScope::full()
        ),
        Decision::RequireConfirmation
    );
}

// I4a — a `prod` secret is never packaged; the refusal names the coordinate but
// never carries the value.
#[test]
fn ac_i4a_package_refuses_prod_without_leaking_value() {
    let recipient = generate(KeyAlgorithm::Ed25519).unwrap();
    let payload = PackagePayload::new(
        "prod",
        "2026-05-30T00:00:00Z",
        9_999_999_999,
        vec![lit_record("prod", "db", "prod-only-secret")],
    );
    let err = seal_package(payload, &recipient.public_openssh).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("I4a"), "names the invariant: {msg}");
    assert!(msg.contains("prod/app/db"), "names the coordinate: {msg}");
    assert!(
        !msg.contains("prod-only-secret"),
        "the error must never carry the value"
    );
}

// I4b — defense in depth: even a (forged) package carrying a `prod` entry cannot
// be consumed unattended.
#[test]
fn ac_i4b_unattended_refuses_prod_entry() {
    let payload = PackagePayload::new(
        "prod",
        "2026-05-30T00:00:00Z",
        9_999_999_999,
        vec![lit_record("prod", "db", "x")],
    );
    let err = enforce_no_prod_unattended(&payload).unwrap_err();
    assert!(format!("{err}").contains("I4b"));
}

// I8 — a reference travels as its pointer only: sealing then opening a package
// preserves the URI and never materializes (or stores) a value.
#[test]
fn ac_i8_reference_travels_as_pointer() {
    let recipient = generate(KeyAlgorithm::Ed25519).unwrap();
    let clock = MockClock::default();
    let reference = SecretRecord::Reference {
        reference: "azure-kv://corp-kv/api-key".to_string(),
        sensitivity: Sensitivity::Medium,
        revealable: false,
        environment: "dev".to_string(),
        component: "app".to_string(),
        key: "api".to_string(),
        description: None,
        created: "2026-05-30T00:00:00Z".to_string(),
        updated: "2026-05-30T00:00:00Z".to_string(),
    };
    let payload = PackagePayload::new(
        "dev",
        "2026-05-30T00:00:00Z",
        clock.unix_secs() + 3600,
        vec![reference],
    );
    let (package, _token) = seal_package(payload, &recipient.public_openssh).unwrap();
    let opened = open_attended(&package, &recipient.private_openssh, &clock).unwrap();
    assert_eq!(
        opened.entries[0].reference(),
        Some("azure-kv://corp-kv/api-key"),
        "the reference survives as a pointer, with no value attached"
    );
}
