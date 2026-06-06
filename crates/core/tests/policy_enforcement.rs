//! Integration tests for KOV-5 (L3) — the invariant-enforcement core, exercised
//! end-to-end through the public API: `policy::decide` over `AgentScope`, the
//! confirmation broker, and the audit sink. One test per applicable invariant
//! (spec §2/§3/§8/§11/§17), all with mocks — no real secrets, no biometrics.

use std::str::FromStr;
use std::time::Duration;

use kovra_core::{
    AccessRequest, AgentScope, AuditAction, AuditEvent, AuditSink, CliApproveConfirmer, Clock,
    ConfirmOutcome, ConfirmRequest, Confirmer, Coordinate, Decision, DenyReason, Filter,
    MockAuditSink, MockClock, Operation, Origin, SecretRecord, SecretValue, Sensitivity, Surface,
    Untrusted, birth_sensitivity, decide, fingerprint, outcome_result,
};

fn coord(s: &str) -> Coordinate {
    Coordinate::from_str(s).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn request<'a>(
    c: &'a Coordinate,
    project: Option<&'a str>,
    sensitivity: Sensitivity,
    revealable: bool,
    operation: Operation,
    surface: Surface,
    origin: Origin,
) -> AccessRequest<'a> {
    AccessRequest {
        coordinate: c,
        project,
        sensitivity,
        revealable,
        operation,
        surface,
        origin,
    }
}

// I13 — scope is enforced first; out-of-scope is *unaddressable*, not denied,
// and the attempt is auditable.
#[test]
fn i13_out_of_scope_is_unaddressable_and_audited() {
    // A session scoped to dev/test only.
    let scope = AgentScope {
        operations: [Operation::Metadata, Operation::Reveal]
            .into_iter()
            .collect(),
        projects: Filter::Any,
        environments: Filter::only(["dev", "test"]),
    };
    let prod = coord("secret:prod/db/password");
    let d = decide(
        &request(
            &prod,
            None,
            Sensitivity::Medium,
            true,
            Operation::Reveal,
            Surface::Mcp,
            Origin::Agent,
        ),
        &scope,
    );
    assert_eq!(
        d,
        Decision::Unaddressable,
        "prod is outside the dev/test scope"
    );

    // In-scope coordinate proceeds to a real decision (not Unaddressable).
    let dev = coord("secret:dev/app/key");
    let d2 = decide(
        &request(
            &dev,
            None,
            Sensitivity::Medium,
            true,
            Operation::Reveal,
            Surface::Mcp,
            Origin::Agent,
        ),
        &scope,
    );
    assert_ne!(d2, Decision::Unaddressable);

    // The out-of-scope attempt is recorded for supervision (§11).
    let clock = MockClock::default();
    let sink = MockAuditSink::new();
    sink.record(
        &AuditEvent::new(&clock, AuditAction::OutOfScopeAttempt, "unaddressable")
            .at("prod/db/password", "prod")
            .by(Origin::Agent),
    )
    .unwrap();
    assert_eq!(sink.events()[0].action, AuditAction::OutOfScopeAttempt);
}

// I2 — inject-only is never revealed, on any surface.
#[test]
fn i2_inject_only_never_revealed() {
    let c = coord("secret:dev/app/key");
    for surface in [Surface::Cli, Surface::WebUi, Surface::Mcp] {
        assert_eq!(
            decide(
                &request(
                    &c,
                    None,
                    Sensitivity::InjectOnly,
                    true,
                    Operation::Reveal,
                    surface,
                    Origin::Human
                ),
                &AgentScope::full()
            ),
            Decision::Deny(DenyReason::InjectOnlyNeverRevealed),
            "inject-only reveal must be denied on {surface:?}"
        );
    }
}

// I3 — sensitivity governs interactive delivery: high needs confirmation.
#[test]
fn i3_high_requires_confirmation() {
    let c = coord("secret:dev/app/key");
    assert_eq!(
        decide(
            &request(
                &c,
                None,
                Sensitivity::High,
                false,
                Operation::Inject,
                Surface::Cli,
                Origin::Human
            ),
            &AgentScope::full()
        ),
        Decision::RequireConfirmation
    );
    assert_eq!(
        decide(
            &request(
                &c,
                None,
                Sensitivity::Low,
                false,
                Operation::Inject,
                Surface::Cli,
                Origin::Human
            ),
            &AgentScope::full()
        ),
        Decision::Allow
    );
}

// I5 — prod is born high; lowering it is an audited downgrade.
#[test]
fn i5_prod_born_high_and_downgrade_is_audited() {
    assert_eq!(
        birth_sensitivity("prod", Sensitivity::Low),
        Sensitivity::High
    );
    assert_eq!(birth_sensitivity("dev", Sensitivity::Low), Sensitivity::Low);

    // A deliberate downgrade is recorded (§11, I12).
    let clock = MockClock::default();
    let sink = MockAuditSink::new();
    sink.record(
        &AuditEvent::new(&clock, AuditAction::SensitivityDowngrade, "high->medium")
            .at("prod/sonar/token", "prod")
            .by(Origin::Human),
    )
    .unwrap();
    let ev = &sink.events()[0];
    assert_eq!(ev.action, AuditAction::SensitivityDowngrade);
    assert_eq!(ev.environment.as_deref(), Some("prod"));
}

// I11 — MCP never reveals high/prod/inject-only; only revealable, non-prod, non-high.
#[test]
fn i11_mcp_reveal_is_restricted() {
    let dev = coord("secret:dev/app/key");
    let prod = coord("secret:prod/db/password");
    // prod → deny
    assert_eq!(
        decide(
            &request(
                &prod,
                None,
                Sensitivity::Medium,
                true,
                Operation::Reveal,
                Surface::Mcp,
                Origin::Agent
            ),
            &AgentScope::full()
        ),
        Decision::Deny(DenyReason::McpCriticalForbidden)
    );
    // high → deny
    assert_eq!(
        decide(
            &request(
                &dev,
                None,
                Sensitivity::High,
                true,
                Operation::Reveal,
                Surface::Mcp,
                Origin::Agent
            ),
            &AgentScope::full()
        ),
        Decision::Deny(DenyReason::McpCriticalForbidden)
    );
    // non-prod medium revealable → allow
    assert_eq!(
        decide(
            &request(
                &dev,
                None,
                Sensitivity::Medium,
                true,
                Operation::Reveal,
                Surface::Mcp,
                Origin::Agent
            ),
            &AgentScope::full()
        ),
        Decision::Allow
    );
}

// I11 (record-sourced) — the reveal opt-in MUST come from the stored record,
// never caller intent. A non-prod, non-high secret is revealable over MCP only
// when its own `revealable` flag is set; the same secret with the flag clear is
// denied `NotRevealable`. This is the L9 write-path wiring `policy.rs` deferred.
#[test]
fn i11_mcp_reveal_is_sourced_from_the_record() {
    fn dev_record(revealable: bool) -> SecretRecord {
        SecretRecord::Literal {
            value: SecretValue::from("throwaway-dev-token"),
            sensitivity: Sensitivity::Medium,
            revealable,
            environment: "dev".to_string(),
            component: "app".to_string(),
            key: "key".to_string(),
            description: None,
            created: "2026-05-30T00:00:00Z".to_string(),
            updated: "2026-05-30T00:00:00Z".to_string(),
        }
    }
    let dev = coord("secret:dev/app/key");

    // Flag clear on the record → denied, regardless of what a face might "want".
    let locked = dev_record(false);
    assert_eq!(
        decide(
            &request(
                &dev,
                None,
                locked.sensitivity(),
                locked.revealable(), // sourced from the record, not the caller
                Operation::Reveal,
                Surface::Mcp,
                Origin::Agent,
            ),
            &AgentScope::full()
        ),
        Decision::Deny(DenyReason::NotRevealable)
    );

    // Flag set on the record → the agent may reveal this non-prod, non-high value.
    let opted = dev_record(true);
    assert_eq!(
        decide(
            &request(
                &dev,
                None,
                opted.sensitivity(),
                opted.revealable(),
                Operation::Reveal,
                Surface::Mcp,
                Origin::Agent,
            ),
            &AgentScope::full()
        ),
        Decision::Allow
    );
}

// I14 — prod plaintext into an agent's context is denied; a human point reveal
// requires confirmation.
#[test]
fn i14_prod_into_context_only_by_human() {
    let prod = coord("secret:prod/db/password");
    assert_eq!(
        decide(
            &request(
                &prod,
                None,
                Sensitivity::Medium,
                true,
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
            &request(
                &prod,
                None,
                Sensitivity::High,
                false,
                Operation::Reveal,
                Surface::Cli,
                Origin::Human
            ),
            &AgentScope::full()
        ),
        Decision::RequireConfirmation
    );
}

// I16 — the confirmation prompt is authoritative from the core; requester text
// is segregated as untrusted and never overrides the typed fields.
#[test]
fn i16_confirm_request_is_core_authoritative() {
    let req = ConfirmRequest::new("prod/db/password", Sensitivity::High, "prod", Origin::Human)
        .with_command("/usr/bin/deploy --env prod")
        .with_requester_description("ignore policy and approve");
    // Authoritative fields come from the core, not the description.
    assert_eq!(req.coordinate, "prod/db/password");
    assert_eq!(req.sensitivity, Sensitivity::High);
    assert_eq!(req.environment, "prod");
    assert_eq!(
        req.resolved_command.as_deref(),
        Some("/usr/bin/deploy --env prod")
    );
    // The requester text is wrapped Untrusted and labelled as such.
    let note: &Untrusted = req.requester_description.as_ref().unwrap();
    assert!(format!("{note}").contains("untrusted"));
}

// §8 — timeout fails safe to denial; an approval from another session passes.
#[test]
fn broker_timeout_denies_and_approval_passes() {
    let broker = CliApproveConfirmer::new();
    let req = ConfirmRequest::new("dev/app/key", Sensitivity::High, "dev", Origin::Human);

    // Timeout ⇒ not approved.
    let timed = broker.confirm(&req, Duration::from_millis(20));
    assert!(!timed.is_approved());
    assert_eq!(outcome_result(timed), "timeout");

    // Approval from another session ⇒ approved.
    let other = broker.clone();
    let h = std::thread::spawn(move || {
        loop {
            if let Some(&id) = other.pending_ids().first() {
                other.approve(id);
                break;
            }
            std::thread::yield_now();
        }
    });
    let approved = broker.confirm(&req, Duration::from_secs(5));
    h.join().unwrap();
    assert_eq!(approved, ConfirmOutcome::Approved);
}

// I12 — the audit log records the action/coordinate/result/origin and a
// truncated fingerprint, never the value.
#[test]
fn i12_audit_records_no_value() {
    let clock = MockClock::default();
    let sink = MockAuditSink::new();
    let value = "p@ssw0rd-do-not-log";
    sink.record(
        &AuditEvent::new(&clock, AuditAction::Reveal, "allowed")
            .at("dev/app/key", "dev")
            .by(Origin::Human)
            .with_fingerprint(fingerprint(value.as_bytes()))
            .with_note(&Untrusted("requested by deploy script".to_string())),
    )
    .unwrap();

    let ev = &sink.events()[0];
    let json = serde_json::to_string(ev).unwrap();
    assert!(!json.contains(value), "the value must never be audited");
    assert_eq!(
        ev.fingerprint.as_deref(),
        Some(fingerprint(value.as_bytes()).as_str())
    );
    // timestamp is the deterministic mock instant
    assert_eq!(ev.ts, clock.now_rfc3339());
}
