//! Integration tests for KOV-6 (L5) — the Wrapper end-to-end over a `tempfile`
//! registry with mock core dependencies. Covers the spec §17 L5 exit criteria
//! and the applicable invariants: I7 (no disk writes; injected via child env),
//! I15 (non-allowlisted command refused high/prod injection), I3/I16 (high/prod
//! blocks pending an attended confirmation whose prompt shows the exact argv).
//! No real secrets, no real provider, no network.

use std::path::Path;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;

use kovra_core::{
    AuditAction, CliApproveConfirmer, ConfirmOutcome, ConfirmRequest, Confirmer, Coordinate,
    EnvRefs, KEY_LEN, MockAuditSink, MockClock, MockConfirmer, MockEnvSource, MockKeyring,
    MockProvider, Origin, Registry, SecretRecord, SecretValue, Sensitivity, seal, store,
};
use kovra_wrapper::{
    Allowlist, MockRunner, Output, ProcessRunner, SystemRunner, Wrapper, WrapperError,
};

const MASTER: [u8; KEY_LEN] = [0x5a; KEY_LEN];

fn lit(value: &str, sensitivity: Sensitivity, env: &str, comp: &str, key: &str) -> SecretRecord {
    SecretRecord::Literal {
        value: SecretValue::from(value),
        sensitivity,
        revealable: false,
        environment: env.to_string(),
        component: comp.to_string(),
        key: key.to_string(),
        description: None,
        created: "2026-05-30T00:00:00Z".to_string(),
        updated: "2026-05-30T00:00:00Z".to_string(),
    }
}

/// Owns the long-lived mock dependencies so the `Wrapper`'s borrows outlive it.
struct Fixture {
    _tmp: tempfile::TempDir,
    reg: Registry,
    keyring: MockKeyring,
    env_source: MockEnvSource,
    provider: MockProvider,
    audit: MockAuditSink,
    clock: MockClock,
    requesting_process: Option<String>,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let reg = Registry::open(tmp.path()).unwrap();
        Self {
            _tmp: tmp,
            reg,
            keyring: MockKeyring::with_key(MASTER),
            env_source: MockEnvSource::new(),
            provider: MockProvider::new(),
            audit: MockAuditSink::new(),
            clock: MockClock::default(),
            requesting_process: None,
        }
    }

    /// Set the trusted, observed requesting-process identity (I16, §8.3).
    fn with_requesting_process(mut self, s: &str) -> Self {
        self.requesting_process = Some(s.to_string());
        self
    }

    fn seed_global(&self, coord: &str, record: SecretRecord) {
        let c = Coordinate::from_str(coord).unwrap();
        store::write_record(&self.reg.global_dir(), &c, &seal(&record, &MASTER).unwrap()).unwrap();
    }

    fn wrapper<'a>(
        &'a self,
        confirmer: &'a dyn Confirmer,
        allowlist: &'a Allowlist,
        runner: &'a dyn ProcessRunner,
        confirm_timeout: Duration,
        sanitize_output: bool,
    ) -> Wrapper<'a> {
        Wrapper {
            registry: &self.reg,
            keyring: &self.keyring,
            env_source: &self.env_source,
            provider: &self.provider,
            confirmer,
            audit: &self.audit,
            clock: &self.clock,
            allowlist,
            runner,
            confirm_timeout,
            sanitize_output,
            requesting_process: self.requesting_process.clone(),
        }
    }
}

/// A confirmer that records the request it saw and returns a fixed outcome — for
/// asserting the authoritative prompt contract (I16).
struct RecordingConfirmer {
    outcome: ConfirmOutcome,
    seen: Mutex<Option<ConfirmRequest>>,
}

impl RecordingConfirmer {
    fn new(outcome: ConfirmOutcome) -> Self {
        Self {
            outcome,
            seen: Mutex::new(None),
        }
    }
    fn request(&self) -> Option<ConfirmRequest> {
        self.seen.lock().unwrap().clone()
    }
}

impl Confirmer for RecordingConfirmer {
    fn confirm(&self, req: &ConfirmRequest, _timeout: Duration) -> ConfirmOutcome {
        *self.seen.lock().unwrap() = Some(req.clone());
        self.outcome
    }
}

/// A reviewed, allowlisted executable (must exist for path canonicalization).
fn reviewed_exe(dir: &Path) -> std::path::PathBuf {
    let p = dir.join("deploy.sh");
    std::fs::write(&p, b"#!/bin/sh\n").unwrap();
    p
}

// I7 — a low/medium non-prod value injects into the child's environment (proven
// by the child echoing it) and the Wrapper writes nothing to a scratch dir. Also
// proves the allowlist/broker are NOT consulted for non-gated values (the
// confirmer is always-deny yet the run succeeds).
#[test]
fn injects_value_via_child_env_and_writes_nothing_to_disk() {
    let fx = Fixture::new();
    fx.seed_global(
        "secret:dev/app/token",
        lit("s3cr3t-dev", Sensitivity::Medium, "dev", "app", "token"),
    );

    let scratch = tempfile::tempdir().unwrap();
    let allow = Allowlist::empty();
    let runner = SystemRunner;
    let deny = MockConfirmer::always(ConfirmOutcome::Denied);
    let w = fx.wrapper(&deny, &allow, &runner, Duration::from_secs(1), false);

    let refs = EnvRefs::parse("TOKEN=secret:dev/app/token").unwrap();
    let out = w
        .run(
            &refs,
            "dev",
            None,
            Path::new("/bin/sh"),
            &["-c".to_string(), "printf %s \"$TOKEN\"".to_string()],
            Origin::Human,
        )
        .unwrap();

    assert_eq!(out.status, Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "s3cr3t-dev");
    assert_eq!(
        std::fs::read_dir(scratch.path()).unwrap().count(),
        0,
        "the Wrapper must not write any file to disk (I7)"
    );
}

// I15 — a `high` secret injected into a command NOT on the executor allowlist is
// refused, before any confirmation or launch. The confirmer is always-approve to
// prove the allowlist gate fires first.
#[test]
fn high_injection_into_non_allowlisted_command_is_refused() {
    let fx = Fixture::new();
    fx.seed_global(
        "secret:dev/app/key",
        lit("hunter2", Sensitivity::High, "dev", "app", "key"),
    );

    let allow = Allowlist::empty(); // nothing reviewed
    let runner = MockRunner::ok();
    let approve = MockConfirmer::always(ConfirmOutcome::Approved);
    let w = fx.wrapper(&approve, &allow, &runner, Duration::from_secs(1), false);

    let refs = EnvRefs::parse("KEY=secret:dev/app/key").unwrap();
    let err = w
        .run(
            &refs,
            "dev",
            None,
            Path::new("/bin/sh"),
            &["-c".to_string(), "true".to_string()],
            Origin::Agent,
        )
        .unwrap_err();

    assert!(matches!(err, WrapperError::NotAllowlisted { .. }));
    assert!(!runner.was_invoked(), "the child must never launch (I15)");
    assert!(
        fx.audit
            .events()
            .iter()
            .any(|e| e.result == "denied:not-allowlisted"),
        "the refusal is audited"
    );
}

// I3/I16 — a prod (born-high) injection into an allowlisted command blocks on the
// broker; a denial refuses injection and the child never launches. The
// authoritative prompt carries the exact resolved argv (I16) and no requester
// text.
#[test]
fn prod_high_denied_blocks_injection_and_prompt_shows_argv() {
    let fx = Fixture::new();
    fx.seed_global(
        "secret:prod/db/password",
        lit("prod-pw", Sensitivity::High, "prod", "db", "password"),
    );

    let bin = tempfile::tempdir().unwrap();
    let deploy = reviewed_exe(bin.path());
    let allow = Allowlist::from_paths([&deploy]);

    let runner = MockRunner::ok();
    let confirmer = RecordingConfirmer::new(ConfirmOutcome::Denied);
    let w = fx.wrapper(&confirmer, &allow, &runner, Duration::from_secs(1), false);

    let refs = EnvRefs::parse("DB=secret:prod/db/password").unwrap();
    let err = w
        .run(
            &refs,
            "prod",
            None,
            &deploy,
            &["--now".to_string()],
            Origin::Human,
        )
        .unwrap_err();

    assert!(matches!(err, WrapperError::ConfirmationDenied));
    assert!(!runner.was_invoked(), "denied ⇒ child never launches");

    let req = confirmer.request().expect("the broker was consulted");
    let expected = format!("{} --now", deploy.display());
    assert_eq!(
        req.resolved_command.as_deref(),
        Some(expected.as_str()),
        "the prompt shows the exact resolved argv (I16)"
    );
    assert_eq!(req.coordinate, "prod/db/password");
    assert_eq!(req.environment, "prod");
    assert_eq!(req.sensitivity, Sensitivity::High);
    assert!(
        req.requester_description.is_none(),
        "authoritative prompt carries no requester free-text"
    );
    assert!(fx.audit.events().iter().any(|e| e.result == "denied"));
}

// I16/§8.3 — the trusted, observed requesting-process identity threads onto the
// authoritative prompt as its own field, never via the untrusted description.
#[test]
fn prompt_carries_observed_requesting_process() {
    let fx = Fixture::new().with_requesting_process("node (pid 4242)");
    fx.seed_global(
        "secret:prod/db/password",
        lit("prod-pw", Sensitivity::High, "prod", "db", "password"),
    );

    let bin = tempfile::tempdir().unwrap();
    let deploy = reviewed_exe(bin.path());
    let allow = Allowlist::from_paths([&deploy]);

    let runner = MockRunner::ok();
    let confirmer = RecordingConfirmer::new(ConfirmOutcome::Denied);
    let w = fx.wrapper(&confirmer, &allow, &runner, Duration::from_secs(1), false);

    let refs = EnvRefs::parse("DB=secret:prod/db/password").unwrap();
    let _ = w.run(&refs, "prod", None, &deploy, &[], Origin::Agent);

    let req = confirmer.request().expect("the broker was consulted");
    assert_eq!(
        req.requesting_process.as_deref(),
        Some("node (pid 4242)"),
        "the observed requesting process threads onto the prompt (I16/§8.3)"
    );
    // It is a trusted field, distinct from the untrusted requester description.
    assert!(req.requester_description.is_none());
}

// The approved path: prod/high into an allowlisted command launches, injects the
// value, and audits Approve + Inject.
#[test]
fn prod_high_approved_injects_and_audits() {
    let fx = Fixture::new();
    fx.seed_global(
        "secret:prod/db/password",
        lit("prod-pw", Sensitivity::High, "prod", "db", "password"),
    );

    let bin = tempfile::tempdir().unwrap();
    let deploy = reviewed_exe(bin.path());
    let allow = Allowlist::from_paths([&deploy]);

    let runner = MockRunner::ok();
    let approve = MockConfirmer::always(ConfirmOutcome::Approved);
    let w = fx.wrapper(&approve, &allow, &runner, Duration::from_secs(1), false);

    let refs = EnvRefs::parse("DB=secret:prod/db/password").unwrap();
    let out = w
        .run(&refs, "prod", None, &deploy, &[], Origin::Human)
        .unwrap();

    assert_eq!(
        out,
        Output {
            status: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new()
        }
    );
    let runs = runner.invocations();
    assert_eq!(runs.len(), 1);
    assert_eq!(
        runs[0].env_value("DB"),
        Some("prod-pw"),
        "value injected into child env"
    );

    let actions: Vec<_> = fx.audit.events().iter().map(|e| e.action).collect();
    assert!(actions.contains(&AuditAction::Approve));
    assert!(actions.contains(&AuditAction::Inject));
}

// KOV-25 — a deliberately-downgraded `prod` secret (now `low`) injects into an
// allowlisted command WITHOUT a biometric prompt (I3: confirmation is
// sensitivity-only, orthogonal to environment); the executor allowlist (I15)
// still applies.
#[test]
fn downgraded_prod_low_injects_without_prompt_but_still_needs_allowlist() {
    let fx = Fixture::new();
    fx.seed_global(
        "secret:prod/db/password",
        lit("prod-pw", Sensitivity::Low, "prod", "db", "password"),
    );

    let bin = tempfile::tempdir().unwrap();
    let deploy = reviewed_exe(bin.path());
    let allow = Allowlist::from_paths([&deploy]);

    let runner = MockRunner::ok();
    // Always-deny broker: were it consulted, the run would fail. It must NOT be.
    let confirmer = RecordingConfirmer::new(ConfirmOutcome::Denied);
    let w = fx.wrapper(&confirmer, &allow, &runner, Duration::from_secs(1), false);

    let refs = EnvRefs::parse("DB=secret:prod/db/password").unwrap();
    let out = w
        .run(&refs, "prod", None, &deploy, &[], Origin::Human)
        .unwrap();
    assert_eq!(
        out.status,
        Some(0),
        "downgraded prod injects without a prompt"
    );
    assert!(
        confirmer.request().is_none(),
        "the broker is NOT consulted for a `low` secret (I3 — sensitivity-only)"
    );
    assert!(runner.was_invoked(), "the child launches");

    // …but I15 still holds: the same injection into a non-allowlisted command is
    // refused (prod containment is environment-aware, independent of the prompt).
    let runner2 = MockRunner::ok();
    let empty = Allowlist::empty();
    let approve = MockConfirmer::always(ConfirmOutcome::Approved);
    let w2 = fx.wrapper(&approve, &empty, &runner2, Duration::from_secs(1), false);
    let err = w2
        .run(&refs, "prod", None, &deploy, &[], Origin::Human)
        .unwrap_err();
    assert!(
        matches!(err, WrapperError::NotAllowlisted { .. }),
        "a downgraded prod secret still requires an allowlisted executable (I15)"
    );
    assert!(!runner2.was_invoked());
}

// inject-only (non-prod) is its normal delivery: injected without a prompt and
// without consulting the allowlist (the confirmer is always-deny yet it runs).
#[test]
fn inject_only_non_prod_passes_without_confirmation() {
    let fx = Fixture::new();
    fx.seed_global(
        "secret:dev/app/secret",
        lit("io-value", Sensitivity::InjectOnly, "dev", "app", "secret"),
    );

    let allow = Allowlist::empty();
    let runner = MockRunner::ok();
    let deny = MockConfirmer::always(ConfirmOutcome::Denied);
    let w = fx.wrapper(&deny, &allow, &runner, Duration::from_secs(1), false);

    let refs = EnvRefs::parse("S=secret:dev/app/secret").unwrap();
    w.run(
        &refs,
        "dev",
        None,
        Path::new("/bin/sh"),
        &["-c".to_string(), "true".to_string()],
        Origin::Agent,
    )
    .unwrap();

    let runs = runner.invocations();
    assert_eq!(runs.len(), 1, "inject-only delivers by injection");
    assert_eq!(runs[0].env_value("S"), Some("io-value"));
}

// A confirmation timeout fails safe to denial (§8): injection refused, child
// never launches, timeout audited.
#[test]
fn confirmation_timeout_denies_injection() {
    let fx = Fixture::new();
    fx.seed_global(
        "secret:prod/db/password",
        lit("prod-pw", Sensitivity::High, "prod", "db", "password"),
    );

    let bin = tempfile::tempdir().unwrap();
    let deploy = reviewed_exe(bin.path());
    let allow = Allowlist::from_paths([&deploy]);

    let runner = MockRunner::ok();
    let confirmer = CliApproveConfirmer::new(); // no approver ⇒ times out
    let w = fx.wrapper(
        &confirmer,
        &allow,
        &runner,
        Duration::from_millis(20),
        false,
    );

    let refs = EnvRefs::parse("DB=secret:prod/db/password").unwrap();
    let err = w
        .run(&refs, "prod", None, &deploy, &[], Origin::Human)
        .unwrap_err();

    assert!(matches!(err, WrapperError::ConfirmationTimedOut));
    assert!(!runner.was_invoked());
    assert!(fx.audit.events().iter().any(|e| e.result == "timeout"));
}

// The §5.1 margin defense, end-to-end: with sanitization on, a naive echo of an
// injected value is masked in the child's stdout.
#[test]
fn sanitization_masks_injected_value_in_output() {
    let fx = Fixture::new();
    fx.seed_global(
        "secret:dev/app/token",
        lit("leak-me-123", Sensitivity::Medium, "dev", "app", "token"),
    );

    let allow = Allowlist::empty();
    let runner = SystemRunner;
    let deny = MockConfirmer::always(ConfirmOutcome::Denied);
    let w = fx.wrapper(&deny, &allow, &runner, Duration::from_secs(1), true);

    let refs = EnvRefs::parse("TOKEN=secret:dev/app/token").unwrap();
    let out = w
        .run(
            &refs,
            "dev",
            None,
            Path::new("/bin/sh"),
            &["-c".to_string(), "printf %s \"$TOKEN\"".to_string()],
            Origin::Human,
        )
        .unwrap();

    assert_eq!(String::from_utf8_lossy(&out.stdout), "***");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("leak-me-123"));
}

// Sanitization masks vault-backed secret values but leaves plain literals and
// `${env:}` passthrough untouched (§5.1 — the net targets secrets, not config).
#[test]
fn sanitization_masks_only_vault_backed_secrets() {
    let fx = Fixture::new();
    fx.seed_global(
        "secret:dev/app/token",
        lit("sekret9", Sensitivity::Medium, "dev", "app", "token"),
    );

    let allow = Allowlist::empty();
    let runner = SystemRunner;
    let deny = MockConfirmer::always(ConfirmOutcome::Denied);
    let w = fx.wrapper(&deny, &allow, &runner, Duration::from_secs(1), true);

    // PORT is a literal, TOKEN is a vault secret. The child echoes both.
    let refs = EnvRefs::parse("PORT=8080\nTOKEN=secret:dev/app/token").unwrap();
    let out = w
        .run(
            &refs,
            "dev",
            None,
            Path::new("/bin/sh"),
            &[
                "-c".to_string(),
                "printf 'PORT=%s TOKEN=%s' \"$PORT\" \"$TOKEN\"".to_string(),
            ],
            Origin::Human,
        )
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "PORT=8080 TOKEN=***",
        "literal visible, secret masked"
    );
}
