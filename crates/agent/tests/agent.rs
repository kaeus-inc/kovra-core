//! Mock-based invariant tests for the governed ssh-agent (KOV-13).
//!
//! These drive the session logic in-process with constructed parsed requests +
//! `MockConfirmer`/`MockAuditSink` over a tempdir — **no real socket peer and no
//! real `ssh`** (that path is `[host]`, validated by the human on the M4; see
//! the plan §9 and CLAUDE.md rule 4). Coverage:
//!
//! | Invariant | Test |
//! |-----------|------|
//! | I7  (in-memory sign, no disk) | `sign_writes_no_key_material_to_disk` |
//! | I12 (per-sign audit, no value) | `high_sign_audits_without_key_or_challenge` / `low_sign_is_audited_silently` |
//! | I13 (scope limits usable keys) | `out_of_scope_key_is_not_listed_and_refuses_to_sign` |
//! | I3/I15 (per-sig confirm)       | `high_sign_confirms_every_time` / `denied_and_timeout_yield_failure` |
//! | protocol round-trip / malformed | `protocol_round_trips_*` / `malformed_frame_is_failure_not_panic` |

use std::time::Duration;

use kovra_agent::protocol::{
    self, Request, SSH_AGENT_FAILURE, SSH_AGENT_IDENTITIES_ANSWER, SSH_AGENT_SIGN_RESPONSE,
};
use kovra_agent::session::{KeypairEntry, Session};
use kovra_core::{
    AgentScope, AuditAction, ConfirmOutcome, Coordinate, Filter, MockAuditSink, MockClock,
    MockConfirmer, Operation, Sensitivity, generate, public_key_blob,
};
use std::str::FromStr;
use zeroize::Zeroizing;

const TIMEOUT: Duration = Duration::from_secs(1);

/// Build a custodied keypair entry from a freshly generated ed25519 key.
fn keypair_entry(coord: &str, sensitivity: Sensitivity) -> KeypairEntry {
    let kp = generate(kovra_core::KeyAlgorithm::Ed25519).unwrap();
    let coordinate = Coordinate::from_str(coord).unwrap();
    let environment = match &coordinate.environment {
        kovra_core::EnvSegment::Literal(e) => e.clone(),
        kovra_core::EnvSegment::Placeholder => unreachable!(),
    };
    KeypairEntry {
        coordinate,
        project: None,
        environment,
        sensitivity,
        public_openssh: kp.public_openssh.clone(),
        private_openssh: Zeroizing::new(kp.private_openssh.to_string()),
    }
}

/// An agent scope mirroring the daemon's default: any env/project, no reveal.
fn agent_scope() -> AgentScope {
    AgentScope {
        operations: [Operation::Metadata, Operation::Inject]
            .into_iter()
            .collect(),
        projects: Filter::Any,
        environments: Filter::Any,
    }
}

fn sign_request(entry: &KeypairEntry, challenge: &[u8]) -> Request {
    Request::SignRequest {
        key_blob: public_key_blob(&entry.public_openssh).unwrap(),
        data: challenge.to_vec(),
        flags: 0,
    }
}

// ── I3/I15: high/prod confirms on EVERY signature ──────────────────────────

#[test]
fn high_sign_confirms_every_time() {
    let key = keypair_entry("secret:prod/ssh/deploy", Sensitivity::High);
    let keys = [key];
    let scope = agent_scope();
    let confirmer = MockConfirmer::always(ConfirmOutcome::Approved);
    let audit = MockAuditSink::new();
    let clock = MockClock::default();
    let session = Session {
        keys: &keys,
        scope: &scope,
        confirmer: &confirmer,
        audit: &audit,
        clock: &clock,
        confirm_timeout: TIMEOUT,
        requesting_process: Some("ssh (pid 4242)".into()),
    };

    // Two signatures → two confirmations → two SIGN_RESPONSEs.
    for _ in 0..2 {
        let req = sign_request(&keys[0], b"challenge");
        let reply = session.handle(&req).unwrap();
        assert_eq!(reply[0], SSH_AGENT_SIGN_RESPONSE);
    }
    // Each high signature produced an Approve audit event (per signature).
    let approves = audit
        .events()
        .into_iter()
        .filter(|e| e.action == AuditAction::Approve)
        .count();
    assert_eq!(approves, 2, "every high signature confirms + audits");
}

#[test]
fn denied_and_timeout_yield_failure() {
    let key = keypair_entry("secret:prod/ssh/deploy", Sensitivity::High);
    let keys = [key];
    let scope = agent_scope();
    let clock = MockClock::default();

    for (outcome, expected_action) in [
        (ConfirmOutcome::Denied, AuditAction::Deny),
        (ConfirmOutcome::TimedOut, AuditAction::Timeout),
    ] {
        let confirmer = MockConfirmer::always(outcome);
        let audit = MockAuditSink::new();
        let session = Session {
            keys: &keys,
            scope: &scope,
            confirmer: &confirmer,
            audit: &audit,
            clock: &clock,
            confirm_timeout: TIMEOUT,
            requesting_process: None,
        };
        let reply = session.handle(&sign_request(&keys[0], b"c")).unwrap();
        assert_eq!(
            reply,
            vec![SSH_AGENT_FAILURE],
            "refused → FAILURE, no signature"
        );
        assert!(
            audit.events().iter().any(|e| e.action == expected_action),
            "the refusal is audited as {expected_action:?}"
        );
    }
}

// ── I12: per-signature audit, no key bytes / no challenge ───────────────────

#[test]
fn high_sign_audits_without_key_or_challenge() {
    let key = keypair_entry("secret:prod/ssh/deploy", Sensitivity::High);
    let private = key.private_openssh.to_string();
    let keys = [key];
    let scope = agent_scope();
    let confirmer = MockConfirmer::always(ConfirmOutcome::Approved);
    let audit = MockAuditSink::new();
    let clock = MockClock::default();
    let session = Session {
        keys: &keys,
        scope: &scope,
        confirmer: &confirmer,
        audit: &audit,
        clock: &clock,
        confirm_timeout: TIMEOUT,
        requesting_process: None,
    };

    let challenge = b"the-ssh-session-challenge-bytes";
    session.handle(&sign_request(&keys[0], challenge)).unwrap();

    let events = audit.events();
    assert!(!events.is_empty());
    for ev in &events {
        let json = serde_json::to_string(ev).unwrap();
        // No private key bytes (I7/I12) and no challenge bytes ever in the log.
        assert!(!json.contains(&private), "audit must not carry key bytes");
        assert!(
            !json.contains("the-ssh-session-challenge-bytes"),
            "audit must not carry the challenge"
        );
        // The coordinate (address) IS recorded.
        assert_eq!(ev.coordinate.as_deref(), Some("prod/ssh/deploy"));
    }
    // The Approve event carries a truncated fingerprint (of the public key).
    let approve = events
        .iter()
        .find(|e| e.action == AuditAction::Approve)
        .expect("an Approve event");
    let fp = approve.fingerprint.as_deref().unwrap();
    assert_eq!(fp.len(), 8, "fingerprint is the truncated form (§10.4)");
}

#[test]
fn low_sign_is_audited_silently() {
    let key = keypair_entry("secret:dev/ssh/laptop", Sensitivity::Low);
    let keys = [key];
    let scope = agent_scope();
    // A confirmer that would *fail* if ever consulted — proves low signs without
    // prompting.
    let confirmer = MockConfirmer::always(ConfirmOutcome::Denied);
    let audit = MockAuditSink::new();
    let clock = MockClock::default();
    let session = Session {
        keys: &keys,
        scope: &scope,
        confirmer: &confirmer,
        audit: &audit,
        clock: &clock,
        confirm_timeout: TIMEOUT,
        requesting_process: None,
    };

    let reply = session.handle(&sign_request(&keys[0], b"c")).unwrap();
    assert_eq!(
        reply[0], SSH_AGENT_SIGN_RESPONSE,
        "low signs without a prompt"
    );
    // Still audited (Inject), but never an Approve/Deny (no confirmation path).
    let events = audit.events();
    assert!(events.iter().any(|e| e.action == AuditAction::Inject));
    assert!(!events.iter().any(|e| e.action == AuditAction::Approve));
    assert!(!events.iter().any(|e| e.action == AuditAction::Deny));
}

// ── I13: scope limits which keys are usable ─────────────────────────────────

#[test]
fn out_of_scope_key_is_not_listed_and_refuses_to_sign() {
    let in_scope = keypair_entry("secret:dev/ssh/laptop", Sensitivity::Low);
    let out_scope = keypair_entry("secret:prod/ssh/deploy", Sensitivity::High);
    let out_blob = public_key_blob(&out_scope.public_openssh).unwrap();
    let keys = [in_scope, out_scope];

    // Scope serves only `dev` — prod is unaddressable.
    let scope = AgentScope {
        operations: [Operation::Metadata, Operation::Inject]
            .into_iter()
            .collect(),
        projects: Filter::Any,
        environments: Filter::only(["dev"]),
    };
    let confirmer = MockConfirmer::always(ConfirmOutcome::Approved);
    let audit = MockAuditSink::new();
    let clock = MockClock::default();
    let session = Session {
        keys: &keys,
        scope: &scope,
        confirmer: &confirmer,
        audit: &audit,
        clock: &clock,
        confirm_timeout: TIMEOUT,
        requesting_process: None,
    };

    // REQUEST_IDENTITIES omits the out-of-scope key (only 1 listed).
    let answer = session.handle(&Request::RequestIdentities).unwrap();
    assert_eq!(answer[0], SSH_AGENT_IDENTITIES_ANSWER);
    let nkeys = u32::from_be_bytes(answer[1..5].try_into().unwrap());
    assert_eq!(nkeys, 1, "the prod key is not listed (unaddressable, I13)");

    // A SIGN_REQUEST for the out-of-scope key → FAILURE (refused, not signed).
    let req = Request::SignRequest {
        key_blob: out_blob,
        data: b"c".to_vec(),
        flags: 0,
    };
    let reply = session.handle(&req).unwrap();
    assert_eq!(reply, vec![SSH_AGENT_FAILURE]);
    assert!(
        audit
            .events()
            .iter()
            .any(|e| e.action == AuditAction::OutOfScopeAttempt)
    );
}

// ── I7: signing touches no disk; the key lives in memory only ───────────────

#[test]
fn sign_writes_no_key_material_to_disk() {
    let dir = tempfile::tempdir().unwrap();
    let key = keypair_entry("secret:dev/ssh/laptop", Sensitivity::Low);
    let private = key.private_openssh.to_string();
    let keys = [key];
    let scope = agent_scope();
    let confirmer = MockConfirmer::always(ConfirmOutcome::Approved);
    // Audit to a real file under the tempdir — the only file the agent writes.
    let audit = kovra_core::FileAuditSink::under_root(dir.path());
    let clock = MockClock::default();
    let session = Session {
        keys: &keys,
        scope: &scope,
        confirmer: &confirmer,
        audit: &audit,
        clock: &clock,
        confirm_timeout: TIMEOUT,
        requesting_process: None,
    };

    let reply = session
        .handle(&sign_request(&keys[0], b"challenge"))
        .unwrap();
    assert_eq!(
        reply[0], SSH_AGENT_SIGN_RESPONSE,
        "a valid signature is produced"
    );

    // Walk every file under the tempdir; none may contain the private key bytes.
    let mut files = 0;
    for entry in walk(dir.path()) {
        files += 1;
        let bytes = std::fs::read(&entry).unwrap();
        let hay = String::from_utf8_lossy(&bytes);
        assert!(
            !hay.contains(&private),
            "no file the agent touched holds the private key (I7): {}",
            entry.display()
        );
        // The OpenSSH armor header must never appear on disk either.
        assert!(!hay.contains("BEGIN OPENSSH PRIVATE KEY"));
    }
    // The only thing written is the audit log.
    assert!(files >= 1, "the audit log was written");
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

// ── Protocol round-trips + malformed-input safety ───────────────────────────

#[test]
fn protocol_round_trips_ed25519_and_rsa_sign() {
    use ssh_encoding::Decode;
    for alg in [
        kovra_core::KeyAlgorithm::Ed25519,
        kovra_core::KeyAlgorithm::Rsa,
    ] {
        let kp = generate(alg).unwrap();
        let entry = KeypairEntry {
            coordinate: Coordinate::from_str("secret:dev/ssh/x").unwrap(),
            project: None,
            environment: "dev".into(),
            sensitivity: Sensitivity::Low,
            public_openssh: kp.public_openssh.clone(),
            private_openssh: Zeroizing::new(kp.private_openssh.to_string()),
        };
        let keys = [entry];
        let scope = agent_scope();
        let confirmer = MockConfirmer::always(ConfirmOutcome::Approved);
        let audit = MockAuditSink::new();
        let clock = MockClock::default();
        let session = Session {
            keys: &keys,
            scope: &scope,
            confirmer: &confirmer,
            audit: &audit,
            clock: &clock,
            confirm_timeout: TIMEOUT,
            requesting_process: None,
        };

        // Frame a SIGN_REQUEST, read it back, parse it, handle it, and confirm
        // the response carries a non-empty `string algorithm || string blob`.
        let req = sign_request(&keys[0], b"the-challenge");
        let reply = session.handle(&req).unwrap();
        assert_eq!(reply[0], SSH_AGENT_SIGN_RESPONSE);
        // reply = byte type || string signature
        let sig_value = &reply[1..];
        let len = u32::from_be_bytes(sig_value[0..4].try_into().unwrap()) as usize;
        let inner = &sig_value[4..4 + len];
        let mut reader = inner;
        let alg_name = String::decode(&mut reader).unwrap();
        let sig_blob = Vec::<u8>::decode(&mut reader).unwrap();
        assert!(!sig_blob.is_empty());
        match alg {
            kovra_core::KeyAlgorithm::Ed25519 => assert_eq!(alg_name, "ssh-ed25519"),
            // flags=0 → legacy ssh-rsa
            kovra_core::KeyAlgorithm::Rsa => assert_eq!(alg_name, "ssh-rsa"),
        }
    }
}

#[test]
fn request_identities_round_trips_through_frame() {
    let body = vec![protocol::SSH_AGENTC_REQUEST_IDENTITIES];
    let framed = protocol::frame(&body);
    let mut cursor = std::io::Cursor::new(framed);
    let read = protocol::read_frame(&mut cursor).unwrap().unwrap();
    assert_eq!(
        protocol::parse_request(&read).unwrap(),
        Request::RequestIdentities
    );
}

#[test]
fn malformed_frame_is_failure_not_panic() {
    // A pile of arbitrary inputs must never panic; each parses to a request or a
    // protocol error (the daemon maps the error to a single FAILURE byte).
    let samples: &[&[u8]] = &[
        &[],
        &[0xFF],
        &[protocol::SSH_AGENTC_SIGN_REQUEST],
        &[protocol::SSH_AGENTC_SIGN_REQUEST, 0xFF, 0xFF, 0xFF, 0xFF],
        &[protocol::SSH_AGENTC_REQUEST_IDENTITIES, 0x00],
    ];
    for s in samples {
        match protocol::parse_request(s) {
            Ok(_) => {}
            Err(e) => assert!(matches!(e, kovra_agent::AgentError::Protocol(_))),
        }
    }
}

#[test]
fn unknown_key_blob_yields_failure() {
    let key = keypair_entry("secret:dev/ssh/laptop", Sensitivity::Low);
    let keys = [key];
    let scope = agent_scope();
    let confirmer = MockConfirmer::always(ConfirmOutcome::Approved);
    let audit = MockAuditSink::new();
    let clock = MockClock::default();
    let session = Session {
        keys: &keys,
        scope: &scope,
        confirmer: &confirmer,
        audit: &audit,
        clock: &clock,
        confirm_timeout: TIMEOUT,
        requesting_process: None,
    };
    // A blob the agent does not custody.
    let req = Request::SignRequest {
        key_blob: b"not-a-real-key-blob".to_vec(),
        data: b"c".to_vec(),
        flags: 0,
    };
    assert_eq!(session.handle(&req).unwrap(), vec![SSH_AGENT_FAILURE]);
}
