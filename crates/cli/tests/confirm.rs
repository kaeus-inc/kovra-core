//! Integration tests for `kovra confirm` (KOV-31): an attended human
//! confirmation for a generic action, gated by the broker, exposed as a
//! standalone CLI primitive — **exit 0 on approval, non-zero on deny/timeout**.
//!
//! Secret-independent: these tests neither `init` the vault nor set a passphrase
//! (no master key), proving the primitive needs no vault unlock. `KOVRA_CONFIRMER=file`
//! forces the file broker so the host needs no biometric hardware; the approval
//! is delivered cross-process by `kovra approve`, exactly as a human would.

use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_kovra");

/// Run `kovra <args>` against `vault` with the file broker forced. No passphrase
/// and no `init` — `kovra confirm` must work without a master key.
fn run(vault: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .env("KOVRA_VAULT_DIR", vault)
        .env("KOVRA_CONFIRMER", "file")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kovra")
        .wait_with_output()
        .expect("wait kovra")
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Spawn a blocking `kovra confirm` that will sit pending in the file broker.
fn spawn_confirm(vault: &Path, description: &str, ttl: &str) -> std::process::Child {
    Command::new(BIN)
        .env("KOVRA_VAULT_DIR", vault)
        .env("KOVRA_CONFIRMER", "file")
        .args(["confirm", description, "--ttl", ttl])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn confirm")
}

/// The pending request id: the first non-empty, non-indented line of
/// `approve --list` (mirrors the edit_downgrade / keypair tests' parser).
fn parse_pending_id(listing: &str) -> Option<String> {
    listing
        .lines()
        .find(|l| !l.is_empty() && !l.starts_with(' ') && l.contains('-') && !l.starts_with('('))
        .map(|l| l.trim().to_string())
}

/// Poll `approve --list` until a request appears; panic past the deadline.
fn wait_pending(vault: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let listing =
            String::from_utf8_lossy(&run(vault, &["approve", "--list"]).stdout).into_owned();
        if let Some(id) = parse_pending_id(&listing) {
            return id;
        }
        assert!(Instant::now() < deadline, "no pending request appeared");
        std::thread::sleep(Duration::from_millis(100));
    }
}

// Approved → exit 0. The action is delivered cross-process by `kovra approve`.
#[test]
fn confirm_approved_exits_zero() {
    let dir = tempfile::tempdir().unwrap();
    let child = spawn_confirm(dir.path(), "deploy api to prod", "10");
    let id = wait_pending(dir.path());
    // The pending listing renders the action (not a secret).
    let listing =
        String::from_utf8_lossy(&run(dir.path(), &["approve", "--list"]).stdout).into_owned();
    assert!(listing.contains("action  : deploy api to prod"));

    assert!(run(dir.path(), &["approve", &id]).status.success());
    let out = child.wait_with_output().expect("wait confirm");
    assert!(out.status.success(), "approved confirm must exit 0");
}

// Denied → non-zero exit.
#[test]
fn confirm_denied_exits_nonzero() {
    let dir = tempfile::tempdir().unwrap();
    let child = spawn_confirm(dir.path(), "wipe the staging database", "10");
    let id = wait_pending(dir.path());
    assert!(
        run(dir.path(), &["approve", "--deny", &id])
            .status
            .success()
    );
    let out = child.wait_with_output().expect("wait confirm");
    assert!(!out.status.success(), "denied confirm must exit non-zero");
    assert!(stderr(&out).contains("denied"));
}

// Timeout → non-zero exit, fails safe to denial (§8). No approver shows up.
#[test]
fn confirm_timeout_exits_nonzero() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(dir.path(), &["confirm", "noop action", "--ttl", "1"]);
    assert!(
        !out.status.success(),
        "timed-out confirm must exit non-zero"
    );
    assert!(stderr(&out).contains("timed out"));
}
