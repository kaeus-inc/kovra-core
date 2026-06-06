//! Integration tests for the sensitivity-downgrade confirmation gate (I5 + I16):
//! lowering a `high`/`inject-only` secret requires an attended approval (Touch
//! ID on macOS; here the file broker, driven cross-process by `kovra approve`).
//! Lowering from a non-critical level, or raising, is never gated.
//!
//! `KOVRA_CONFIRMER=file` forces the file broker so the test host needs no
//! biometric hardware; the approval is delivered from a second process exactly
//! as a human would (mirrors the keypair high-sign broker test).

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_kovra");
const PASS: &str = "integration-pass";

fn run(vault: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.env("KOVRA_VAULT_DIR", vault)
        .env("KOVRA_PASSPHRASE", PASS)
        .env("KOVRA_CONFIRMER", "file")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn kovra");
    if let Some(s) = stdin {
        child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
    }
    child.wait_with_output().expect("wait kovra")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn vault() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    assert!(run(dir.path(), &["init"], None).status.success());
    dir
}

fn add(vault: &Path, coord: &str, value: &str, sensitivity: &str) {
    let o = run(
        vault,
        &["add", coord, "--stdin", "--sensitivity", sensitivity],
        Some(value),
    );
    assert!(o.status.success(), "add failed: {}", stderr(&o));
}

/// The pending request id: the first non-empty, non-indented line of
/// `approve --list` (mirrors the keypair test's parser).
fn parse_pending_id(listing: &str) -> Option<String> {
    listing
        .lines()
        .find(|l| !l.is_empty() && !l.starts_with(' ') && l.contains('-') && !l.starts_with('('))
        .map(|l| l.trim().to_string())
}

/// Spawn a blocking `edit --sensitivity <to>` and return the child (the request
/// will sit pending in the file broker until approved/denied).
fn spawn_edit(vault: &Path, coord: &str, to: &str) -> std::process::Child {
    Command::new(BIN)
        .env("KOVRA_VAULT_DIR", vault)
        .env("KOVRA_PASSPHRASE", PASS)
        .env("KOVRA_CONFIRMER", "file")
        .args(["edit", coord, "--sensitivity", to])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn edit")
}

/// Poll `approve --list` until a request appears; panic past the deadline.
fn wait_pending(vault: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        assert!(
            Instant::now() < deadline,
            "downgrade request never appeared"
        );
        let list = run(vault, &["approve", "--list"], None);
        if let Some(id) = parse_pending_id(&stdout(&list)) {
            return id;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

// Lowering a `high` secret blocks until approved, then applies (I5 + I16).
#[test]
fn downgrade_from_high_requires_approval_then_applies() {
    let v = vault();
    add(v.path(), "secret:dev/db/password", "v", "high");

    let child = spawn_edit(v.path(), "secret:dev/db/password", "medium");
    let id = wait_pending(v.path());
    let approve = run(v.path(), &["approve", &id], None);
    assert!(approve.status.success(), "approve: {}", stderr(&approve));

    let out = child.wait_with_output().expect("wait edit");
    assert!(out.status.success(), "edit after approve: {}", stderr(&out));

    // The downgrade took effect.
    let list = run(v.path(), &["list", "--env", "dev"], None);
    let table = stdout(&list);
    assert!(table.contains("dev/db/password"));
    assert!(table.contains("medium"), "now medium: {table}");
    assert!(!table.contains("high"), "no longer high: {table}");
}

// A denied approval leaves the secret untouched (still `high`).
#[test]
fn denied_downgrade_keeps_high() {
    let v = vault();
    add(v.path(), "secret:dev/db/password", "v", "high");

    let child = spawn_edit(v.path(), "secret:dev/db/password", "low");
    let id = wait_pending(v.path());
    let deny = run(v.path(), &["approve", "--deny", &id], None);
    assert!(deny.status.success(), "deny: {}", stderr(&deny));

    let out = child.wait_with_output().expect("wait edit");
    assert!(!out.status.success(), "denied edit must fail");
    assert!(stderr(&out).contains("denied"), "error: {}", stderr(&out));

    // Unchanged — still high.
    let list = run(v.path(), &["list", "--env", "dev"], None);
    assert!(
        stdout(&list).contains("high"),
        "still high: {}",
        stdout(&list)
    );
}

// Lowering a NON-critical secret (medium → low) is not gated: it applies
// immediately with no approver running.
#[test]
fn downgrade_from_medium_is_not_gated() {
    let v = vault();
    add(v.path(), "secret:dev/db/password", "v", "medium");
    let o = run(
        v.path(),
        &["edit", "secret:dev/db/password", "--sensitivity", "low"],
        None,
    );
    assert!(
        o.status.success(),
        "medium→low must not be gated: {}",
        stderr(&o)
    );
    let list = run(v.path(), &["list", "--env", "dev"], None);
    assert!(stdout(&list).contains("low"));
}

// Raising sensitivity (medium → high) is never gated.
#[test]
fn raising_sensitivity_is_not_gated() {
    let v = vault();
    add(v.path(), "secret:dev/db/password", "v", "medium");
    let o = run(
        v.path(),
        &["edit", "secret:dev/db/password", "--sensitivity", "high"],
        None,
    );
    assert!(
        o.status.success(),
        "raising must not be gated: {}",
        stderr(&o)
    );
    let list = run(v.path(), &["list", "--env", "dev"], None);
    assert!(stdout(&list).contains("high"));
}
