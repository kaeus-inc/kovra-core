//! Integration tests for KOV-18 (`kovra doctor` / `lint`) — drive the real
//! binary against a throwaway vault. Covers: a clean config exits 0, a broken
//! config exits non-zero with coordinate-addressed findings, the `lint` alias,
//! and the no-value invariant (no secret value appears in output).

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_kovra");
const PASS: &str = "doctor-test-pass";

fn run(vault: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.env("KOVRA_VAULT_DIR", vault)
        .env("KOVRA_PASSPHRASE", PASS)
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

fn vault() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    assert!(run(dir.path(), &["init"], None).status.success());
    dir
}

#[test]
fn doctor_clean_config_exits_zero() {
    let v = vault();
    run(
        v.path(),
        &["add", "secret:dev/db/password", "--stdin"],
        Some("s3cr3t-value"),
    );
    let refs = v.path().join("clean.env.refs");
    std::fs::write(&refs, "DB=secret:${ENV}/db/password\n").unwrap();

    let out = run(
        v.path(),
        &["doctor", "--env", "dev", "--refs", refs.to_str().unwrap()],
        None,
    );
    assert!(
        out.status.success(),
        "clean config should exit 0: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    // The secret value must never appear in doctor output.
    let combined =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(
        !combined.contains("s3cr3t-value"),
        "doctor must not print a value: {combined}"
    );
}

#[test]
fn doctor_broken_config_exits_nonzero_with_findings() {
    let v = vault();
    // prod secret with a fallback — a hard finding (I4c), plus an unresolved one.
    run(
        v.path(),
        &[
            "add",
            "secret:prod/db/password",
            "--stdin",
            "--sensitivity",
            "high",
        ],
        Some("prod-value"),
    );
    let refs = v.path().join("broken.env.refs");
    std::fs::write(
        &refs,
        "DB=secret:prod/db/password | localhost\nGONE=secret:prod/api/missing\n",
    )
    .unwrap();

    let out = run(
        v.path(),
        &["doctor", "--env", "prod", "--refs", refs.to_str().unwrap()],
        None,
    );
    assert!(!out.status.success(), "broken config should exit non-zero");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ERROR"),
        "expected ERROR findings: {stdout}"
    );
    assert!(
        stdout.contains("prod/db/password") && stdout.contains("prod/api/missing"),
        "findings must be coordinate-addressed: {stdout}"
    );
    assert!(
        !stdout.contains("prod-value"),
        "doctor must not print a value: {stdout}"
    );
}

#[test]
fn lint_is_an_alias_for_doctor() {
    let v = vault();
    run(
        v.path(),
        &["add", "secret:dev/db/password", "--stdin"],
        Some("v"),
    );
    let refs = v.path().join("a.env.refs");
    std::fs::write(&refs, "DB=secret:${ENV}/db/password\n").unwrap();
    let out = run(
        v.path(),
        &["lint", "--env", "dev", "--refs", refs.to_str().unwrap()],
        None,
    );
    assert!(
        out.status.success(),
        "`lint` alias should work: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
