//! Integration tests for KOV-7 (CLI) — drive the real `kovra` binary against a
//! throwaway vault (passphrase/Argon2 mode, so the OS keychain is never touched).
//! Covers the ACs: I6 (value never in argv), `show` reveal + high needs approval,
//! `generate` never prints, cross-process `approve`, and `run` injection.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_kovra");
const PASS: &str = "integration-pass";

/// Run `kovra <args>` against `vault`, optionally writing `stdin`, to completion.
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

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn vault() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let o = run(dir.path(), &["init"], None);
    assert!(
        o.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    dir
}

#[test]
fn add_list_show_roundtrip() {
    let v = vault();
    let add = run(
        v.path(),
        &["add", "secret:dev/db/password", "--stdin"],
        Some("s3cr3t-dev"),
    );
    assert!(
        add.status.success(),
        "add: {}",
        String::from_utf8_lossy(&add.stderr)
    );

    let list = run(v.path(), &["list"], None);
    assert!(stdout(&list).contains("dev/db/password"));
    assert!(stdout(&list).contains("medium"));

    let show = run(v.path(), &["show", "secret:dev/db/password"], None);
    assert!(show.status.success());
    assert!(
        stdout(&show).contains("s3cr3t-dev"),
        "show should reveal the value"
    );
}

// I6 — there is no `--value` flag; a value can only enter via stdin/prompt.
#[test]
fn no_value_flag_exists() {
    let v = vault();
    let out = run(
        v.path(),
        &["add", "secret:dev/db/password", "--value", "leak"],
        None,
    );
    assert!(!out.status.success(), "a --value flag must not exist (I6)");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("unexpected") || err.contains("--value") || err.contains("error"),
        "expected an arg error, got: {err}"
    );
}

// generate stores a value but never prints it (AC3).
#[test]
fn generate_does_not_print_the_value() {
    let v = vault();
    let g = run(
        v.path(),
        &["generate", "secret:dev/app/key", "--length", "20"],
        None,
    );
    assert!(
        g.status.success(),
        "generate: {}",
        String::from_utf8_lossy(&g.stderr)
    );
    let out = stdout(&g);
    assert!(out.contains("stored"));
    // The value is 20 alphanumerics; the success line must not be the value.
    let show = run(v.path(), &["show", "secret:dev/app/key"], None);
    let value = stdout(&show);
    assert!(
        !out.contains(value.trim()),
        "generate stdout must not contain the value"
    );
    assert_eq!(
        value.trim().len(),
        20,
        "stored value is the generated length"
    );
}

// prod is born high (I5), even without --sensitivity.
#[test]
fn prod_is_born_high() {
    let v = vault();
    run(
        v.path(),
        &["add", "secret:prod/db/password", "--stdin"],
        Some("pw"),
    );
    let list = run(v.path(), &["list", "--env", "prod"], None);
    let out = stdout(&list);
    assert!(out.contains("prod/db/password"));
    assert!(out.contains("high"), "prod secret must be born high: {out}");
}

// AC4 — `kovra show` of a high secret blocks until `kovra approve <id>` runs in
// ANOTHER process, then reveals.
#[test]
fn show_high_blocks_until_cross_process_approve() {
    let v = vault();
    run(
        v.path(),
        &[
            "add",
            "secret:dev/api/key",
            "--stdin",
            "--sensitivity",
            "high",
        ],
        Some("hi-secret"),
    );

    // Spawn the blocking `show` in its own process. Pin the file broker
    // (`KOVRA_CONFIRMER=file`) so the test drives the deterministic cross-process
    // approve flow rather than popping a Touch ID dialog on the macOS dev host
    // (the biometric path is `[host]`-validated, never exercised by CI).
    let show = Command::new(BIN)
        .env("KOVRA_VAULT_DIR", v.path())
        .env("KOVRA_PASSPHRASE", PASS)
        .env("KOVRA_CONFIRMER", "file")
        .args(["show", "secret:dev/api/key"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn show");

    // Poll `approve --list` until the pending request appears, then approve it.
    let deadline = Instant::now() + Duration::from_secs(30);
    let id = loop {
        assert!(Instant::now() < deadline, "request never appeared");
        let list = run(v.path(), &["approve", "--list"], None);
        if let Some(id) = parse_pending_id(&stdout(&list)) {
            break id;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let approve = run(v.path(), &["approve", &id], None);
    assert!(
        approve.status.success(),
        "approve: {}",
        String::from_utf8_lossy(&approve.stderr)
    );

    let out = show.wait_with_output().expect("wait show");
    assert!(
        out.status.success(),
        "show after approve: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout(&out).contains("hi-secret"),
        "value revealed after approval"
    );
}

/// The id is the first non-empty, non-indented line of `approve --list` output.
fn parse_pending_id(listing: &str) -> Option<String> {
    listing
        .lines()
        .find(|l| !l.is_empty() && !l.starts_with(' ') && l.contains('-') && !l.starts_with('('))
        .map(|l| l.trim().to_string())
}

// `run` injects a vault secret into the child and masks it in the returned output.
#[test]
fn run_injects_and_masks() {
    let v = vault();
    run(
        v.path(),
        &["add", "secret:dev/app/token", "--stdin"],
        Some("tok-xyz"),
    );

    let proj = tempfile::tempdir().unwrap();
    std::fs::write(
        proj.path().join(".env.refs"),
        "TOKEN=secret:dev/app/token\nPORT=8080\n",
    )
    .unwrap();
    let refs = proj.path().join(".env.refs");

    let out = run(
        v.path(),
        &[
            "run",
            "--env",
            "dev",
            "--refs",
            refs.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            "printf 'PORT=%s TOKEN=%s' \"$PORT\" \"$TOKEN\"",
        ],
        None,
    );
    assert!(
        out.status.success(),
        "run: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = stdout(&out);
    assert_eq!(
        s, "PORT=8080 TOKEN=***",
        "literal visible, vault secret masked: {s}"
    );
}
