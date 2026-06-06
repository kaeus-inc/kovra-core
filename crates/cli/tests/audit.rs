//! Integration tests for KOV-20 (`kovra audit`) — drive the real binary, perform
//! audited operations, then query the trail. Covers: events render with the
//! sensitivity column (from the redb index), filtering by env/action, and the
//! no-value / no-full-fingerprint invariant on the render path (I11/I12).

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_kovra");
const PASS: &str = "audit-test-pass";

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
    assert!(run(dir.path(), &["init"], None).status.success());
    dir
}

#[test]
fn audit_renders_filters_and_never_leaks_a_value() {
    let v = vault();
    // Two audited create operations across environments.
    assert!(
        run(
            v.path(),
            &["add", "secret:dev/db/password", "--stdin"],
            Some("dev-secret-zzz"),
        )
        .status
        .success()
    );
    assert!(
        run(
            v.path(),
            &[
                "add",
                "secret:prod/api/key",
                "--stdin",
                "--sensitivity",
                "high",
            ],
            Some("prod-secret-yyy"),
        )
        .status
        .success()
    );

    // Full trail.
    let all = run(v.path(), &["audit"], None);
    assert!(
        all.status.success(),
        "audit: {}",
        String::from_utf8_lossy(&all.stderr)
    );
    let out = stdout(&all);
    assert!(out.contains("dev/db/password") && out.contains("prod/api/key"));
    assert!(out.contains("create"), "create events rendered: {out}");
    // Sensitivity column from the redb index.
    assert!(out.contains("high"), "sensitivity from the index: {out}");
    // No value ever appears.
    assert!(
        !out.contains("dev-secret-zzz") && !out.contains("prod-secret-yyy"),
        "audit must never render a value: {out}"
    );

    // Filter by environment.
    let prod = stdout(&run(v.path(), &["audit", "--env", "prod"], None));
    assert!(prod.contains("prod/api/key"));
    assert!(!prod.contains("dev/db/password"), "env filter: {prod}");

    // Filter by action.
    let creates = stdout(&run(v.path(), &["audit", "--action", "create"], None));
    assert!(creates.contains("dev/db/password") && creates.contains("prod/api/key"));

    // An unknown action is a clear error.
    let bad = run(v.path(), &["audit", "--action", "nonsense"], None);
    assert!(!bad.status.success(), "unknown action must error");
}

#[test]
fn audit_accepts_secret_prefix_and_bare_date_window() {
    let v = vault();
    assert!(
        run(
            v.path(),
            &["add", "secret:dev/db/password", "--stdin"],
            Some("val-aaa"),
        )
        .status
        .success()
    );

    // The user-facing `secret:` form is normalized to the canonical coordinate.
    let by_prefix = stdout(&run(
        v.path(),
        &["audit", "--coordinate", "secret:dev/db/password"],
        None,
    ));
    assert!(
        by_prefix.contains("dev/db/password") && by_prefix.contains("1 event"),
        "the `secret:` form must match the canonical coordinate: {by_prefix}"
    );

    // A bare `YYYY-MM-DD` --until must INCLUDE same-day events (widened to
    // end-of-day) rather than dropping them on a lexical compare.
    let full = stdout(&run(v.path(), &["audit"], None));
    let date = full
        .lines()
        .find_map(|l| {
            let t = l.split_whitespace().next()?;
            (t.len() >= 10 && t.as_bytes()[4] == b'-').then(|| t[..10].to_string())
        })
        .expect("an event timestamp");
    let windowed = stdout(&run(v.path(), &["audit", "--until", &date], None));
    assert!(
        windowed.contains("dev/db/password"),
        "bare --until {date} must include same-day events: {windowed}"
    );
}
