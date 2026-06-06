//! Integration tests for KOV-24 (`kovra import` from 1Password). Drive the real
//! `kovra` binary against a throwaway vault (passphrase mode) with a **fake `op`
//! CLI** shadowing the real one on PATH, so the end-to-end import path
//! (including `SystemOpRunner`) is exercised without a real 1Password account.
//!
//! Coverage: the value is stored as a literal (not a reference) and reveals
//! intact; `prod` is born `high` (I5); the value never appears in `import`'s
//! own output (I12); a non-`op://` reference and a not-signed-in `op` both fail
//! with clear, distinct errors.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_kovra");
const PASS: &str = "integration-pass";

/// Write a fake `op` executable into `dir`. In `ok` mode, `op read <ref>` prints
/// `$FAKE_OP_VALUE` (with a trailing newline, like the real `op`); in `signin`
/// mode it fails as if not signed in.
fn fake_op(dir: &Path, mode: &str) {
    let script = match mode {
        "ok" => {
            "#!/bin/sh\nif [ \"$1\" = \"read\" ]; then printf '%s\\n' \"$FAKE_OP_VALUE\"; exit 0; fi\necho 'unexpected op invocation' >&2\nexit 2\n"
        }
        "signin" => {
            "#!/bin/sh\necho '[ERROR] you are not currently signed in. Please run `op signin`.' >&2\nexit 1\n"
        }
        other => panic!("unknown fake op mode {other}"),
    };
    let path = dir.join("op");
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Run `kovra` with a fake-`op` dir prepended to PATH and `FAKE_OP_VALUE` set.
fn run_import(vault: &Path, op_dir: &Path, value: &str, args: &[&str]) -> Output {
    let path = format!(
        "{}:{}",
        op_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::new(BIN);
    cmd.env("KOVRA_VAULT_DIR", vault)
        .env("KOVRA_PASSPHRASE", PASS)
        .env("PATH", path)
        .env("FAKE_OP_VALUE", value)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn().expect("spawn kovra");
    child.wait_with_output().expect("wait kovra")
}

/// Run `kovra` normally (no fake op needed — e.g. show/list).
fn run(vault: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.env("KOVRA_VAULT_DIR", vault)
        .env("KOVRA_PASSPHRASE", PASS)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.spawn()
        .expect("spawn kovra")
        .wait_with_output()
        .expect("wait kovra")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn vault() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let o = run(dir.path(), &["init"]);
    assert!(o.status.success(), "init failed: {}", stderr(&o));
    dir
}

// A dev/medium credential imports as a literal and reveals intact; the value
// never appears in the import command's own output (I12).
#[test]
fn imports_value_as_literal_and_reveals() {
    let v = vault();
    let ops = tempfile::tempdir().unwrap();
    fake_op(ops.path(), "ok");

    let o = run_import(
        v.path(),
        ops.path(),
        "s3cr3t-from-1password",
        &[
            "import",
            "secret:dev/db/password",
            "--from",
            "op://Personal/db/password",
            "--sensitivity",
            "medium",
        ],
    );
    assert!(o.status.success(), "import failed: {}", stderr(&o));
    assert!(
        stdout(&o).contains("Imported dev/db/password"),
        "summary: {}",
        stdout(&o)
    );
    // I12 — the value is never echoed by import (stored, not shown).
    assert!(!stdout(&o).contains("s3cr3t-from-1password"));
    assert!(!stderr(&o).contains("s3cr3t-from-1password"));

    // It is a literal (not a reference) — `list` shows mode `literal`.
    let o = run(v.path(), &["list", "--env", "dev"]);
    let table = stdout(&o);
    assert!(table.contains("dev/db/password"));
    assert!(table.contains("literal"), "stored as literal: {table}");
    assert!(
        !table.contains("op://"),
        "no 1Password relationship is kept"
    );

    // The value reveals intact (dev/medium → allowed).
    let o = run(v.path(), &["show", "secret:dev/db/password"]);
    assert!(o.status.success(), "show failed: {}", stderr(&o));
    assert!(
        stdout(&o).contains("s3cr3t-from-1password"),
        "revealed: {}",
        stdout(&o)
    );
}

// I5 — a prod import is born `high` (and stored as a literal).
#[test]
fn prod_import_is_born_high() {
    let v = vault();
    let ops = tempfile::tempdir().unwrap();
    fake_op(ops.path(), "ok");

    let o = run_import(
        v.path(),
        ops.path(),
        "prod-value",
        &[
            "import",
            "secret:prod/db/password",
            "--from",
            "op://Prod/db/password",
        ],
    );
    assert!(o.status.success(), "import failed: {}", stderr(&o));
    assert!(
        stdout(&o).contains("High"),
        "prod born high: {}",
        stdout(&o)
    );
    let o = run(v.path(), &["list", "--env", "prod"]);
    assert!(stdout(&o).contains("high"), "listed high: {}", stdout(&o));
}

// A not-signed-in `op` fails with a clear, distinct error — never a silent store.
#[test]
fn not_signed_in_fails_clearly() {
    let v = vault();
    let ops = tempfile::tempdir().unwrap();
    fake_op(ops.path(), "signin");

    let o = run_import(
        v.path(),
        ops.path(),
        "unused",
        &[
            "import",
            "secret:dev/db/password",
            "--from",
            "op://Personal/db/password",
        ],
    );
    assert!(!o.status.success(), "must fail when not signed in");
    assert!(stderr(&o).contains("signed in"), "error: {}", stderr(&o));
    // Nothing was stored.
    let o = run(v.path(), &["list", "--env", "dev"]);
    assert!(
        stdout(&o).contains("(no secrets)"),
        "nothing stored on failure"
    );
}

// A non-`op://` reference is rejected before `op` is ever invoked (I6/validation).
#[test]
fn non_op_reference_is_rejected() {
    let v = vault();
    let ops = tempfile::tempdir().unwrap();
    fake_op(ops.path(), "ok");
    let o = run_import(
        v.path(),
        ops.path(),
        "x",
        &[
            "import",
            "secret:dev/db/password",
            "--from",
            "azure-kv://kv/secret",
        ],
    );
    assert!(!o.status.success(), "non-op:// reference must be rejected");
    assert!(
        stderr(&o).contains("op://"),
        "error names the expected form: {}",
        stderr(&o)
    );
}

// Importing onto an existing coordinate is refused (use set/edit).
#[test]
fn existing_coordinate_is_refused() {
    let v = vault();
    let ops = tempfile::tempdir().unwrap();
    fake_op(ops.path(), "ok");
    let args = [
        "import",
        "secret:dev/db/password",
        "--from",
        "op://Personal/db/password",
    ];
    let first = run_import(v.path(), ops.path(), "v1", &args);
    assert!(
        first.status.success(),
        "first import failed: {}",
        stderr(&first)
    );
    let second = run_import(v.path(), ops.path(), "v2", &args);
    assert!(!second.status.success(), "second import must be refused");
    assert!(
        stderr(&second).contains("already exists"),
        "error: {}",
        stderr(&second)
    );
}
