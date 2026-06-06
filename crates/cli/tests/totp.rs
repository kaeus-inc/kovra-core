//! Integration tests for KOV-11 (the TOTP modality) — drive the real `kovra`
//! binary against a throwaway vault (passphrase/Argon2 mode, so the OS keychain
//! is never touched; all seeds are RFC-6238 test vectors / throwaway, never a
//! real enrollment).
//!
//! Invariant coverage (one assertion path per applicable invariant):
//! - **I6** — no seed ever enters `argv` (there is no `--seed`/`--value` flag;
//!   the seed arrives via stdin / a hidden prompt).
//! - **I7** — `add --totp`'s seed is never written to disk in plaintext (the
//!   whole vault tree is scanned for the seed bytes).
//! - **I11/I14** — the seed is never revealed: `kovra show` of a TOTP record
//!   renders only its params + a hint, never the seed; `kovra code` prints the
//!   derived code, not the seed.
//! - **I12** — the audit log records the op + coordinate but never the seed.
//! - **I3/I15** — a `high`/`prod` `code` op is broker-gated: it blocks on
//!   `kovra approve` and proceeds only once approved.
//!
//! The exact RFC-6238 known-answer derivation (deterministic via `MockClock`)
//! lives in the core unit tests (`kovra-core` `totp::tests`); through the CLI
//! the clock is the real system clock, so here we assert code *shape* and the
//! invariant boundaries, not a fixed code value.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_kovra");
const PASS: &str = "integration-pass";

// The base32 of the RFC-6238 SHA1 test seed "12345678901234567890".
const SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
// The raw seed bytes (must never appear on disk / in the audit log — I7/I12).
const SEED_RAW: &[u8] = b"12345678901234567890";

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

/// Recursively collect every file path under `dir`.
fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
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

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// add --totp ingests a base32 seed via stdin (I6 — never argv), and the seed is
// never written to disk in plaintext (I7).
#[test]
fn add_totp_seed_never_on_disk_and_code_is_six_digits() {
    let v = vault();
    let add = run(
        v.path(),
        &[
            "add",
            "secret:dev/auth/mfa",
            "--totp",
            "--stdin",
            "--sensitivity",
            "low",
        ],
        Some(SEED_B32),
    );
    assert!(
        add.status.success(),
        "add --totp: {}",
        String::from_utf8_lossy(&add.stderr)
    );

    // I7 — the raw seed must not appear anywhere under the vault tree.
    for entry in walk(v.path()) {
        if let Ok(bytes) = std::fs::read(&entry) {
            assert!(
                !contains(&bytes, SEED_RAW),
                "seed found in plaintext on disk at {} (I7)",
                entry.display()
            );
            assert!(
                !contains(&bytes, SEED_B32.as_bytes()),
                "base32 seed found in plaintext on disk at {} (I7)",
                entry.display()
            );
        }
    }

    // A low/dev `code` prints a 6-digit code directly (ungated), never the seed.
    let code = run(v.path(), &["code", "secret:dev/auth/mfa"], None);
    assert!(
        code.status.success(),
        "code: {}",
        String::from_utf8_lossy(&code.stderr)
    );
    let printed = stdout(&code);
    let digits = printed.trim();
    assert_eq!(digits.len(), 6, "default code is 6 digits: {printed:?}");
    assert!(
        digits.chars().all(|c| c.is_ascii_digit()),
        "code is all digits: {printed:?}"
    );
    // The seed is never printed (I11/I14).
    assert!(!printed.contains(SEED_B32));
    assert!(!String::from_utf8_lossy(&code.stderr).contains(SEED_B32));
}

// add --totp accepts a full otpauth:// URI; the derived code length honors the
// URI's `digits` parameter (8 here).
#[test]
fn add_totp_otpauth_uri_honors_digits() {
    let v = vault();
    let uri = format!(
        "otpauth://totp/ACME:alice@example.com?secret={SEED_B32}&issuer=ACME&algorithm=SHA1&digits=8&period=30"
    );
    let add = run(
        v.path(),
        &[
            "add",
            "secret:dev/auth/uri",
            "--totp",
            "--stdin",
            "--sensitivity",
            "low",
        ],
        Some(&uri),
    );
    assert!(
        add.status.success(),
        "add --totp uri: {}",
        String::from_utf8_lossy(&add.stderr)
    );
    let code = run(v.path(), &["code", "secret:dev/auth/uri"], None);
    assert!(code.status.success());
    assert_eq!(stdout(&code).trim().len(), 8, "URI overrode digits to 8");
}

// `--min-validity 0` forces non-interactive scripting output and, since the
// seconds remaining in a window is always >= 1 (> 0), must return the CURRENT
// code immediately and deterministically — exercising the flag plumbing without
// any window-boundary timing flakiness. The seed is never printed (I11/I14).
#[test]
fn code_min_validity_zero_returns_current_code() {
    let v = vault();
    run(
        v.path(),
        &[
            "add",
            "secret:dev/auth/minv",
            "--totp",
            "--stdin",
            "--sensitivity",
            "low",
        ],
        Some(SEED_B32),
    );
    let c = run(
        v.path(),
        &["code", "secret:dev/auth/minv", "--min-validity", "0"],
        None,
    );
    assert!(
        c.status.success(),
        "code --min-validity 0: {}",
        String::from_utf8_lossy(&c.stderr)
    );
    let printed = stdout(&c);
    let digits = printed.trim();
    assert_eq!(digits.len(), 6, "default code is 6 digits: {printed:?}");
    assert!(
        digits.chars().all(|c| c.is_ascii_digit()),
        "code is all digits: {printed:?}"
    );
    // The seed is never printed (I11/I14).
    assert!(!printed.contains(SEED_B32));
    assert!(!String::from_utf8_lossy(&c.stderr).contains(SEED_B32));
}

// `--min-validity N` with N >= the code's period is an impossible guarantee (a
// code is valid for at most `period` seconds) — it must error, not loop/return a
// code that can't satisfy the request. The default period is 30s.
#[test]
fn code_min_validity_at_or_above_period_errors() {
    let v = vault();
    run(
        v.path(),
        &[
            "add",
            "secret:dev/auth/minv2",
            "--totp",
            "--stdin",
            "--sensitivity",
            "low",
        ],
        Some(SEED_B32),
    );
    let c = run(
        v.path(),
        &["code", "secret:dev/auth/minv2", "--min-validity", "30"],
        None,
    );
    assert!(!c.status.success(), "min-validity == period must error");
    let err = String::from_utf8_lossy(&c.stderr);
    assert!(
        err.contains("less than the TOTP period"),
        "clear error explaining the impossible guarantee: {err:?}"
    );
}

// I11/I14 — `kovra show` of a TOTP record never prints the seed, only the
// params + a hint to use `kovra code`.
#[test]
fn show_totp_never_prints_seed() {
    let v = vault();
    run(
        v.path(),
        &[
            "add",
            "secret:dev/auth/mfa",
            "--totp",
            "--stdin",
            "--sensitivity",
            "low",
        ],
        Some(SEED_B32),
    );
    let show = run(v.path(), &["show", "secret:dev/auth/mfa"], None);
    assert!(
        show.status.success(),
        "show must succeed on a TOTP record: {}",
        String::from_utf8_lossy(&show.stderr)
    );
    let combined = format!("{}{}", stdout(&show), String::from_utf8_lossy(&show.stderr));
    assert!(
        combined.contains("totp"),
        "show renders the TOTP params: {combined}"
    );
    assert!(
        combined.contains("kovra code"),
        "show hints to derive a code with `kovra code`: {combined}"
    );
    assert!(
        !combined.contains(SEED_B32),
        "show must never print the seed (I11/I14): {combined}"
    );
}

// `set` cannot overwrite a TOTP enrollment (the modality is fixed).
#[test]
fn set_rejects_totp() {
    let v = vault();
    run(
        v.path(),
        &[
            "add",
            "secret:dev/auth/mfa",
            "--totp",
            "--stdin",
            "--sensitivity",
            "low",
        ],
        Some(SEED_B32),
    );
    let set = run(
        v.path(),
        &["set", "secret:dev/auth/mfa", "--stdin"],
        Some("plain-value"),
    );
    assert!(
        !set.status.success(),
        "set must refuse to overwrite a TOTP enrollment"
    );
    assert!(
        String::from_utf8_lossy(&set.stderr).contains("TOTP"),
        "the error explains it is a TOTP enrollment"
    );
}

// I12 — `code` audits the op + coordinate but never the seed bytes.
#[test]
fn code_audited_without_seed() {
    let v = vault();
    run(
        v.path(),
        &[
            "add",
            "secret:dev/auth/audit",
            "--totp",
            "--stdin",
            "--sensitivity",
            "low",
        ],
        Some(SEED_B32),
    );
    let c = run(v.path(), &["code", "secret:dev/auth/audit"], None);
    assert!(
        c.status.success(),
        "code: {}",
        String::from_utf8_lossy(&c.stderr)
    );

    let log = std::fs::read_to_string(v.path().join("audit.log")).unwrap();
    assert!(
        log.contains("dev/auth/audit"),
        "coordinate is audited (I12)"
    );
    assert!(
        log.contains("code-derived"),
        "the code op is audited (I12): {log}"
    );
    assert!(
        !log.contains(SEED_B32) && !log.contains("12345678901234567890"),
        "the audit log must never contain the seed (I12)"
    );
}

// I3/I15 — a `code` op on a `high` enrollment blocks until cross-process
// approval, exactly like a high reveal/private-key op. dev/high keeps the gate
// on without needing prod.
#[test]
fn high_code_blocks_until_cross_process_approve() {
    let v = vault();
    run(
        v.path(),
        &[
            "add",
            "secret:dev/auth/high",
            "--totp",
            "--stdin",
            "--sensitivity",
            "high",
        ],
        Some(SEED_B32),
    );

    // Spawn the blocking `code` in its own process.
    let child = Command::new(BIN)
        .env("KOVRA_VAULT_DIR", v.path())
        .env("KOVRA_PASSPHRASE", PASS)
        .env("KOVRA_CONFIRMER", "file") // force the cross-process file broker
        .args(["code", "secret:dev/auth/high"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn code");

    // Poll `approve --list` until the pending request appears, then approve.
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

    let out = child.wait_with_output().expect("wait code");
    assert!(
        out.status.success(),
        "code after approve: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let printed = stdout(&out);
    assert_eq!(
        printed.trim().len(),
        6,
        "an approved high code emits a 6-digit code: {printed:?}"
    );
    assert!(!printed.contains(SEED_B32), "the seed is never printed");
}

// I6 — there is no flag that puts the seed on argv; the seed is born only from
// stdin / a hidden prompt.
#[test]
fn no_seed_flag_exists() {
    let v = vault();
    let out = run(
        v.path(),
        &["add", "secret:dev/auth/x", "--totp", "--seed", SEED_B32],
        None,
    );
    assert!(!out.status.success(), "there must be no --seed flag (I6)");
}

// `--totp` is mutually exclusive with `--reference` and `--public-key`.
#[test]
fn totp_is_mutually_exclusive() {
    let v = vault();
    let out = run(
        v.path(),
        &[
            "add",
            "secret:dev/auth/x",
            "--totp",
            "--reference",
            "azure-kv://kv/x",
        ],
        Some(SEED_B32),
    );
    assert!(
        !out.status.success(),
        "--totp and --reference are mutually exclusive"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("mutually exclusive"),);
}

/// The id is the first non-empty, non-indented line of `approve --list` output.
fn parse_pending_id(listing: &str) -> Option<String> {
    listing
        .lines()
        .find(|l| !l.is_empty() && !l.starts_with(' ') && l.contains('-') && !l.starts_with('('))
        .map(|l| l.trim().to_string())
}
