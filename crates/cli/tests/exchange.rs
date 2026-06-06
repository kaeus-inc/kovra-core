//! Integration tests for KOV-42 (`kovra exchange seal`) — the origin side of the
//! USB offline-exchange kit, driven through the real binary across two throwaway
//! passphrase vaults (sender → recipient). The `[host]` pieces (formatting a
//! real USB in `exchange init`, the `/Volumes` mount) are NOT exercised here;
//! `--usb <dir>` points the seal at an ordinary temp directory, so the whole
//! seal → token-to-stdout → `unpack --identity` round-trip is CI-testable.
//!
//! Invariant coverage:
//! - **§7.2 two-channel** — the access token is emitted to STDOUT and is
//!   deliberately NOT written to the USB; package + token are two factors.
//! - **I4a** — sealing a `prod` env is refused; the value never appears.
//! - Functional round-trip: a sealed `medium` literal imports via the custodied
//!   recipient identity (KOV-39), and a `high` entry imports with the token.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_kovra");
const PASS: &str = "integration-pass";
/// Must match `kovra_core::exchange::RECIPIENT_COORDINATE`.
const RECIPIENT_COORD: &str = "secret:exchange/recipient/key";

fn run(vault: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.env("KOVRA_VAULT_DIR", vault)
        .env("KOVRA_PASSPHRASE", PASS)
        .env("KOVRA_CONFIRMER", "file");
    cmd.args(args)
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

fn init_vault() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let o = run(dir.path(), &["init"], None);
    assert!(o.status.success(), "init failed: {}", stderr(&o));
    dir
}

/// Stand up a recipient vault with a custodied keypair at the fixed exchange
/// coordinate, and write its public key to `<usb>/recipient.pub` (what the
/// destination's `install.sh` does). `sensitivity` controls whether opening the
/// package later is broker-gated.
fn recipient_with_pub(usb: &Path, sensitivity: &str) -> tempfile::TempDir {
    let recipient = init_vault();
    let g = run(
        recipient.path(),
        &[
            "keygen",
            RECIPIENT_COORD,
            "--type",
            "ed25519",
            "--sensitivity",
            sensitivity,
        ],
        None,
    );
    assert!(g.status.success(), "keygen failed: {}", stderr(&g));
    let pk = run(recipient.path(), &["pubkey", RECIPIENT_COORD], None);
    assert!(pk.status.success(), "pubkey failed: {}", stderr(&pk));
    let line = stdout(&pk)
        .lines()
        .find(|l| l.starts_with("ssh-ed25519 "))
        .expect("a public key line")
        .to_string();
    std::fs::write(usb.join("recipient.pub"), line).unwrap();
    recipient
}

// Full origin→destination round-trip with --usb pointed at a temp dir: seal
// writes package.kovra + unpack.sh, prints the token to stdout, and the
// destination opens it with the custodied identity. The token is NOT on the USB.
#[test]
fn seal_round_trip_token_to_stdout_not_on_usb() {
    let sender = init_vault();
    let usb = tempfile::tempdir().unwrap();
    let recipient = recipient_with_pub(usb.path(), "medium");

    let o = run(
        sender.path(),
        &[
            "add",
            "secret:dev/db/url",
            "--stdin",
            "--sensitivity",
            "medium",
        ],
        Some("postgres://localhost/app"),
    );
    assert!(o.status.success(), "add failed: {}", stderr(&o));

    let o = run(
        sender.path(),
        &[
            "exchange",
            "seal",
            "--env",
            "dev",
            "--usb",
            usb.path().to_str().unwrap(),
        ],
        None,
    );
    assert!(o.status.success(), "exchange seal failed: {}", stderr(&o));

    // package.kovra + unpack.sh on the USB; the token is NOT on the USB.
    assert!(usb.path().join("package.kovra").exists(), "package written");
    assert!(usb.path().join("unpack.sh").exists(), "unpack.sh written");
    assert!(
        !usb.path().join("token").exists() && !usb.path().join("package.token").exists(),
        "the token must never be written to the USB (§7.2)"
    );

    // The token went to stdout — capture it for the destination (second channel).
    let token_text = stdout(&o);
    assert!(!token_text.trim().is_empty(), "token emitted to stdout");
    let token_file = usb.path().parent().unwrap().join("token.out");
    std::fs::write(&token_file, token_text.trim()).unwrap();

    // Destination opens with the custodied identity (medium → ungated).
    let o = run(
        recipient.path(),
        &[
            "unpack",
            "--in",
            usb.path().join("package.kovra").to_str().unwrap(),
            "--identity",
            RECIPIENT_COORD,
        ],
        None,
    );
    assert!(
        o.status.success(),
        "destination unpack failed: {}",
        stderr(&o)
    );
    assert!(stdout(&o).contains("Imported 1"), "summary: {}", stdout(&o));

    let o = run(recipient.path(), &["show", "secret:dev/db/url"], None);
    assert!(
        stdout(&o).contains("postgres://localhost/app"),
        "revealed: {}",
        stdout(&o)
    );
}

// The stdout token is a real access token: it enables unattended import of a
// `high` entry on the destination (the two-factor second channel).
#[test]
fn stdout_token_enables_unattended_high_import() {
    let sender = init_vault();
    let usb = tempfile::tempdir().unwrap();
    // medium identity so opening is ungated; the HIGH packaged entry is what the
    // token gates.
    let recipient = recipient_with_pub(usb.path(), "medium");

    run(
        sender.path(),
        &[
            "add",
            "secret:dev/api/key",
            "--stdin",
            "--sensitivity",
            "high",
        ],
        Some("a-high-dev-secret"),
    );

    let o = run(
        sender.path(),
        &[
            "exchange",
            "seal",
            "--env",
            "dev",
            "--usb",
            usb.path().to_str().unwrap(),
        ],
        None,
    );
    assert!(o.status.success(), "seal failed: {}", stderr(&o));
    let token_file = usb.path().parent().unwrap().join("tok.out");
    std::fs::write(&token_file, stdout(&o).trim()).unwrap();

    // With the token, the high entry imports unattended (file broker, no human).
    let o = run(
        recipient.path(),
        &[
            "unpack",
            "--in",
            usb.path().join("package.kovra").to_str().unwrap(),
            "--identity",
            RECIPIENT_COORD,
            "--token",
            token_file.to_str().unwrap(),
        ],
        None,
    );
    assert!(o.status.success(), "token unpack failed: {}", stderr(&o));
    assert!(stdout(&o).contains("Imported 1"), "summary: {}", stdout(&o));
}

// I4a — sealing a prod env is refused, and the value never appears in output.
#[test]
fn seal_prod_is_refused() {
    let sender = init_vault();
    let usb = tempfile::tempdir().unwrap();
    let _recipient = recipient_with_pub(usb.path(), "medium");

    run(
        sender.path(),
        &["add", "secret:prod/db/password", "--stdin"],
        Some("prod-only-value"),
    );

    let o = run(
        sender.path(),
        &[
            "exchange",
            "seal",
            "--env",
            "prod",
            "--usb",
            usb.path().to_str().unwrap(),
        ],
        None,
    );
    assert!(!o.status.success(), "sealing prod must fail (I4a)");
    let err = stderr(&o);
    assert!(
        !err.contains("prod-only-value"),
        "the error must not leak the value"
    );
    assert!(
        !usb.path().join("package.kovra").exists(),
        "no package on refusal"
    );
}

// ───────────────────────── KOV-43: exchange open + register-token ─────────────

/// Seal `env` from `sender` to the USB and return the stdout access token text.
fn seal_to_usb(sender: &Path, usb: &Path, env: &str) -> String {
    let o = run(
        sender,
        &[
            "exchange",
            "seal",
            "--env",
            env,
            "--usb",
            usb.to_str().unwrap(),
        ],
        None,
    );
    assert!(o.status.success(), "seal failed: {}", stderr(&o));
    stdout(&o).trim().to_string()
}

// One-action destination import: register the out-of-band token (via stdin),
// then `exchange open` discovers package.kovra and imports — no token flag, no
// identity flag. The registered token is consumed on success.
#[test]
fn open_one_action_with_registered_token() {
    let sender = init_vault();
    let usb = tempfile::tempdir().unwrap();
    let recipient = recipient_with_pub(usb.path(), "medium");

    run(
        sender.path(),
        &[
            "add",
            "secret:dev/api/key",
            "--stdin",
            "--sensitivity",
            "high",
        ],
        Some("a-high-dev-secret"),
    );
    let token = seal_to_usb(sender.path(), usb.path(), "dev");

    // Register the token (second channel) by pasting it on stdin.
    let o = run(
        recipient.path(),
        &["exchange", "register-token"],
        Some(&token),
    );
    assert!(o.status.success(), "register-token failed: {}", stderr(&o));

    // One action: open. No --token, no --identity — both come from registration
    // and the fixed recipient coordinate.
    let o = run(
        recipient.path(),
        &["exchange", "open", "--usb", usb.path().to_str().unwrap()],
        None,
    );
    assert!(o.status.success(), "exchange open failed: {}", stderr(&o));
    assert!(stdout(&o).contains("Imported 1"), "summary: {}", stdout(&o));

    // The registered token is single-use: it is consumed (deleted) on success.
    let registered = recipient.path().join("exchange").join("registered.token");
    assert!(
        !registered.exists(),
        "the registered token must be consumed after a successful open"
    );
}

// `exchange open --token <file>` uses an explicit token file instead of the
// registered one.
#[test]
fn open_with_explicit_token_flag() {
    let sender = init_vault();
    let usb = tempfile::tempdir().unwrap();
    let recipient = recipient_with_pub(usb.path(), "medium");

    run(
        sender.path(),
        &[
            "add",
            "secret:dev/db/url",
            "--stdin",
            "--sensitivity",
            "medium",
        ],
        Some("postgres://localhost/app"),
    );
    let token = seal_to_usb(sender.path(), usb.path(), "dev");
    let token_file = usb.path().parent().unwrap().join("explicit.token");
    std::fs::write(&token_file, &token).unwrap();

    let o = run(
        recipient.path(),
        &[
            "exchange",
            "open",
            "--usb",
            usb.path().to_str().unwrap(),
            "--token",
            token_file.to_str().unwrap(),
        ],
        None,
    );
    assert!(o.status.success(), "open --token failed: {}", stderr(&o));
    assert!(stdout(&o).contains("Imported 1"), "summary: {}", stdout(&o));

    let o = run(recipient.path(), &["show", "secret:dev/db/url"], None);
    assert!(
        stdout(&o).contains("postgres://localhost/app"),
        "revealed: {}",
        stdout(&o)
    );
}

// `exchange open` with no package on the USB errors clearly (no panic).
#[test]
fn open_missing_package_errors() {
    let recipient = init_vault();
    let usb = tempfile::tempdir().unwrap();
    let o = run(
        recipient.path(),
        &["exchange", "open", "--usb", usb.path().to_str().unwrap()],
        None,
    );
    assert!(!o.status.success(), "missing package must fail");
    assert!(
        stderr(&o).contains("package.kovra"),
        "error names the missing package: {}",
        stderr(&o)
    );
}

// register-token rejects garbage that is not a real access token.
#[test]
fn register_token_rejects_non_token() {
    let recipient = init_vault();
    let o = run(
        recipient.path(),
        &["exchange", "register-token"],
        Some("not-a-real-token"),
    );
    assert!(!o.status.success(), "garbage token must be rejected");
}
