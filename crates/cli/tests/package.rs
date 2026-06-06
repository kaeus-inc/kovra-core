//! Integration tests for KOV-21 (L7 — encrypted package + access token). Drive
//! the real `kovra` binary across two throwaway vaults (sender → recipient) in
//! passphrase/Argon2 mode, so the OS keychain is never touched and no real
//! secret is used. The recipient identity is a fresh ed25519 key generated with
//! `ssh-keygen` (the realistic `--identity-file` artifact — kovra never exports
//! a custodied private key).
//!
//! Invariant coverage (one assertion path per applicable invariant):
//! - **I4a** — packaging a `prod` secret fails with an explicit error; the value
//!   never appears in the output.
//! - **I8** — a reference is packaged and imported as its pointer URI; no value
//!   is ever materialized (no provider is invoked at packaging or import).
//! - **I6** — there is no flag to pass a private key on argv; `unpack` reads the
//!   identity only from `--identity-file` or `KOVRA_RECIPIENT_KEY`.
//! - **§7.2 two-factor** — a `high` entry imports unattended only WITH the token;
//!   a wrong identity cannot open the package at all.
//! - Functional round-trip: a packaged literal is imported and revealed intact.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_kovra");
const PASS: &str = "integration-pass";

fn run(vault: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    run_env(vault, args, stdin, &[])
}

fn run_env(vault: &Path, args: &[&str], stdin: Option<&str>, env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.env("KOVRA_VAULT_DIR", vault)
        .env("KOVRA_PASSPHRASE", PASS)
        // Force the file broker so a high entry without a token does not try to
        // open a (non-existent) biometric prompt on the test host.
        .env("KOVRA_CONFIRMER", "file");
    for (k, v) in env {
        cmd.env(k, v);
    }
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

/// Generate a fresh ed25519 identity with ssh-keygen; returns (private, public)
/// file paths inside `dir`.
fn ssh_keygen(dir: &Path) -> (PathBuf, PathBuf) {
    let priv_path = dir.join("id_ed25519");
    let o = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", "kovra-test", "-f"])
        .arg(&priv_path)
        .output()
        .expect("run ssh-keygen");
    assert!(
        o.status.success(),
        "ssh-keygen failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let pub_path = dir.join("id_ed25519.pub");
    assert!(priv_path.exists() && pub_path.exists());
    (priv_path, pub_path)
}

// End-to-end: a packaged medium literal is imported into the recipient vault and
// reveals intact (functional round-trip). No token needed for a non-high entry.
#[test]
fn round_trip_import_and_reveal() {
    let sender = init_vault();
    let recipient = init_vault();
    let keys = tempfile::tempdir().unwrap();
    let (id, pubkey) = ssh_keygen(keys.path());
    let out = keys.path().join("pkg.kvpk");
    let token = keys.path().join("pkg.token");

    // Sender stores a medium dev secret and packages env `dev`.
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
            "package",
            "--env",
            "dev",
            "--recipient",
            pubkey.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--token-out",
            token.to_str().unwrap(),
        ],
        None,
    );
    assert!(o.status.success(), "package failed: {}", stderr(&o));
    assert!(out.exists() && token.exists());

    // Recipient imports with the matching identity (no token → medium imports
    // directly).
    let o = run(
        recipient.path(),
        &[
            "unpack",
            "--in",
            out.to_str().unwrap(),
            "--identity-file",
            id.to_str().unwrap(),
        ],
        None,
    );
    assert!(o.status.success(), "unpack failed: {}", stderr(&o));
    assert!(stdout(&o).contains("Imported 1"), "summary: {}", stdout(&o));

    // The imported value reveals intact (medium, non-prod → Allow).
    let o = run(recipient.path(), &["show", "secret:dev/db/url"], None);
    assert!(o.status.success(), "show failed: {}", stderr(&o));
    assert!(
        stdout(&o).contains("postgres://localhost/app"),
        "revealed value: {}",
        stdout(&o)
    );
}

// I4a — packaging a prod secret is refused with an explicit error, and the value
// never appears in the output.
#[test]
fn i4a_packaging_prod_is_refused() {
    let sender = init_vault();
    let keys = tempfile::tempdir().unwrap();
    let (_id, pubkey) = ssh_keygen(keys.path());
    let out = keys.path().join("pkg.kvpk");
    let token = keys.path().join("pkg.token");

    let o = run(
        sender.path(),
        &["add", "secret:prod/db/password", "--stdin"],
        Some("prod-only-value"),
    );
    assert!(o.status.success(), "add failed: {}", stderr(&o));

    let o = run(
        sender.path(),
        &[
            "package",
            "--env",
            "prod",
            "--recipient",
            pubkey.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--token-out",
            token.to_str().unwrap(),
        ],
        None,
    );
    assert!(!o.status.success(), "packaging prod must fail");
    let err = stderr(&o);
    assert!(err.contains("I4a"), "error cites I4a: {err}");
    assert!(
        !err.contains("prod-only-value"),
        "error must not leak the value"
    );
    // Nothing was written.
    assert!(!out.exists(), "no package file on refusal");
}

// I8 — a reference is packaged and imported as its pointer URI only; no value is
// materialized (the provider `az` is never invoked).
#[test]
fn i8_reference_imported_as_pointer() {
    let sender = init_vault();
    let recipient = init_vault();
    let keys = tempfile::tempdir().unwrap();
    let (id, pubkey) = ssh_keygen(keys.path());
    let out = keys.path().join("pkg.kvpk");
    let token = keys.path().join("pkg.token");

    let o = run(
        sender.path(),
        &[
            "add",
            "secret:dev/api/key",
            "--reference",
            "azure-kv://corp-kv/api-key",
        ],
        None,
    );
    assert!(o.status.success(), "add reference failed: {}", stderr(&o));

    let o = run(
        sender.path(),
        &[
            "package",
            "--env",
            "dev",
            "--recipient",
            pubkey.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--token-out",
            token.to_str().unwrap(),
        ],
        None,
    );
    assert!(o.status.success(), "package failed: {}", stderr(&o));

    let o = run(
        recipient.path(),
        &[
            "unpack",
            "--in",
            out.to_str().unwrap(),
            "--identity-file",
            id.to_str().unwrap(),
        ],
        None,
    );
    assert!(o.status.success(), "unpack failed: {}", stderr(&o));

    // The imported entry is the pointer, not a value — `show` prints the URI.
    let o = run(recipient.path(), &["show", "secret:dev/api/key"], None);
    assert!(o.status.success(), "show failed: {}", stderr(&o));
    assert!(
        stdout(&o).contains("azure-kv://corp-kv/api-key"),
        "shows the pointer: {}",
        stdout(&o)
    );
}

// §7.2 two-factor: a `high` dev entry imports unattended ONLY with the token. The
// file broker is active and no approver is running, so the token is the only way
// the import can complete without blocking on a human.
#[test]
fn token_enables_unattended_high_import() {
    let sender = init_vault();
    let recipient = init_vault();
    let keys = tempfile::tempdir().unwrap();
    let (id, pubkey) = ssh_keygen(keys.path());
    let out = keys.path().join("pkg.kvpk");
    let token = keys.path().join("pkg.token");

    let o = run(
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
    assert!(o.status.success(), "add failed: {}", stderr(&o));

    let o = run(
        sender.path(),
        &[
            "package",
            "--env",
            "dev",
            "--recipient",
            pubkey.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--token-out",
            token.to_str().unwrap(),
        ],
        None,
    );
    assert!(o.status.success(), "package failed: {}", stderr(&o));

    // WITH the token: the high entry imports unattended (no human, no block).
    let o = run(
        recipient.path(),
        &[
            "unpack",
            "--in",
            out.to_str().unwrap(),
            "--identity-file",
            id.to_str().unwrap(),
            "--token",
            token.to_str().unwrap(),
        ],
        None,
    );
    assert!(o.status.success(), "token unpack failed: {}", stderr(&o));
    assert!(stdout(&o).contains("Imported 1"), "summary: {}", stdout(&o));

    // The high secret is now custodied in the recipient vault (metadata visible;
    // the value is not revealable without approval — we only assert presence).
    let o = run(recipient.path(), &["list", "--env", "dev"], None);
    assert!(stdout(&o).contains("dev/api/key"), "listed: {}", stdout(&o));
}

// A wrong identity cannot open the package (factor 1 — confidentiality).
#[test]
fn wrong_identity_cannot_open() {
    let sender = init_vault();
    let recipient = init_vault();
    let keys = tempfile::tempdir().unwrap();
    let (_id, pubkey) = ssh_keygen(keys.path());
    let (wrong_id, _wrong_pub) = {
        let d = tempfile::tempdir().unwrap();
        let p = ssh_keygen(d.path());
        // Keep the dir alive by leaking it into the returned paths' parent.
        std::mem::forget(d);
        p
    };
    let out = keys.path().join("pkg.kvpk");
    let token = keys.path().join("pkg.token");

    run(
        sender.path(),
        &[
            "add",
            "secret:dev/db/url",
            "--stdin",
            "--sensitivity",
            "low",
        ],
        Some("v"),
    );
    let o = run(
        sender.path(),
        &[
            "package",
            "--env",
            "dev",
            "--recipient",
            pubkey.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--token-out",
            token.to_str().unwrap(),
        ],
        None,
    );
    assert!(o.status.success(), "package failed: {}", stderr(&o));

    let o = run(
        recipient.path(),
        &[
            "unpack",
            "--in",
            out.to_str().unwrap(),
            "--identity-file",
            wrong_id.to_str().unwrap(),
        ],
        None,
    );
    assert!(
        !o.status.success(),
        "wrong identity must not open the package"
    );
}

// I6 — with neither `--identity-file` nor `KOVRA_RECIPIENT_KEY`, unpack errors and
// points at the two off-argv ways to supply the key (there is no argv flag).
#[test]
fn missing_identity_errors_off_argv() {
    let sender = init_vault();
    let recipient = init_vault();
    let keys = tempfile::tempdir().unwrap();
    let (_id, pubkey) = ssh_keygen(keys.path());
    let out = keys.path().join("pkg.kvpk");
    let token = keys.path().join("pkg.token");

    run(
        sender.path(),
        &[
            "add",
            "secret:dev/db/url",
            "--stdin",
            "--sensitivity",
            "low",
        ],
        Some("v"),
    );
    run(
        sender.path(),
        &[
            "package",
            "--env",
            "dev",
            "--recipient",
            pubkey.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--token-out",
            token.to_str().unwrap(),
        ],
        None,
    );

    let o = run(
        recipient.path(),
        &["unpack", "--in", out.to_str().unwrap()],
        None,
    );
    assert!(!o.status.success(), "no identity must fail");
    let err = stderr(&o);
    assert!(
        err.contains("KOVRA_RECIPIENT_KEY"),
        "names the env var: {err}"
    );
    assert!(err.contains("I6"), "cites I6: {err}");
}

// The same package opens via the `KOVRA_RECIPIENT_KEY` env var (no key on argv).
#[test]
fn identity_via_env_var() {
    let sender = init_vault();
    let recipient = init_vault();
    let keys = tempfile::tempdir().unwrap();
    let (id, pubkey) = ssh_keygen(keys.path());
    let out = keys.path().join("pkg.kvpk");
    let token = keys.path().join("pkg.token");

    run(
        sender.path(),
        &[
            "add",
            "secret:dev/db/url",
            "--stdin",
            "--sensitivity",
            "low",
        ],
        Some("env-value"),
    );
    let o = run(
        sender.path(),
        &[
            "package",
            "--env",
            "dev",
            "--recipient",
            pubkey.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--token-out",
            token.to_str().unwrap(),
        ],
        None,
    );
    assert!(o.status.success(), "package failed: {}", stderr(&o));

    let key_text = std::fs::read_to_string(&id).unwrap();
    let o = run_env(
        recipient.path(),
        &["unpack", "--in", out.to_str().unwrap()],
        None,
        &[("KOVRA_RECIPIENT_KEY", &key_text)],
    );
    assert!(o.status.success(), "env-var unpack failed: {}", stderr(&o));
    let o = run(recipient.path(), &["show", "secret:dev/db/url"], None);
    assert!(stdout(&o).contains("env-value"), "revealed: {}", stdout(&o));
}

// ───────── KOV-39: unpack --identity <coordinate> (custodied keypair) ─────────
//
// The all-kovra recipient path: the recipient custodies its own ed25519 keypair
// (`keygen`), shares only the public half (`pubkey`), and opens packages with
// `unpack --identity <coordinate>` — the private key is loaded under the master
// key, broker-gated for `high` keystones exactly like `decrypt`, and never
// leaves kovra (no `ssh-keygen`, no on-disk private). Tests below cover the
// functional round-trip plus the applicable invariants (I3/I15, I7/I11/I14).

/// keygen a custodied ed25519 keypair at `coord` in `vault`, then write its
/// OpenSSH **public** key to `pub_path` (the artifact a sender feeds to
/// `package --recipient`). The private half stays custodied — never exported.
fn keygen_recipient(vault: &Path, coord: &str, sensitivity: &str, pub_path: &Path) {
    let g = run(
        vault,
        &[
            "keygen",
            coord,
            "--type",
            "ed25519",
            "--sensitivity",
            sensitivity,
        ],
        None,
    );
    assert!(g.status.success(), "keygen failed: {}", stderr(&g));
    let pk = run(vault, &["pubkey", coord], None);
    assert!(pk.status.success(), "pubkey failed: {}", stderr(&pk));
    let line = stdout(&pk)
        .lines()
        .find(|l| l.starts_with("ssh-ed25519 "))
        .expect("a public key line")
        .to_string();
    std::fs::write(pub_path, line).unwrap();
}

/// Spawn a (potentially blocking) `unpack --identity` under the file broker, so
/// a `high` custodied identity can be approved/denied cross-process.
fn spawn_unpack_identity(vault: &Path, pkg: &Path, coord: &str) -> Child {
    Command::new(BIN)
        .env("KOVRA_VAULT_DIR", vault)
        .env("KOVRA_PASSPHRASE", PASS)
        .env("KOVRA_CONFIRMER", "file")
        .args(["unpack", "--in", pkg.to_str().unwrap(), "--identity", coord])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn unpack")
}

/// Poll `approve --list` until a pending request appears; return its id.
fn wait_for_pending(vault: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        assert!(Instant::now() < deadline, "approval request never appeared");
        let list = run(vault, &["approve", "--list"], None);
        if let Some(id) = parse_pending_id(&stdout(&list)) {
            return id;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The id is the first non-empty, non-indented line of `approve --list` output.
fn parse_pending_id(listing: &str) -> Option<String> {
    listing
        .lines()
        .find(|l| !l.is_empty() && !l.starts_with(' ') && l.contains('-') && !l.starts_with('('))
        .map(|l| l.trim().to_string())
}

// Functional round-trip: a custodied (medium → ungated) keypair opens a package
// sealed to its public key. The full manual exchange the WI promises.
#[test]
fn round_trip_custodied_identity() {
    let sender = init_vault();
    let recipient = init_vault();
    let keys = tempfile::tempdir().unwrap();
    let pubkey = keys.path().join("recipient.pub");
    keygen_recipient(
        recipient.path(),
        "secret:dev/exchange/key",
        "medium",
        &pubkey,
    );

    let out = keys.path().join("pkg.kvpk");
    let token = keys.path().join("pkg.token");

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
            "package",
            "--env",
            "dev",
            "--recipient",
            pubkey.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--token-out",
            token.to_str().unwrap(),
        ],
        None,
    );
    assert!(o.status.success(), "package failed: {}", stderr(&o));

    // Open with the custodied identity — no --identity-file, no env key.
    let o = run(
        recipient.path(),
        &[
            "unpack",
            "--in",
            out.to_str().unwrap(),
            "--identity",
            "secret:dev/exchange/key",
        ],
        None,
    );
    assert!(
        o.status.success(),
        "unpack --identity failed: {}",
        stderr(&o)
    );
    assert!(stdout(&o).contains("Imported 1"), "summary: {}", stdout(&o));

    let o = run(recipient.path(), &["show", "secret:dev/db/url"], None);
    assert!(o.status.success(), "show failed: {}", stderr(&o));
    assert!(
        stdout(&o).contains("postgres://localhost/app"),
        "revealed value: {}",
        stdout(&o)
    );
}

// clap rejects `--identity` together with `--identity-file` at parse time —
// before any package is read, so nothing is imported.
#[test]
fn identity_and_identity_file_conflict() {
    let recipient = init_vault();
    let keys = tempfile::tempdir().unwrap();
    let dummy = keys.path().join("id");
    std::fs::write(&dummy, "x").unwrap();

    let o = run(
        recipient.path(),
        &[
            "unpack",
            "--in",
            "/nonexistent.kvpk",
            "--identity",
            "secret:dev/x/y",
            "--identity-file",
            dummy.to_str().unwrap(),
        ],
        None,
    );
    assert!(!o.status.success(), "both identity flags must be rejected");
    let err = stderr(&o);
    assert!(
        err.contains("cannot be used with") || err.to_lowercase().contains("conflict"),
        "clap reports the conflict: {err}"
    );
    assert!(
        !err.contains("Imported"),
        "a rejected invocation imports nothing"
    );
}

// I7/I11/I14 — the custodied private key is used only in memory; it never
// appears on stdout/stderr of a successful `unpack --identity`.
#[test]
fn custodied_private_never_leaks_on_unpack() {
    let sender = init_vault();
    let recipient = init_vault();
    let keys = tempfile::tempdir().unwrap();
    let pubkey = keys.path().join("recipient.pub");
    keygen_recipient(
        recipient.path(),
        "secret:dev/exchange/key",
        "medium",
        &pubkey,
    );
    let out = keys.path().join("pkg.kvpk");
    let token = keys.path().join("pkg.token");

    run(
        sender.path(),
        &[
            "add",
            "secret:dev/db/url",
            "--stdin",
            "--sensitivity",
            "medium",
        ],
        Some("v"),
    );
    let o = run(
        sender.path(),
        &[
            "package",
            "--env",
            "dev",
            "--recipient",
            pubkey.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--token-out",
            token.to_str().unwrap(),
        ],
        None,
    );
    assert!(o.status.success(), "package failed: {}", stderr(&o));

    let o = run(
        recipient.path(),
        &[
            "unpack",
            "--in",
            out.to_str().unwrap(),
            "--identity",
            "secret:dev/exchange/key",
        ],
        None,
    );
    assert!(o.status.success(), "unpack failed: {}", stderr(&o));
    let combined = format!("{}{}", stdout(&o), stderr(&o));
    assert!(
        !combined.contains("OPENSSH PRIVATE KEY"),
        "the custodied private must never reach stdout/stderr (I7/I11/I14): {combined}"
    );
}

// I3/I15 — a `high` custodied identity is broker-gated: approving cross-process
// lets the package open. (The packaged secret is medium so the only approval in
// play is the identity gate, mirroring `decrypt`.)
#[test]
fn high_custodied_identity_opens_when_approved() {
    let sender = init_vault();
    let recipient = init_vault();
    let keys = tempfile::tempdir().unwrap();
    let pubkey = keys.path().join("recipient.pub");
    keygen_recipient(recipient.path(), "secret:dev/exchange/hi", "high", &pubkey);
    let out = keys.path().join("pkg.kvpk");
    let token = keys.path().join("pkg.token");

    run(
        sender.path(),
        &[
            "add",
            "secret:dev/db/url",
            "--stdin",
            "--sensitivity",
            "medium",
        ],
        Some("gated-round-trip"),
    );
    let o = run(
        sender.path(),
        &[
            "package",
            "--env",
            "dev",
            "--recipient",
            pubkey.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--token-out",
            token.to_str().unwrap(),
        ],
        None,
    );
    assert!(o.status.success(), "package failed: {}", stderr(&o));

    let child = spawn_unpack_identity(recipient.path(), &out, "secret:dev/exchange/hi");
    let id = wait_for_pending(recipient.path());
    let ap = run(recipient.path(), &["approve", &id], None);
    assert!(ap.status.success(), "approve: {}", stderr(&ap));

    let done = child.wait_with_output().expect("wait unpack");
    assert!(
        done.status.success(),
        "approved high identity should open the package: {}",
        String::from_utf8_lossy(&done.stderr)
    );
    assert!(
        String::from_utf8_lossy(&done.stdout).contains("Imported 1"),
        "imported after approval: {}",
        String::from_utf8_lossy(&done.stdout)
    );
}

// I3/I15 — denying the `high` custodied identity fails closed: the package is
// never opened and nothing is imported.
#[test]
fn high_custodied_identity_denied_fails_closed() {
    let sender = init_vault();
    let recipient = init_vault();
    let keys = tempfile::tempdir().unwrap();
    let pubkey = keys.path().join("recipient.pub");
    keygen_recipient(recipient.path(), "secret:dev/exchange/hi", "high", &pubkey);
    let out = keys.path().join("pkg.kvpk");
    let token = keys.path().join("pkg.token");

    run(
        sender.path(),
        &[
            "add",
            "secret:dev/db/url",
            "--stdin",
            "--sensitivity",
            "medium",
        ],
        Some("must-not-import"),
    );
    let o = run(
        sender.path(),
        &[
            "package",
            "--env",
            "dev",
            "--recipient",
            pubkey.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--token-out",
            token.to_str().unwrap(),
        ],
        None,
    );
    assert!(o.status.success(), "package failed: {}", stderr(&o));

    let child = spawn_unpack_identity(recipient.path(), &out, "secret:dev/exchange/hi");
    let id = wait_for_pending(recipient.path());
    let dn = run(recipient.path(), &["approve", "--deny", &id], None);
    assert!(dn.status.success(), "deny: {}", stderr(&dn));

    let done = child.wait_with_output().expect("wait unpack");
    assert!(
        !done.status.success(),
        "a denied high identity must fail closed"
    );
    // Nothing was imported into the recipient vault.
    let show = run(recipient.path(), &["show", "secret:dev/db/url"], None);
    assert!(
        !show.status.success(),
        "a denied identity must import nothing"
    );
}

// A wrong custodied identity cannot open a package sealed to another key
// (factor 1 — confidentiality), just like a wrong --identity-file.
#[test]
fn wrong_custodied_identity_cannot_open() {
    let sender = init_vault();
    let recipient = init_vault();
    let keys = tempfile::tempdir().unwrap();
    let pubkey = keys.path().join("recipient.pub");
    keygen_recipient(
        recipient.path(),
        "secret:dev/exchange/right",
        "medium",
        &pubkey,
    );
    // A different custodied keypair — the wrong identity.
    let other = run(
        recipient.path(),
        &[
            "keygen",
            "secret:dev/exchange/wrong",
            "--type",
            "ed25519",
            "--sensitivity",
            "medium",
        ],
        None,
    );
    assert!(other.status.success(), "keygen wrong: {}", stderr(&other));

    let out = keys.path().join("pkg.kvpk");
    let token = keys.path().join("pkg.token");
    run(
        sender.path(),
        &[
            "add",
            "secret:dev/db/url",
            "--stdin",
            "--sensitivity",
            "medium",
        ],
        Some("v"),
    );
    let o = run(
        sender.path(),
        &[
            "package",
            "--env",
            "dev",
            "--recipient",
            pubkey.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--token-out",
            token.to_str().unwrap(),
        ],
        None,
    );
    assert!(o.status.success(), "package failed: {}", stderr(&o));

    let o = run(
        recipient.path(),
        &[
            "unpack",
            "--in",
            out.to_str().unwrap(),
            "--identity",
            "secret:dev/exchange/wrong",
        ],
        None,
    );
    assert!(
        !o.status.success(),
        "the wrong custodied identity must not open the package"
    );
}

// A public-only entry has no private half — `--identity` pointing at one is a
// clean error (via keypair_private), not a silent failure.
#[test]
fn public_only_identity_rejected() {
    let sender = init_vault();
    let recipient = init_vault();
    let keys = tempfile::tempdir().unwrap();

    // Generate a keypair to obtain a real public key, then store it public-only.
    let g = run(
        recipient.path(),
        &[
            "keygen",
            "secret:dev/src/key",
            "--type",
            "ed25519",
            "--sensitivity",
            "medium",
        ],
        None,
    );
    let pk_line = stdout(&g)
        .lines()
        .find(|l| l.starts_with("ssh-ed25519 "))
        .expect("a public key line")
        .to_string();
    let add = run(
        recipient.path(),
        &["add", "secret:dev/peer/pub", "--public-key", "--stdin"],
        Some(&pk_line),
    );
    assert!(add.status.success(), "add --public-key: {}", stderr(&add));

    // Seal to that same public key, so opening *would* work if a private existed.
    let pubfile = keys.path().join("peer.pub");
    std::fs::write(&pubfile, &pk_line).unwrap();
    let out = keys.path().join("pkg.kvpk");
    let token = keys.path().join("pkg.token");
    run(
        sender.path(),
        &[
            "add",
            "secret:dev/db/url",
            "--stdin",
            "--sensitivity",
            "medium",
        ],
        Some("v"),
    );
    let o = run(
        sender.path(),
        &[
            "package",
            "--env",
            "dev",
            "--recipient",
            pubfile.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--token-out",
            token.to_str().unwrap(),
        ],
        None,
    );
    assert!(o.status.success(), "package failed: {}", stderr(&o));

    let o = run(
        recipient.path(),
        &[
            "unpack",
            "--in",
            out.to_str().unwrap(),
            "--identity",
            "secret:dev/peer/pub",
        ],
        None,
    );
    assert!(
        !o.status.success(),
        "a public-only identity has no private key to open with"
    );
    assert!(
        stderr(&o).contains("public-only"),
        "the error explains there is no private half: {}",
        stderr(&o)
    );
}

// A missing coordinate, and a coordinate that is not a keypair, both error
// cleanly via resolve_keypair.
#[test]
fn identity_coordinate_not_found_or_not_keypair() {
    let sender = init_vault();
    let recipient = init_vault();
    let keys = tempfile::tempdir().unwrap();
    let pubkey = keys.path().join("recipient.pub");
    keygen_recipient(
        recipient.path(),
        "secret:dev/exchange/key",
        "medium",
        &pubkey,
    );
    let out = keys.path().join("pkg.kvpk");
    let token = keys.path().join("pkg.token");
    run(
        sender.path(),
        &[
            "add",
            "secret:dev/db/url",
            "--stdin",
            "--sensitivity",
            "medium",
        ],
        Some("v"),
    );
    run(
        sender.path(),
        &[
            "package",
            "--env",
            "dev",
            "--recipient",
            pubkey.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--token-out",
            token.to_str().unwrap(),
        ],
        None,
    );

    // Not found.
    let o = run(
        recipient.path(),
        &[
            "unpack",
            "--in",
            out.to_str().unwrap(),
            "--identity",
            "secret:dev/missing/key",
        ],
        None,
    );
    assert!(
        !o.status.success(),
        "a missing identity coordinate must fail"
    );

    // Present, but not a keypair.
    run(
        recipient.path(),
        &[
            "add",
            "secret:dev/plain/val",
            "--stdin",
            "--sensitivity",
            "low",
        ],
        Some("notakey"),
    );
    let o = run(
        recipient.path(),
        &[
            "unpack",
            "--in",
            out.to_str().unwrap(),
            "--identity",
            "secret:dev/plain/val",
        ],
        None,
    );
    assert!(!o.status.success(), "a non-keypair identity must fail");
    assert!(
        stderr(&o).contains("not a keypair"),
        "the error explains it is not a keypair: {}",
        stderr(&o)
    );
}
