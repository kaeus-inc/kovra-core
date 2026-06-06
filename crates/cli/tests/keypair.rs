//! Integration tests for KOV-12 (asymmetric keys) — drive the real `kovra`
//! binary against a throwaway vault (passphrase/Argon2 mode, so the OS keychain
//! is never touched; all keypairs are generated fresh in-test, never real keys).
//!
//! Invariant coverage (one assertion path per applicable invariant):
//! - **I6** — no key value ever enters `argv` (there is no `--private-key` flag;
//!   public keys arrive via stdin).
//! - **I7** — `keygen`'s private half is never written to disk in plaintext
//!   (the whole vault tree is scanned for the OpenSSH private-key marker).
//! - **I11/I14** — a keypair's private half is never revealed: `kovra show` of a
//!   keypair never prints the private key, only the public one.
//! - **I12** — the audit log records the op + coordinate but never key bytes.
//! - **I3/I15** — a `high`/`prod` private-key op (`sign`) is broker-gated: it
//!   blocks on `kovra approve` and proceeds only once approved.
//! - Functional round-trips: sign/verify and encrypt/decrypt (ed25519),
//!   sign/verify (rsa), and OpenSSH-validity of generated public keys.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_kovra");
const PASS: &str = "integration-pass";

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

fn run_bytes(vault: &Path, args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.env("KOVRA_VAULT_DIR", vault)
        .env("KOVRA_PASSPHRASE", PASS)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn kovra");
    if let Some(s) = stdin {
        child.stdin.take().unwrap().write_all(s).unwrap();
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

// keygen produces an OpenSSH-valid public key; the private half is never printed
// (I11) and never written to disk in plaintext (I7).
#[test]
fn keygen_ed25519_openssh_valid_private_never_on_disk_or_printed() {
    let v = vault();
    let g = run(
        v.path(),
        &["keygen", "secret:dev/ssh/deploy", "--type", "ed25519"],
        None,
    );
    assert!(
        g.status.success(),
        "keygen: {}",
        String::from_utf8_lossy(&g.stderr)
    );
    let out = stdout(&g);
    // The public key is shown and is OpenSSH-valid.
    assert!(
        out.contains("ssh-ed25519 "),
        "keygen must print the OpenSSH public key: {out}"
    );
    // The private half is NEVER printed (I11/I14).
    assert!(
        !out.contains("OPENSSH PRIVATE KEY"),
        "keygen must not print the private key (I11)"
    );

    // I7 — no plaintext OpenSSH private key anywhere under the vault tree.
    for entry in walk(v.path()) {
        if let Ok(bytes) = std::fs::read(&entry) {
            assert!(
                !bytes
                    .windows(b"OPENSSH PRIVATE KEY".len())
                    .any(|w| w == b"OPENSSH PRIVATE KEY"),
                "private key found in plaintext on disk at {} (I7)",
                entry.display()
            );
        }
    }
}

// I11/I14 — `kovra show` of a keypair never prints the private key, only the
// public half (the private half is used only through sign/decrypt/ssh-add).
#[test]
fn show_keypair_never_prints_private_key() {
    let v = vault();
    run(
        v.path(),
        &["keygen", "secret:dev/ssh/deploy", "--type", "ed25519"],
        None,
    );
    let show = run(v.path(), &["show", "secret:dev/ssh/deploy"], None);
    // `show` must succeed on a keypair (must not panic/abort) and must render
    // the *public* key — a positive assertion so a fall-through to `unreachable!`
    // is caught, not silently passed by the absence check alone.
    assert!(
        show.status.success(),
        "show must succeed on a keypair record, got {:?}: {}",
        show.status,
        String::from_utf8_lossy(&show.stderr)
    );
    assert!(
        stdout(&show).contains("ssh-ed25519 "),
        "show must render the keypair's public key: {}",
        stdout(&show)
    );
    let combined = format!("{}{}", stdout(&show), String::from_utf8_lossy(&show.stderr));
    assert!(
        !combined.contains("OPENSSH PRIVATE KEY"),
        "show must never print a keypair's private key (I11/I14): {combined}"
    );
    // `pubkey` shows the public key freely.
    let pubk = run(v.path(), &["pubkey", "secret:dev/ssh/deploy"], None);
    assert!(pubk.status.success());
    assert!(stdout(&pubk).contains("ssh-ed25519 "));
}

// ed25519 sign → verify round-trip through the CLI (dev/low: ungated).
#[test]
fn ed25519_sign_verify_round_trip() {
    let v = vault();
    run(
        v.path(),
        &[
            "keygen",
            "secret:dev/ssh/sign",
            "--type",
            "ed25519",
            "--sensitivity",
            "low",
        ],
        None,
    );
    let sig = run(
        v.path(),
        &["sign", "secret:dev/ssh/sign", "-"],
        Some("attest this"),
    );
    assert!(
        sig.status.success(),
        "sign: {}",
        String::from_utf8_lossy(&sig.stderr)
    );
    let sig_file = v.path().join("sig.pem");
    std::fs::write(&sig_file, sig.stdout).unwrap();

    let ok = run(
        v.path(),
        &[
            "verify",
            "secret:dev/ssh/sign",
            "--signature",
            sig_file.to_str().unwrap(),
            "-",
        ],
        Some("attest this"),
    );
    assert!(
        ok.status.success() && stdout(&ok).contains("OK"),
        "verify should succeed: {} / {}",
        stdout(&ok),
        String::from_utf8_lossy(&ok.stderr)
    );

    // A tampered message must NOT verify.
    let bad = run(
        v.path(),
        &[
            "verify",
            "secret:dev/ssh/sign",
            "--signature",
            sig_file.to_str().unwrap(),
            "-",
        ],
        Some("attest THAT"),
    );
    assert!(!bad.status.success(), "tampered message must not verify");
}

// rsa sign → verify round-trip through the CLI.
#[test]
fn rsa_sign_verify_round_trip() {
    let v = vault();
    run(
        v.path(),
        &[
            "keygen",
            "secret:dev/ssh/rsa",
            "--type",
            "rsa",
            "--sensitivity",
            "low",
        ],
        None,
    );
    let sig = run(
        v.path(),
        &["sign", "secret:dev/ssh/rsa", "-"],
        Some("rsa msg"),
    );
    assert!(
        sig.status.success(),
        "rsa sign: {}",
        String::from_utf8_lossy(&sig.stderr)
    );
    let sig_file = v.path().join("rsa.sig");
    std::fs::write(&sig_file, sig.stdout).unwrap();
    let ok = run(
        v.path(),
        &[
            "verify",
            "secret:dev/ssh/rsa",
            "--signature",
            sig_file.to_str().unwrap(),
            "-",
        ],
        Some("rsa msg"),
    );
    assert!(
        ok.status.success() && stdout(&ok).contains("OK"),
        "rsa verify should succeed"
    );
}

// ed25519 encrypt → decrypt round-trip through the CLI (encrypt is free).
#[test]
fn ed25519_encrypt_decrypt_round_trip() {
    let v = vault();
    run(
        v.path(),
        &[
            "keygen",
            "secret:dev/box/key",
            "--type",
            "ed25519",
            "--sensitivity",
            "low",
        ],
        None,
    );
    let msg = b"top-secret cargo";
    let ct = run_bytes(v.path(), &["encrypt", "secret:dev/box/key", "-"], Some(msg));
    assert!(
        ct.status.success(),
        "encrypt: {}",
        String::from_utf8_lossy(&ct.stderr)
    );
    assert_ne!(ct.stdout, msg, "ciphertext must differ from plaintext");

    let pt = run_bytes(
        v.path(),
        &["decrypt", "secret:dev/box/key", "-"],
        Some(&ct.stdout),
    );
    assert!(
        pt.status.success(),
        "decrypt: {}",
        String::from_utf8_lossy(&pt.stderr)
    );
    assert_eq!(pt.stdout, msg, "decrypt must recover the plaintext");
}

// A public-only entry (add --public-key) can verify and encrypt but has no
// private half for sign/decrypt. I6: the public key enters via stdin, not argv.
#[test]
fn public_only_entry_encrypts_and_rejects_private_ops() {
    let v = vault();
    // Generate a keypair elsewhere to obtain a real OpenSSH public key.
    let g = run(
        v.path(),
        &[
            "keygen",
            "secret:dev/ssh/source",
            "--type",
            "ed25519",
            "--sensitivity",
            "low",
        ],
        None,
    );
    let pubkey_line = stdout(&g)
        .lines()
        .find(|l| l.starts_with("ssh-ed25519 "))
        .expect("a public key line")
        .to_string();

    // Store it as a public-only recipient entry.
    let add = run(
        v.path(),
        &[
            "add",
            "secret:dev/peer/recipient",
            "--public-key",
            "--stdin",
        ],
        Some(&pubkey_line),
    );
    assert!(
        add.status.success(),
        "add --public-key: {}",
        String::from_utf8_lossy(&add.stderr)
    );

    // It can encrypt (public op).
    let ct = run_bytes(
        v.path(),
        &["encrypt", "secret:dev/peer/recipient", "-"],
        Some(b"hi"),
    );
    assert!(ct.status.success(), "public-only entry must encrypt");

    // It cannot sign (no private half) — explicit error, not a silent success.
    let sign = run(
        v.path(),
        &["sign", "secret:dev/peer/recipient", "-"],
        Some("x"),
    );
    assert!(
        !sign.status.success(),
        "a public-only entry has no private key to sign with"
    );
    assert!(
        String::from_utf8_lossy(&sign.stderr).contains("public-only"),
        "the error should explain there is no private half"
    );
}

// I12 — a private-key op audits the action + coordinate but never the key bytes.
#[test]
fn private_key_op_audited_without_key_bytes() {
    let v = vault();
    let g = run(
        v.path(),
        &[
            "keygen",
            "secret:dev/ssh/audit",
            "--type",
            "ed25519",
            "--sensitivity",
            "low",
        ],
        None,
    );
    assert!(g.status.success());
    let s = run(v.path(), &["sign", "secret:dev/ssh/audit", "-"], Some("m"));
    assert!(
        s.status.success(),
        "sign: {}",
        String::from_utf8_lossy(&s.stderr)
    );

    let log = std::fs::read_to_string(v.path().join("audit.log")).unwrap();
    assert!(log.contains("dev/ssh/audit"), "coordinate is audited (I12)");
    assert!(log.contains("sign"), "the op is audited");
    assert!(
        !log.contains("OPENSSH PRIVATE KEY"),
        "the audit log must never contain key bytes (I12)"
    );
}

// I3/I15 — a high private-key op (`sign`) blocks until cross-process approval,
// exactly like a high reveal. dev/high here keeps the gate on without prod.
#[test]
fn high_sign_blocks_until_cross_process_approve() {
    let v = vault();
    run(
        v.path(),
        &[
            "keygen",
            "secret:dev/ssh/highkey",
            "--type",
            "ed25519",
            "--sensitivity",
            "high",
        ],
        None,
    );

    // Spawn the blocking `sign` in its own process, feeding data on stdin.
    let mut child = Command::new(BIN)
        .env("KOVRA_VAULT_DIR", v.path())
        .env("KOVRA_PASSPHRASE", PASS)
        .args(["sign", "secret:dev/ssh/highkey", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sign");
    child.stdin.take().unwrap().write_all(b"sign me").unwrap();

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

    let out = child.wait_with_output().expect("wait sign");
    assert!(
        out.status.success(),
        "sign after approve: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout(&out).contains("BEGIN SSH SIGNATURE"),
        "an approved high sign emits a signature"
    );
}

/// The id is the first non-empty, non-indented line of `approve --list` output.
fn parse_pending_id(listing: &str) -> Option<String> {
    listing
        .lines()
        .find(|l| !l.is_empty() && !l.starts_with(' ') && l.contains('-') && !l.starts_with('('))
        .map(|l| l.trim().to_string())
}

// I6 — there is no flag that puts key material on argv; a private key can only
// be born inside `keygen` (server-side) or sealed from a public-only stdin.
#[test]
fn no_private_key_flag_exists() {
    let v = vault();
    let out = run(
        v.path(),
        &[
            "keygen",
            "secret:dev/ssh/x",
            "--private-key",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
        ],
        None,
    );
    assert!(
        !out.status.success(),
        "there must be no --private-key flag (I6)"
    );
}

// The keypair half-selector resolves into a child env via `run`: #public injects
// the public key (ungated), and the private half is never returned to the caller
// (inject-only delivery, I11/I14).
#[test]
fn env_refs_public_half_injects_public_key() {
    let v = vault();
    let g = run(
        v.path(),
        &[
            "keygen",
            "secret:dev/ssh/deploy",
            "--type",
            "ed25519",
            "--sensitivity",
            "low",
        ],
        None,
    );
    let pubkey_line = stdout(&g)
        .lines()
        .find(|l| l.starts_with("ssh-ed25519 "))
        .expect("public key")
        .to_string();

    let proj = tempfile::tempdir().unwrap();
    std::fs::write(
        proj.path().join(".env.refs"),
        "DEPLOY_KEY=secret:dev/ssh/deploy#public\n",
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
            "printf '%s' \"$DEPLOY_KEY\"",
        ],
        None,
    );
    assert!(
        out.status.success(),
        "run: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The public half is not a secret: it is injected verbatim (not masked).
    assert_eq!(
        stdout(&out).trim(),
        pubkey_line.trim(),
        "#public injects the public key verbatim into the child env"
    );
}
