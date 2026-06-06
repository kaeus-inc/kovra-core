//! Integration tests for KOV-19 (`kovra hooks install`) — drive the real binary
//! to install a pre-commit secret-scan hook, then prove it blocks a planted
//! fake secret and lets a clean diff through. The end-to-end scan test is gated
//! on `gitleaks` being on PATH (a `[host]` tool); the install test always runs.
//!
//! No real secret is used — the planted material is a synthetic fake.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_kovra");

fn kovra(vault: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .env("KOVRA_VAULT_DIR", vault)
        .env("KOVRA_PASSPHRASE", "hooks-test-pass")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn kovra")
}

fn git(repo: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .current_dir(repo)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn git")
}

/// A fresh git repo with identity configured.
fn git_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    assert!(git(dir.path(), &["init", "-q"]).status.success());
    git(dir.path(), &["config", "user.email", "t@t.test"]);
    git(dir.path(), &["config", "user.name", "Test"]);
    dir
}

#[test]
fn install_writes_an_executable_hook_and_config() {
    let vault = tempfile::tempdir().unwrap();
    let repo = git_repo();

    let out = kovra(
        vault.path(),
        &["hooks", "install", repo.path().to_str().unwrap()],
    );
    assert!(
        out.status.success(),
        "hooks install: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let hook = repo.path().join(".git/hooks/pre-commit");
    assert!(hook.exists(), "pre-commit hook must be written");
    let body = std::fs::read_to_string(&hook).unwrap();
    assert!(body.contains("gitleaks") && body.contains("--staged"));
    assert!(
        repo.path().join(".gitleaks.toml").exists(),
        "gitleaks config shipped"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&hook).unwrap().permissions().mode();
        assert!(mode & 0o111 != 0, "hook must be executable");
    }
}

#[test]
fn install_refuses_to_clobber_a_foreign_hook_without_force() {
    let vault = tempfile::tempdir().unwrap();
    let repo = git_repo();
    let hook = repo.path().join(".git/hooks/pre-commit");
    std::fs::write(&hook, "#!/bin/sh\necho mine\n").unwrap();

    let out = kovra(
        vault.path(),
        &["hooks", "install", repo.path().to_str().unwrap()],
    );
    assert!(
        !out.status.success(),
        "must refuse to clobber a foreign hook"
    );
    assert_eq!(
        std::fs::read_to_string(&hook).unwrap(),
        "#!/bin/sh\necho mine\n",
        "foreign hook left untouched"
    );

    // --force replaces it.
    let out = kovra(
        vault.path(),
        &["hooks", "install", repo.path().to_str().unwrap(), "--force"],
    );
    assert!(out.status.success(), "--force should replace the hook");
}

#[test]
fn hook_blocks_a_planted_secret_and_passes_clean() {
    if which("gitleaks").is_none() {
        eprintln!("SKIP: gitleaks not on PATH — end-to-end scan not exercised");
        return;
    }
    let vault = tempfile::tempdir().unwrap();
    let repo = git_repo();
    assert!(
        kovra(
            vault.path(),
            &["hooks", "install", repo.path().to_str().unwrap()]
        )
        .status
        .success()
    );
    let hook = repo.path().join(".git/hooks/pre-commit");

    // A synthetic private key block — gitleaks' private-key rule flags it.
    let secret = "-----BEGIN PRIVATE KEY-----\n\
                  MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA1FAKEKEYFAKEKEY\n\
                  -----END PRIVATE KEY-----\n";
    std::fs::write(repo.path().join("leaked.txt"), secret).unwrap();
    assert!(git(repo.path(), &["add", "leaked.txt"]).status.success());

    let blocked = Command::new(&hook)
        .current_dir(repo.path())
        .output()
        .expect("run hook");
    assert!(
        !blocked.status.success(),
        "the hook must BLOCK a commit containing a secret: {}",
        String::from_utf8_lossy(&blocked.stdout)
    );
    // --redact keeps the matched value out of the output.
    let shown = String::from_utf8_lossy(&blocked.stdout).into_owned()
        + &String::from_utf8_lossy(&blocked.stderr);
    assert!(
        !shown.contains("FAKEKEYFAKEKEY"),
        "redacted output must not echo the secret: {shown}"
    );

    // A clean staged diff passes.
    git(repo.path(), &["reset", "-q"]);
    std::fs::remove_file(repo.path().join("leaked.txt")).unwrap();
    std::fs::write(repo.path().join("clean.txt"), "just some code\n").unwrap();
    assert!(git(repo.path(), &["add", "clean.txt"]).status.success());
    let passed = Command::new(&hook)
        .current_dir(repo.path())
        .output()
        .expect("run hook");
    assert!(
        passed.status.success(),
        "a clean diff must pass the hook: {}",
        String::from_utf8_lossy(&passed.stderr)
    );
}

/// Locate a binary on PATH (test-local `which`).
fn which(bin: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join(bin))
            .find(|p| p.is_file())
    })
}
