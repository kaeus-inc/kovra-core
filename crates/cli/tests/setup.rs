//! Integration tests for `kovra setup` (KOV-9) — the per-repo onboarding flow,
//! driven through the real `kovra` binary in an isolated temp repo + temp vault
//! (passphrase mode, no OS keychain, no real secrets).

use std::fs;
use std::path::Path;
use std::process::Command;

fn kovra() -> Command {
    // The integration-test binary path is exposed by Cargo.
    Command::new(env!("CARGO_BIN_EXE_kovra"))
}

/// Run `kovra setup` in `repo`, with an isolated vault dir + passphrase backend.
fn run_setup(repo: &Path, vault: &Path, extra: &[&str]) -> std::process::Output {
    let mut cmd = kovra();
    cmd.arg("setup")
        .args(extra)
        .current_dir(repo)
        .env("KOVRA_VAULT_DIR", vault)
        .env("KOVRA_PASSPHRASE", "setup-itest-throwaway");
    cmd.output().expect("run kovra setup")
}

#[test]
fn setup_creates_mcp_json_and_claude_md() {
    let repo = tempfile::tempdir().unwrap();
    let vault = tempfile::tempdir().unwrap();

    let out = run_setup(repo.path(), vault.path(), &["--project", "demo"]);
    assert!(
        out.status.success(),
        "setup failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // .mcp.json registers the kovra server scoped to the project.
    let mcp = fs::read_to_string(repo.path().join(".mcp.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&mcp).unwrap();
    assert_eq!(v["mcpServers"]["kovra"]["command"], "kovra-mcp");
    assert_eq!(
        v["mcpServers"]["kovra"]["env"]["KOVRA_MCP_PROJECTS"],
        "demo"
    );

    // CLAUDE.md carries the conventions block with its markers.
    let claude = fs::read_to_string(repo.path().join("CLAUDE.md")).unwrap();
    assert!(claude.contains("<!-- kovra:begin -->"));
    assert!(claude.contains("<!-- kovra:end -->"));
    assert!(claude.contains("kovra run"));
}

#[test]
fn setup_is_idempotent() {
    let repo = tempfile::tempdir().unwrap();
    let vault = tempfile::tempdir().unwrap();

    run_setup(repo.path(), vault.path(), &["--project", "demo"]);
    let mcp1 = fs::read_to_string(repo.path().join(".mcp.json")).unwrap();
    let claude1 = fs::read_to_string(repo.path().join("CLAUDE.md")).unwrap();

    // Second run must not change either file.
    run_setup(repo.path(), vault.path(), &["--project", "demo"]);
    let mcp2 = fs::read_to_string(repo.path().join(".mcp.json")).unwrap();
    let claude2 = fs::read_to_string(repo.path().join("CLAUDE.md")).unwrap();

    assert_eq!(mcp1, mcp2, ".mcp.json must be stable across re-runs");
    assert_eq!(claude1, claude2, "CLAUDE.md must be stable across re-runs");
    // exactly one marker pair, never duplicated
    assert_eq!(claude2.matches("<!-- kovra:begin -->").count(), 1);
}

#[test]
fn setup_preserves_existing_claude_md_and_other_mcp_servers() {
    let repo = tempfile::tempdir().unwrap();
    let vault = tempfile::tempdir().unwrap();

    // Pre-existing CLAUDE.md with the project's own rules, and an .mcp.json with
    // another server — both must survive.
    fs::write(
        repo.path().join("CLAUDE.md"),
        "# My Project\n\nMy own rules that must not be touched.\n",
    )
    .unwrap();
    fs::write(
        repo.path().join(".mcp.json"),
        r#"{"mcpServers":{"other":{"command":"other-server"}}}"#,
    )
    .unwrap();

    let out = run_setup(repo.path(), vault.path(), &["--project", "demo"]);
    assert!(out.status.success());

    let claude = fs::read_to_string(repo.path().join("CLAUDE.md")).unwrap();
    assert!(claude.contains("My own rules that must not be touched."));
    assert!(claude.contains("<!-- kovra:begin -->"));

    let v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(repo.path().join(".mcp.json")).unwrap()).unwrap();
    assert_eq!(v["mcpServers"]["other"]["command"], "other-server");
    assert_eq!(v["mcpServers"]["kovra"]["command"], "kovra-mcp");
}

#[test]
fn setup_dry_run_writes_nothing() {
    let repo = tempfile::tempdir().unwrap();
    let vault = tempfile::tempdir().unwrap();

    let out = run_setup(
        repo.path(),
        vault.path(),
        &["--project", "demo", "--dry-run"],
    );
    assert!(out.status.success());
    assert!(
        !repo.path().join(".mcp.json").exists(),
        "dry-run wrote .mcp.json"
    );
    assert!(
        !repo.path().join("CLAUDE.md").exists(),
        "dry-run wrote CLAUDE.md"
    );
}
