//! Integration tests for KOV-17 (`kovra scaffold`) — drive the real binary
//! against a throwaway sample repo. Covers: detection across Python/JS, the
//! three-segment grammar in the proposal, the no-value invariant (a planted
//! `.env` value never appears), and the no-silent-overwrite rule for `--out`.

use std::path::Path;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_kovra");

fn run(vault: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .env("KOVRA_VAULT_DIR", vault)
        .env("KOVRA_PASSPHRASE", "scaffold-test-pass")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn kovra")
}

/// A sample repo with Python + JS sources and a value-bearing `.env`.
fn sample_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("backend")).unwrap();
    std::fs::write(
        root.join("backend/db.py"),
        r#"db = os.getenv("DATABASE_URL")
key = os.environ.get("STRIPE_KEY")
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("web.ts"),
        r#"const url = process.env.DATABASE_URL;
const port = process.env.PORT;
"#,
    )
    .unwrap();
    // A value-bearing .env that scaffold must NEVER read.
    std::fs::write(
        root.join(".env"),
        "DATABASE_URL=postgres://leaked-secret-value\n",
    )
    .unwrap();
    dir
}

#[test]
fn scaffold_proposes_coordinates_without_reading_values() {
    let vault = tempfile::tempdir().unwrap();
    let repo = sample_repo();

    let out = run(vault.path(), &["scaffold", repo.path().to_str().unwrap()]);
    assert!(
        out.status.success(),
        "scaffold: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body = String::from_utf8_lossy(&out.stdout);

    // Detected coordinates, three-segment grammar with the ${ENV} placeholder.
    assert!(body.contains("DATABASE_URL=secret:${ENV}/backend/database-url"));
    assert!(body.contains("STRIPE_KEY=secret:${ENV}/backend/stripe-key"));
    assert!(body.contains("PORT=secret:${ENV}/app/port"));

    // No value is ever read or emitted — the planted .env value must be absent.
    assert!(
        !body.contains("leaked-secret-value"),
        "scaffold must never read or emit a secret value: {body}"
    );
}

#[test]
fn scaffold_out_refuses_to_overwrite_without_force() {
    let vault = tempfile::tempdir().unwrap();
    let repo = sample_repo();
    let dest = repo.path().join(".env.refs");
    std::fs::write(&dest, "# existing, hand-written\n").unwrap();

    // Without --force: refuse, leave the file untouched.
    let out = run(
        vault.path(),
        &[
            "scaffold",
            repo.path().to_str().unwrap(),
            "--out",
            dest.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success(), "must refuse to overwrite");
    assert_eq!(
        std::fs::read_to_string(&dest).unwrap(),
        "# existing, hand-written\n",
        "existing file must be untouched"
    );

    // With --force: overwrite with the proposal.
    let out = run(
        vault.path(),
        &[
            "scaffold",
            repo.path().to_str().unwrap(),
            "--out",
            dest.to_str().unwrap(),
            "--force",
        ],
    );
    assert!(
        out.status.success(),
        "scaffold --force: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let written = std::fs::read_to_string(&dest).unwrap();
    assert!(written.contains("DATABASE_URL=secret:${ENV}/backend/database-url"));
}
