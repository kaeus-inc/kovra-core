//! `kovra_run` — a manual harness that drives the L5 wrapper against the
//! `sandbox/demo-app` project, until the real `kovra` CLI binary lands (L7).
//!
//!   cargo run -p kovra-wrapper --example kovra_run -- dev
//!   cargo run -p kovra-wrapper --example kovra_run -- prod
//!   cargo run -p kovra-wrapper --example kovra_run -- prod nolist
//!
//! It (re)seeds a stable vault under `sandbox/.kovra-vault/` with fixed
//! throwaway values, then resolves `sandbox/demo-app/.env.refs` and launches
//! `sandbox/demo-app/app.sh` with the resolved environment injected.

use std::io::{self, Write};
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use kovra_core::{
    ConfirmOutcome, ConfirmRequest, Confirmer, Coordinate, EnvRefs, FileAuditSink, KEY_LEN,
    MockKeyring, MockProvider, Origin, Registry, SecretRecord, SecretValue, Sensitivity,
    SystemClock, SystemEnvSource, seal, store,
};
use kovra_wrapper::{Allowlist, SystemRunner, Wrapper, WrapperError};

/// Fixed master key so the seeded vault is reproducible across runs/machines.
const MASTER: [u8; KEY_LEN] = [0x5a; KEY_LEN];

/// An attended confirmer: prints the authoritative prompt (built by the core,
/// I16) and reads your y/N from stdin.
struct InteractiveConfirmer;

impl Confirmer for InteractiveConfirmer {
    fn confirm(&self, req: &ConfirmRequest, _timeout: Duration) -> ConfirmOutcome {
        println!("\n  ┌─ kovra needs your approval (high/prod injection) ──────────");
        println!(
            "  │  command : {}",
            req.resolved_command.as_deref().unwrap_or("-")
        );
        println!("  │  secret  : {}", req.coordinate);
        println!("  │  sens/env: {:?} / {}", req.sensitivity, req.environment);
        println!("  │  origin  : {}", req.origin.as_str());
        print!("  └─ approve injection? [y/N] ");
        io::stdout().flush().ok();
        let mut s = String::new();
        io::stdin().read_line(&mut s).ok();
        if s.trim().eq_ignore_ascii_case("y") {
            ConfirmOutcome::Approved
        } else {
            ConfirmOutcome::Denied
        }
    }
}

fn seed(reg: &Registry, env: &str, comp: &str, key: &str, value: &str, s: Sensitivity) {
    let rec = SecretRecord::Literal {
        value: SecretValue::from(value),
        sensitivity: s,
        revealable: false,
        environment: env.into(),
        component: comp.into(),
        key: key.into(),
        description: None,
        created: "2026-05-31T00:00:00Z".into(),
        updated: "2026-05-31T00:00:00Z".into(),
    };
    let coord = Coordinate::from_str(&format!("secret:{env}/{comp}/{key}")).unwrap();
    store::write_record(&reg.global_dir(), &coord, &seal(&rec, &MASTER).unwrap()).unwrap();
}

fn main() {
    // Resolve sandbox paths relative to this crate (robust to the caller's cwd).
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf();
    let project = root.join("sandbox/demo-app");
    let vault_dir = root.join("sandbox/.kovra-vault");
    let app = project.join("app.sh");
    let refs_path = project.join(".env.refs");

    // Parse args: <env> [nolist]
    //   nolist → empty allowlist (demo the I15 refusal)
    let args: Vec<String> = std::env::args().skip(1).collect();
    let env = args.first().cloned().unwrap_or_else(|| "dev".to_string());
    let no_allowlist = args.iter().any(|a| a == "nolist");

    // (Re)seed the stable vault — idempotent overwrite.
    let reg = Registry::open(&vault_dir).expect("open vault");
    seed(
        &reg,
        "dev",
        "db",
        "password",
        "dev-db-pw",
        Sensitivity::Medium,
    );
    seed(
        &reg,
        "dev",
        "app",
        "api-key",
        "dev-api-key-0001",
        Sensitivity::Medium,
    );
    seed(
        &reg,
        "prod",
        "db",
        "password",
        "prod-db-pw-REDACTED",
        Sensitivity::High,
    );
    seed(
        &reg,
        "prod",
        "app",
        "api-key",
        "prod-api-key-REDACTED",
        Sensitivity::High,
    );

    // Make app.sh executable (in case the checkout dropped the bit).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&app, std::fs::Permissions::from_mode(0o755));
    }

    let allowlist = if no_allowlist {
        Allowlist::empty()
    } else {
        Allowlist::from_paths([&app])
    };

    let refs_src = std::fs::read_to_string(&refs_path).expect("read .env.refs");
    let refs = EnvRefs::parse(&refs_src).expect("parse .env.refs");

    let keyring = MockKeyring::with_key(MASTER);
    let env_source = SystemEnvSource; // real env → LOG_LEVEL passthrough works
    let provider = MockProvider::new();
    let audit = FileAuditSink::under_root(&vault_dir);
    let clock = SystemClock;
    let confirmer = InteractiveConfirmer;
    let runner = SystemRunner;

    let w = Wrapper {
        registry: &reg,
        keyring: &keyring,
        env_source: &env_source,
        provider: &provider,
        confirmer: &confirmer,
        audit: &audit,
        clock: &clock,
        allowlist: &allowlist,
        runner: &runner,
        confirm_timeout: Duration::from_secs(120),
        sanitize_output: true,
        requesting_process: kovra_wrapper::observe_parent(),
    };

    println!(
        "kovra run --env {env}  --  {} (allowlist: {})",
        app.display(),
        if no_allowlist { "EMPTY" } else { "app.sh" }
    );

    match w.run(&refs, &env, None, &app, &[], Origin::Human) {
        Ok(out) => {
            print!("\n{}", String::from_utf8_lossy(&out.stdout));
            if !out.stderr.is_empty() {
                eprint!("{}", String::from_utf8_lossy(&out.stderr));
            }
            println!(
                "(exit {:?}; vault-secret values masked above — §5.1)",
                out.status
            );
        }
        Err(WrapperError::ConfirmationDenied) => println!("\n→ denied: the child never launched."),
        Err(WrapperError::ConfirmationTimedOut) => {
            println!("\n→ timed out: denied, child never launched.")
        }
        Err(WrapperError::NotAllowlisted { program }) => {
            println!("\n→ refused (I15): `{program}` is not a reviewed executor.")
        }
        Err(e) => println!("\n→ error: {e}"),
    }

    println!("\naudit log: {}", vault_dir.join("audit.log").display());
}
