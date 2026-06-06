//! `kovra_run_compose` — drives the L5 wrapper against a local **Docker Compose**
//! dev stack, to show how kovra feeds secrets into `docker compose` without ever
//! writing a plaintext `.env` (I7) or putting a value in argv (I6).
//!
//!   cargo run -p kovra-wrapper --example kovra_run_compose -- dev
//!   cargo run -p kovra-wrapper --example kovra_run_compose -- prod
//!
//! It (re)seeds a stable vault under `sandbox/.kovra-compose-vault/`, resolves
//! `sandbox/docker-demo/.env.refs`, and runs `docker compose -f … config` with
//! the resolved values injected into the child environment. `config` renders the
//! fully-interpolated compose file **without** needing the Docker daemon — so you
//! can see exactly which variables Compose received. Vault-backed values come
//! back **masked** in the output (§5.1 net); the literal PORT and the `${env:}`
//! LOG_LEVEL passthrough come back in clear.
//!
//! dev seeds `medium` secrets (inject freely). prod seeds `high` secrets (I5):
//! the wrapper requires an allowlisted executor (here: the real `docker` binary)
//! and an attended confirmation — this harness AUTO-DENIES it to show the gate
//! without hanging, so the child never launches.

use std::path::{Path, PathBuf};
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

/// Prints the authoritative prompt (built by the core, I16) and AUTO-DENIES, so
/// the prod path demonstrates the gate non-interactively.
struct AutoDenyConfirmer;

impl Confirmer for AutoDenyConfirmer {
    fn confirm(&self, req: &ConfirmRequest, _timeout: Duration) -> ConfirmOutcome {
        println!("\n  ┌─ kovra confirmation required (high/prod injection) ────────");
        println!(
            "  │  command : {}",
            req.resolved_command.as_deref().unwrap_or("-")
        );
        println!("  │  secret  : {}", req.coordinate);
        println!("  │  sens/env: {:?} / {}", req.sensitivity, req.environment);
        println!("  └─ (harness auto-denies to avoid hanging)");
        ConfirmOutcome::Denied
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

/// Locate the `docker` binary so it can be allowlisted (prod) and launched.
fn docker_bin() -> PathBuf {
    for cand in ["/usr/local/bin/docker", "/opt/homebrew/bin/docker"] {
        if Path::new(cand).exists() {
            return PathBuf::from(cand);
        }
    }
    PathBuf::from("docker") // PATH fallback
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf();
    let project = root.join("sandbox/docker-demo");
    let vault_dir = root.join("sandbox/.kovra-compose-vault");
    let compose = project.join("docker-compose.yml");
    let refs_path = project.join(".env.refs");

    let env = std::env::args().nth(1).unwrap_or_else(|| "dev".to_string());

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

    let refs_src = std::fs::read_to_string(&refs_path).expect("read .env.refs");
    let refs = EnvRefs::parse(&refs_src).expect("parse .env.refs");

    let docker = docker_bin();
    let args = vec![
        "compose".to_string(),
        "-f".to_string(),
        compose.display().to_string(),
        "config".to_string(),
    ];

    let keyring = MockKeyring::with_key(MASTER);
    let env_source = SystemEnvSource; // real env → LOG_LEVEL passthrough works
    let provider = MockProvider::new();
    let audit = FileAuditSink::under_root(&vault_dir);
    let clock = SystemClock;
    let confirmer = AutoDenyConfirmer;
    let runner = SystemRunner;
    // The reviewed executor for high/prod injection (I15) is the docker binary.
    let allowlist = Allowlist::from_paths([&docker]);

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
        "kovra run --env {env}  --  {} compose -f {} config",
        docker.display(),
        compose.display()
    );

    match w.run(&refs, &env, None, &docker, &args, Origin::Human) {
        Ok(out) => {
            print!("\n{}", String::from_utf8_lossy(&out.stdout));
            if !out.stderr.is_empty() {
                eprint!("{}", String::from_utf8_lossy(&out.stderr));
            }
            println!(
                "(exit {:?}; vault-backed values masked above — §5.1)",
                out.status
            );
        }
        Err(WrapperError::ConfirmationDenied) => {
            println!("\n→ denied: docker compose never launched (no secret reached it).")
        }
        Err(WrapperError::NotAllowlisted { program }) => {
            println!("\n→ refused (I15): `{program}` is not a reviewed executor.")
        }
        Err(e) => println!("\n→ error: {e}"),
    }

    println!("\naudit log: {}", vault_dir.join("audit.log").display());
}
