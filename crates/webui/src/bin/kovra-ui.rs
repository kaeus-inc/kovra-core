//! `kovra-ui` — the container entrypoint for the dockerized Web UI (L11,
//! KOV-23; spec §12; invariants I9/I10).
//!
//! Runs the L10 Web UI **inside a container**. It cannot reach the host OS
//! keyring, so the master key arrives at runtime as a **Docker secret mounted in
//! `tmpfs`** (I9) — read from the file named by `KOVRA_MASTER_KEY_FILE`, never
//! baked into an image layer and never passed as an env *value*. The registry is
//! the `~/.vaults` **rw bind-mount** at `KOVRA_VAULT_DIR`.
//!
//! Inside the container the server binds `KOVRA_UI_BIND` (default `0.0.0.0` so
//! Docker's host-side `-p 127.0.0.1:PORT:PORT` publish — set by `kovra ui
//! --docker` — can reach it). Loopback exposure (I10) is enforced by that
//! host-side publish plus the in-app `Origin`/`Host` guard and session token.
//!
//! Configuration (all via env, set by the orchestrator):
//! - `KOVRA_VAULT_DIR`       — registry root (the rw bind-mount). Required.
//! - `KOVRA_MASTER_KEY_FILE` — path to the master-key secret in tmpfs. Required.
//! - `KOVRA_UI_BIND`         — bind IP (default `0.0.0.0`).
//! - `KOVRA_UI_PORT`         — port (default [`kovra_webui::DEFAULT_PORT`]).
//! - `KOVRA_UI_IDLE_SECS`    — idle auto-shutdown seconds (default `300`).

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use kovra_core::{Confirmer, FileConfirmer};
use kovra_webui::{AppState, parse_master_key, serve};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Diagnostics only — never a key or a value (I7/I12).
            eprintln!("kovra-ui: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let root = env_required("KOVRA_VAULT_DIR")?;
    let key_file = env_required("KOVRA_MASTER_KEY_FILE")?;
    let bind: IpAddr = std::env::var("KOVRA_UI_BIND")
        .ok()
        .unwrap_or_else(|| "0.0.0.0".to_string())
        .parse()
        .map_err(|_| "KOVRA_UI_BIND is not a valid IP address".to_string())?;
    let port: u16 = match std::env::var("KOVRA_UI_PORT") {
        Ok(p) => p
            .parse()
            .map_err(|_| "KOVRA_UI_PORT is not a valid port".to_string())?,
        Err(_) => kovra_webui::DEFAULT_PORT,
    };
    let idle = Duration::from_secs(
        std::env::var("KOVRA_UI_IDLE_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(300),
    );

    // The master key comes from the Docker secret in tmpfs (I9). Read it, parse
    // it, and drop the file bytes immediately — they never reach a log.
    let raw = std::fs::read(&key_file)
        .map_err(|e| format!("reading master key file {key_file:?}: {e}"))?;
    let master = parse_master_key(&raw)?;
    drop(raw);

    // Per-action confirmations (delete / sensitivity downgrade — KOV-30) run
    // through the file broker: there is no Touch ID inside the container, so a
    // pending request surfaces under `<root>/pending` (the `~/.vaults` rw
    // bind-mount) and the operator approves it on the **host** via `kovra
    // approve`. The host-side launch gate (`kovra ui --docker`) covers attended
    // launch separately.
    let root_path = PathBuf::from(root);
    let confirmer: Arc<dyn Confirmer + Send + Sync> =
        Arc::new(FileConfirmer::under_root(&root_path));

    // The host orchestrator may hand us the ephemeral session token (so the URL
    // it opened matches). Otherwise generate one (standalone container use).
    let state = match std::env::var("KOVRA_UI_SESSION") {
        Ok(token) if !token.is_empty() => {
            AppState::new_with_session(root_path, master, token, confirmer)
        }
        _ => AppState::new(root_path, master, confirmer),
    };
    let addr = SocketAddr::new(bind, port);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("binding {addr}: {e}"))?;
    eprintln!(
        "kovra-ui: serving on {addr} (idle shutdown {}s). Reach it via the host's loopback publish.",
        idle.as_secs()
    );
    serve(listener, state, idle)
        .await
        .map_err(|e| format!("serving: {e}"))
}

fn env_required(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is required (set by `kovra ui --docker`)"))
}
