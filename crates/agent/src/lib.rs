//! `kovra-agent` — the governed ssh-agent (KOV-13). A thin face over
//! `kovra-core`, mirroring `kovra-wrapper` and `kovra-cli`: kovra **is** the
//! ssh-agent. It speaks the ssh-agent wire protocol on `$SSH_AUTH_SOCK` and
//! answers each sign request by signing **in its own memory** with a custodied
//! [`Keypair`](kovra_core::SecretRecord) (KOV-12). The private key never leaves
//! kovra and never hits disk (I7).
//!
//! What a plain agent cannot do, and this one does:
//! - **Per-signature policy.** A `high`/`prod` key confirms via the broker /
//!   biometric on **every** signature and is audited (I3/I15/I12); `low`/
//!   `medium` keys sign silently (still audited).
//! - **Scope (I13).** The agent serves keys under an [`AgentScope`] read from a
//!   config file (`<root>/agent.toml`, see [`config`]); an out-of-scope key is
//!   neither listed nor signable.
//!
//! **Honest limit (spec §16).** This governs the *authentication event* — the
//! moment `ssh` asks the agent to sign the session challenge — **not** the SSH
//! session that opens afterward. Once a signature is approved and the session is
//! established, kovra has no further control over what flows through it, exactly
//! as Vault/1Password/etc. cannot. Per-signature confirmation makes each new
//! auth an attended, audited act; it does not contain the live session. Do not
//! overclaim this in docs or UAT notes.
//!
//! ## Layering
//! `agent → core` only (like `wrapper → core`). `core` never depends on this
//! crate. Free core (§20): this is `crates/agent`, NOT `enterprise/`. All
//! cryptography lives in `core` ([`kovra_core::sign_ssh_agent`]); this crate only
//! parses/encodes the wire protocol and orchestrates policy/scope/audit. The
//! untrusted parser is isolated in [`protocol`] (a Phase-4 fuzz target).

pub mod config;
pub mod daemon;
pub mod error;
pub mod protocol;
pub mod session;

use std::path::PathBuf;
use std::time::Duration;

pub use config::{AGENT_CONFIG_FILE, config_path, load_scope};
pub use daemon::{SessionOwned, default_socket_path};
pub use error::AgentError;
pub use session::{KeypairEntry, Session};

use kovra_core::{AgentScope, AuditSink, Clock, Confirmer};

/// Everything `run_agent` needs, built by the face (the CLI) from its `Ctx`.
/// The custodied keys are provided by a closure so the daemon can re-read them
/// per request (a key added/removed while the daemon runs is reflected).
pub struct AgentConfig {
    /// The socket path to bind (published as `$SSH_AUTH_SOCK`).
    pub socket_path: PathBuf,
    /// The agent's capability scope (I13), from `agent.toml` or the safe default.
    pub scope: AgentScope,
    /// How long a `high`/`prod` confirmation may block before failing safe.
    pub confirm_timeout: Duration,
    /// The observed requesting process for the I16 prompt line, if any.
    pub requesting_process: Option<String>,
}

/// Provider of the live session inputs per request: the custodied keypairs, a
/// fresh confirmer, audit sink, and clock. Implemented by the CLI over its
/// `Ctx`; behind a trait so the daemon stays face-agnostic and testable.
pub trait SessionProvider {
    /// Load the custodied keypairs that have a private half. Out-of-scope
    /// filtering is applied by the session against the agent's scope (I13).
    fn load_keys(&self) -> Result<Vec<KeypairEntry>, AgentError>;
    /// A fresh confirmation broker (biometric / file fallback).
    fn confirmer(&self) -> Box<dyn Confirmer>;
    /// The append-only audit sink (I12).
    fn audit(&self) -> Box<dyn AuditSink>;
    /// The clock for audit timestamps.
    fn clock(&self) -> Box<dyn Clock>;
}

/// Run the governed ssh-agent in the **foreground** (decision Q4) until Ctrl-C.
///
/// Refuses to start if `$SSH_AUTH_SOCK` is already set (decision Q5: never
/// hijack/chain an existing agent — the error carries the how-to-proceed
/// guidance). Binds the socket `0600`, prints the `export SSH_AUTH_SOCK=…` hint,
/// serves connections, and removes the socket on exit.
///
/// The socket peer and a real `ssh` client are `[host]` — validated by the human
/// on the M4. The protocol/session logic this drives is mock-tested.
pub fn run_agent<P: SessionProvider>(config: AgentConfig, provider: P) -> Result<(), AgentError> {
    daemon::ensure_no_existing_agent()?;

    let listener = daemon::bind(&config.socket_path)?;
    let path_display = config.socket_path.display().to_string();

    // Best-effort socket teardown on SIGINT/SIGTERM (foreground lifecycle). We
    // install a tiny signal handler that removes the socket and exits; the accept
    // loop otherwise blocks. (Native signal wiring is a `[host]` concern; the
    // core remove is exercised by `daemon::cleanup`.)
    install_signal_cleanup(&config.socket_path);

    eprintln!(
        "kovra ssh-agent listening on {path_display}\n\
         Export it in the shells that should use kovra as their agent:\n\
         \n    export SSH_AUTH_SOCK={path_display}\n\
         \nServing in the foreground — press Ctrl-C to stop. \
         (Governs the auth event, not the SSH session that follows — spec §16.)"
    );

    let confirm_timeout = config.confirm_timeout;
    let scope = config.scope;
    let requesting_process = config.requesting_process;

    let result = daemon::serve(&listener, || {
        Ok(SessionOwned {
            keys: provider.load_keys()?,
            scope: scope.clone(),
            confirmer: provider.confirmer(),
            audit: provider.audit(),
            clock: provider.clock(),
            confirm_timeout,
            requesting_process: requesting_process.clone(),
        })
    });

    daemon::cleanup(&config.socket_path);
    result
}

/// Install a best-effort SIGINT/SIGTERM handler that removes the socket and
/// exits cleanly. Uses only libc (already a transitive dep via `kovra-wrapper`).
#[cfg(unix)]
fn install_signal_cleanup(path: &std::path::Path) {
    use std::sync::OnceLock;
    static SOCK: OnceLock<PathBuf> = OnceLock::new();
    let _ = SOCK.set(path.to_path_buf());

    extern "C" fn handler(_sig: i32) {
        if let Some(p) = SOCK.get() {
            // Direct unlink in the handler (async-signal-safe via libc).
            if let Ok(c) = std::ffi::CString::new(p.as_os_str().to_string_lossy().as_bytes()) {
                unsafe {
                    libc::unlink(c.as_ptr());
                }
            }
        }
        // Exit without unwinding (handler context).
        std::process::exit(130);
    }

    let handler_ptr = handler as *const () as libc::sighandler_t;
    unsafe {
        libc::signal(libc::SIGINT, handler_ptr);
        libc::signal(libc::SIGTERM, handler_ptr);
    }
}

#[cfg(not(unix))]
fn install_signal_cleanup(_path: &std::path::Path) {}
