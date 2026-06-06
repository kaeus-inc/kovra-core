//! Socket lifecycle for the governed ssh-agent (KOV-13, decision Q4:
//! foreground-only MVP; decision Q5: refuse-and-guide on a pre-existing
//! `$SSH_AUTH_SOCK`).
//!
//! This is the OS edge: it binds a UNIX socket (mode `0600`), prints the
//! `SSH_AUTH_SOCK` to export, and serves connections in the foreground until
//! Ctrl-C, removing the socket on exit. **The socket peer and a real `ssh`
//! client are `[host]`** — validated on hardware by the human, not asserted by
//! automated tests (CLAUDE.md rule 4). The *protocol* and *session* logic it
//! drives ([`crate::protocol`], [`crate::session`]) are fully mock-tested.

use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use crate::error::AgentError;
use crate::protocol::{encode_failure, frame, parse_request, read_frame};
use crate::session::Session;

/// Refuse to start if `$SSH_AUTH_SOCK` is already set — we never hijack or chain
/// an existing agent (decision Q5). The caller prints the guidance carried by
/// [`AgentError::AuthSockAlreadySet`].
pub fn ensure_no_existing_agent() -> Result<(), AgentError> {
    if let Some(sock) = std::env::var_os("SSH_AUTH_SOCK") {
        return Err(AgentError::AuthSockAlreadySet(
            sock.to_string_lossy().into_owned(),
        ));
    }
    Ok(())
}

/// Bind the agent socket at `path` (mode `0600`), removing a stale socket file
/// first. Returns the listener; the caller serves it with [`serve`].
pub fn bind(path: &Path) -> Result<UnixListener, AgentError> {
    // Remove a leftover socket from a previous run (a path that exists but has
    // no live listener). We only ever remove a socket file, never a regular file.
    if path.exists() {
        let is_socket = std::fs::symlink_metadata(path)
            .map(|m| {
                use std::os::unix::fs::FileTypeExt;
                m.file_type().is_socket()
            })
            .unwrap_or(false);
        if is_socket {
            let _ = std::fs::remove_file(path);
        } else {
            return Err(AgentError::Socket(format!(
                "{} exists and is not a socket — refusing to overwrite",
                path.display()
            )));
        }
    }
    let listener = UnixListener::bind(path)
        .map_err(|e| AgentError::Socket(format!("bind {}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| AgentError::Socket(format!("chmod {}: {e}", path.display())))?;
    }
    Ok(listener)
}

/// A reasonable default socket path under the vault root: `<root>/agent.sock`.
/// (The vault root is already `0700`, so the socket inherits a private parent.)
pub fn default_socket_path(root: &Path) -> PathBuf {
    root.join("agent.sock")
}

/// Serve the agent in the **foreground** until the listener is closed or an
/// unrecoverable error occurs. Each accepted connection is handled to completion
/// (one request → one reply, looping until the peer closes). Per-connection
/// errors are isolated: a malformed frame answers `SSH_AGENT_FAILURE` and the
/// connection continues; a transport error drops just that connection.
///
/// `make_session` is called per request to build a fresh [`Session`] view over
/// the (possibly re-read) custodied keys — so a key added/removed while the
/// daemon runs is reflected, and the confirmer/audit are the live ones.
pub fn serve<F>(listener: &UnixListener, mut make_session: F) -> Result<(), AgentError>
where
    F: FnMut() -> Result<SessionOwned, AgentError>,
{
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                if let Err(e) = handle_connection(stream, &mut make_session) {
                    // Log to stderr and keep serving — one bad peer must not take
                    // the daemon down. No key bytes are ever in `e`.
                    eprintln!("kovra ssh-agent: connection error: {e}");
                }
            }
            Err(e) => {
                eprintln!("kovra ssh-agent: accept error: {e}");
            }
        }
    }
    Ok(())
}

/// Owned session inputs, so `serve`'s closure can build a session per request
/// without lifetime entanglement with the listener loop.
pub struct SessionOwned {
    /// The custodied keys (with private halves).
    pub keys: Vec<crate::session::KeypairEntry>,
    /// The agent scope.
    pub scope: kovra_core::AgentScope,
    /// The confirmer.
    pub confirmer: Box<dyn kovra_core::Confirmer>,
    /// The audit sink.
    pub audit: Box<dyn kovra_core::AuditSink>,
    /// The clock.
    pub clock: Box<dyn kovra_core::Clock>,
    /// The confirmation timeout.
    pub confirm_timeout: std::time::Duration,
    /// The observed requesting process (I16).
    pub requesting_process: Option<String>,
}

impl SessionOwned {
    fn as_session(&self) -> Session<'_> {
        Session {
            keys: &self.keys,
            scope: &self.scope,
            confirmer: self.confirmer.as_ref(),
            audit: self.audit.as_ref(),
            clock: self.clock.as_ref(),
            confirm_timeout: self.confirm_timeout,
            requesting_process: self.requesting_process.clone(),
        }
    }
}

fn handle_connection<F>(mut stream: UnixStream, make_session: &mut F) -> Result<(), AgentError>
where
    F: FnMut() -> Result<SessionOwned, AgentError>,
{
    loop {
        let body = match read_frame(&mut stream)? {
            Some(b) => b,
            None => return Ok(()), // peer closed at a frame boundary
        };
        let reply_body = match parse_request(&body) {
            Ok(request) => {
                let owned = make_session()?;
                let session = owned.as_session();
                session.handle(&request)?
            }
            // A malformed/unknown frame is answered with FAILURE, not a close —
            // matches the fuzz-target contract (never panic, always a valid reply).
            Err(_) => encode_failure(),
        };
        stream.write_all(&frame(&reply_body))?;
        stream.flush()?;
    }
}

/// Remove the socket file on shutdown (best-effort). Idempotent.
pub fn cleanup(path: &Path) {
    let _ = std::fs::remove_file(path);
}
