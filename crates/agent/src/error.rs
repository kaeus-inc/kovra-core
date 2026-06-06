//! `AgentError` — the agent face's error type (KOV-13).
//!
//! It is a *control-flow* error type: it never carries key bytes, a challenge,
//! or any secret material (I7/I12). A protocol-level fault (malformed frame,
//! unknown opcode, refused signature) is mapped by the daemon to an
//! `SSH_AGENT_FAILURE` reply, not surfaced to the peer as text.

use thiserror::Error;

/// Errors raised while serving the ssh-agent protocol.
#[derive(Debug, Error)]
pub enum AgentError {
    /// `$SSH_AUTH_SOCK` was already set — refuse-and-guide (we never hijack an
    /// existing agent, decision Q5).
    #[error(
        "$SSH_AUTH_SOCK is already set ({0}) — another ssh-agent is active.\n\
         Refusing to hijack it. To use kovra as your agent, start it in a shell \
         with no agent:\n  env -u SSH_AUTH_SOCK kovra ssh-agent\n\
         then export the printed SSH_AUTH_SOCK in the shells that should use it."
    )]
    AuthSockAlreadySet(String),

    /// The socket path could not be bound / cleaned up.
    #[error("ssh-agent socket error: {0}")]
    Socket(String),

    /// A core operation failed (no key bytes in the message).
    #[error("core error: {0}")]
    Core(#[from] kovra_core::CoreError),

    /// A wire-protocol fault (bounds/length/opcode). Mapped to `FAILURE` on the
    /// wire — never echoed to the peer. Carries only a short, value-free reason.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Generic I/O on the socket transport.
    #[error("io error: {0}")]
    Io(String),
}

impl From<std::io::Error> for AgentError {
    fn from(e: std::io::Error) -> Self {
        AgentError::Io(e.to_string())
    }
}
