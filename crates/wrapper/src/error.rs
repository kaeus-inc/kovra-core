//! Wrapper errors. No variant ever carries a secret value (I12).

use kovra_core::CoreError;
use thiserror::Error;

/// Errors produced while resolving and launching a child process.
#[derive(Debug, Error)]
pub enum WrapperError {
    /// A core operation failed (resolution, vault I/O, crypto). Carries no
    /// secret material (I12).
    #[error(transparent)]
    Core(#[from] CoreError),

    /// The target command is not on the executor allowlist, so it is ineligible
    /// to receive `high`/`prod` injection (I15). Carries the program path only,
    /// never a value.
    #[error("`{program}` is not on the executor allowlist; high/prod injection refused (I15)")]
    NotAllowlisted {
        /// The rejected program path (an address, never a value).
        program: String,
    },

    /// The attended confirmation was explicitly denied; injection is refused.
    #[error("confirmation denied; high/prod injection refused")]
    ConfirmationDenied,

    /// No confirmation arrived within the timeout; the broker fails safe to
    /// denial (§8), so injection is refused.
    #[error("confirmation timed out; high/prod injection refused")]
    ConfirmationTimedOut,

    /// The child process could not be launched. Carries an OS context string
    /// only, never a value.
    #[error("failed to launch child process: {0}")]
    Spawn(String),
}
