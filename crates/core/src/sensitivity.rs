//! Sensitivity levels governing interactive value delivery (spec §3.1).
//!
//! Orthogonal to environment; `prod`'s structural invariants (I4) apply on top.

use serde::{Deserialize, Serialize};

/// How a secret's value may be delivered interactively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Sensitivity {
    /// Direct delivery + audit.
    Low,
    /// Direct delivery + audit + visible notification.
    Medium,
    /// Mandatory attended biometric confirmation before delivery.
    High,
    /// Never revealed; injected into a child process only (I2).
    InjectOnly,
}
