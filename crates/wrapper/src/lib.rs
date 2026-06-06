//! `kovra-wrapper` — the `kovra run` engine (spec §5, invariants I7/I15/I16).
//!
//! A thin face over `kovra-core`: it resolves an `.env.refs` (L4), applies the
//! core policy decision for injection (I3/I15), enforces the **executor
//! allowlist** (I15) and the **attended confirmation** (I3) for `high`/`prod`
//! values, injects the resolved values into a child process **without ever
//! touching disk** (I7), and optionally masks injected values in the child's
//! output (§5.1 margin defense — a net, never a boundary).
//!
//! All policy lives in `core`; this crate orchestrates and launches. OS-facing
//! work (spawning the child) is behind the [`ProcessRunner`] trait so the whole
//! pipeline is tested with deterministic mocks. The `kovra` CLI (L7) wires this
//! engine to the `run` subcommand.

pub mod allowlist;
pub mod caller;
pub mod error;
pub mod runner;
pub mod sanitize;
pub mod wrapper;

pub use allowlist::Allowlist;
pub use caller::observe_parent;
pub use error::WrapperError;
pub use runner::{Command, MockRunner, Output, ProcessRunner, RecordedRun, SystemRunner};
pub use sanitize::{MASK, mask_secrets};
pub use wrapper::Wrapper;
