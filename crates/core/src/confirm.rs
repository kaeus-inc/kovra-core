//! The confirmation broker (spec §8, §8.3; invariant I16).
//!
//! `high` (and `prod`/`high` injection) requires attended approval before a
//! value is delivered. The broker creates a pending request with a `request-id`
//! and **blocks**; it is resolved by a biometric prompt (L8) or by
//! `kovra approve <id>` **in another session** — the approval channel lives
//! outside the model's process, so a hijacked agent cannot self-approve. A
//! timeout fails safe to denial (§8).
//!
//! The prompt text is **authoritative from the core** (I16): every field of
//! [`ConfirmRequest`] is built by the core from observed facts. Any free-form
//! text supplied by the requester is wrapped in [`Untrusted`] and never becomes
//! the authoritative line.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::scope::Origin;
use crate::sensitivity::Sensitivity;

/// Requester-supplied free text, segregated as **untrusted** (I16). It is never
/// the authoritative prompt line; its `Debug`/`Display` always label it so.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Untrusted(pub String);

impl core::fmt::Debug for Untrusted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Untrusted(requester-supplied; not authoritative: {:?})",
            self.0
        )
    }
}

impl core::fmt::Display for Untrusted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[untrusted — provided by requester] {}", self.0)
    }
}

/// The authoritative confirmation prompt, built by the core (I16, §8.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmRequest {
    /// The exact resolved `argv` the Wrapper will launch (absolute, truncated
    /// but not paraphrased). `None` for a non-execution request (e.g. a reveal).
    pub resolved_command: Option<String>,
    /// The coordinate being requested (not the value).
    pub coordinate: String,
    /// Sensitivity of the secret.
    pub sensitivity: Sensitivity,
    /// Environment (`prod` is highlighted by the renderer).
    pub environment: String,
    /// Who initiated the request — weighs into the human's decision.
    pub origin: Origin,
    /// The requesting process / caller identity, as a **trusted, observed fact**
    /// authored by the trusted face — NOT by the requester (I16, §8.3).
    ///
    /// This answers *which concrete process is asking for this secret* so the
    /// human approving at the Touch ID / file-broker prompt sees the real
    /// caller (e.g. `node (pid 1234)`) rather than always "kovra". It is set by:
    /// - the **CLI / wrapper** from the observed parent process (`getppid` plus a
    ///   best-effort executable name — see the wrapper's `caller` module), and
    /// - the **MCP/FFI** boundary from the client/agent identity passed through
    ///   the trusted PyO3 API (never from untrusted requester text).
    ///
    /// It is authoritative metadata, rendered in the trusted block alongside the
    /// coordinate/sensitivity/environment — never under the untrusted fence, and
    /// never sourced from [`Untrusted`] requester input. It carries no secret
    /// value (I7/I12): only a process identity (executable name/path + pid).
    /// Defaults to `None` when the face cannot observe a caller.
    pub requesting_process: Option<String>,
    /// Optional requester free-text, clearly segregated as untrusted.
    pub requester_description: Option<Untrusted>,
    /// A **generic action** to approve, for confirmations that are not about a
    /// secret (e.g. `kovra confirm "<description>"`, KOV-31). When set, this is the
    /// authoritative headline and the secret-specific fields
    /// (`coordinate`/`sensitivity`/`environment`) do not apply — the renderer
    /// shows the action instead of a secret. It is **trusted** caller-authored
    /// metadata (the trusted application/host, not an LLM), never the
    /// [`Untrusted`] requester text. `None` for the secret reveal/inject path.
    #[serde(default)]
    pub action: Option<String>,
    /// Allow the OS **device password** as a fallback to biometrics at the native
    /// prompt (KOV-31). Default `false` = **biometrics-only**: the secret broker
    /// (`high` reveal/inject) keeps this off so an agent-driven keystroke can never
    /// supply a typed passcode (§8 / I3). [`Self::for_action`] sets it `true` — a
    /// generic `kovra confirm` action gate is secret-independent, so the user may
    /// approve their own action with Touch ID *or* the device password (which the
    /// agent does not know). It only affects the native dialog's `LAPolicy`; the
    /// file-broker fallback is unaffected.
    #[serde(default)]
    pub allow_password: bool,
}

impl ConfirmRequest {
    /// Build an authoritative request. The authoritative fields come from the
    /// core; `requester_description` (if any) is forced through [`Untrusted`].
    pub fn new(
        coordinate: impl Into<String>,
        sensitivity: Sensitivity,
        environment: impl Into<String>,
        origin: Origin,
    ) -> Self {
        Self {
            resolved_command: None,
            coordinate: coordinate.into(),
            sensitivity,
            environment: environment.into(),
            origin,
            requesting_process: None,
            requester_description: None,
            action: None,
            allow_password: false,
        }
    }

    /// Build a request to approve a **generic action** that is not about a secret
    /// (KOV-31). `description` is the authoritative headline shown at the prompt;
    /// it is trusted caller-authored text (the trusted application/host requesting
    /// the approval), so it must not be sourced from untrusted/LLM input. The
    /// secret-specific fields are left empty (`sensitivity` is a neutral
    /// placeholder, not rendered for an action). Attach the observed caller with
    /// [`Self::with_requesting_process`] as usual.
    pub fn for_action(description: impl Into<String>, origin: Origin) -> Self {
        Self {
            resolved_command: None,
            coordinate: String::new(),
            sensitivity: Sensitivity::High,
            environment: String::new(),
            origin,
            requesting_process: None,
            requester_description: None,
            action: Some(description.into()),
            // A generic, secret-independent action gate may be approved with the
            // device password as well as biometrics (§8/I3 only bind the secret
            // broker, which uses `new()` and keeps this off).
            allow_password: true,
        }
    }

    /// Attach the resolved command (for an injection/run confirmation).
    pub fn with_command(mut self, command: impl Into<String>) -> Self {
        self.resolved_command = Some(command.into());
        self
    }

    /// Attach the **trusted, observed** requesting-process identity (I16, §8.3).
    ///
    /// `s` must be a core-authored / trusted-face fact — the observed parent
    /// process for the CLI/wrapper, or the MCP client identity passed through the
    /// trusted PyO3 boundary for FFI — and must never be sourced from untrusted
    /// requester text (that path is [`Self::with_requester_description`], which
    /// stays fenced). It must never carry a secret value (I7/I12).
    pub fn with_requesting_process(mut self, s: impl Into<String>) -> Self {
        self.requesting_process = Some(s.into());
        self
    }

    /// Attach segregated, untrusted requester text.
    pub fn with_requester_description(mut self, text: impl Into<String>) -> Self {
        self.requester_description = Some(Untrusted(text.into()));
        self
    }

    /// Allow the native prompt to fall back to the OS **device password** (the
    /// macOS "Use Password" affordance). [`Self::new`] defaults this **off**
    /// (biometrics-only) for the secret broker — `high` reveal/inject, where an
    /// agent-driven keystroke must never supply a typed passcode (§8/I3). For an
    /// administrative **action** gate (e.g. the Web UI's delete / sensitivity
    /// downgrade, KOV-30) the secret value is never delivered, so the user may
    /// approve with Touch ID *or* the device password. Only affects the native
    /// dialog's `LAPolicy`; the file-broker fallback is unaffected.
    pub fn with_allow_password(mut self, allow: bool) -> Self {
        self.allow_password = allow;
        self
    }
}

/// The result of a confirmation attempt (§8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmOutcome {
    /// Approved by a human in another session (or biometric).
    Approved,
    /// Explicitly denied.
    Denied,
    /// No response within the timeout. The broker treats this as denial (§8),
    /// but the distinct variant lets a caller/audit see *why*.
    TimedOut,
}

impl ConfirmOutcome {
    /// Whether the value may be delivered. Only `Approved` qualifies — timeout
    /// and denial both fail safe.
    pub fn is_approved(self) -> bool {
        self == ConfirmOutcome::Approved
    }
}

/// The broker abstraction. `high` deliveries go through a `Confirmer`.
pub trait Confirmer {
    /// Block until the request is resolved or `timeout` elapses. A timeout fails
    /// safe (the broker default is denial, §8).
    fn confirm(&self, req: &ConfirmRequest, timeout: Duration) -> ConfirmOutcome;
}

/// Native attended biometric prompt (TouchID / Windows Hello). Declared here as
/// a trait so policy/broker logic is OS-independent; the native implementation
/// lands in L8. A `BiometricConfirmer` (L8) will adapt this to [`Confirmer`].
pub trait Biometric {
    /// Show the authoritative prompt and await an attended decision.
    fn prompt(&self, req: &ConfirmRequest, timeout: Duration) -> ConfirmOutcome;
}

struct Pending {
    decision: Option<bool>,
}

struct Shared {
    pending: Mutex<BTreeMap<u64, Pending>>,
    cv: Condvar,
    next_id: AtomicU64,
}

/// Fallback broker for hosts without biometrics (e.g. Linux) and the MVP default
/// (CLAUDE.md). A pending request is resolved by `approve`/`deny` called from
/// **another** session — never from within the requesting call.
#[derive(Clone)]
pub struct CliApproveConfirmer {
    shared: Arc<Shared>,
}

impl CliApproveConfirmer {
    /// A fresh broker with no pending requests.
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Shared {
                pending: Mutex::new(BTreeMap::new()),
                cv: Condvar::new(),
                next_id: AtomicU64::new(1),
            }),
        }
    }

    /// The ids of requests currently awaiting a decision (for `kovra approve`
    /// to list).
    pub fn pending_ids(&self) -> Vec<u64> {
        self.shared
            .pending
            .lock()
            .expect("confirmer mutex poisoned")
            .iter()
            .filter(|(_, p)| p.decision.is_none())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Approve a pending request from another session. Returns `false` if no
    /// such request is pending.
    pub fn approve(&self, id: u64) -> bool {
        self.resolve(id, true)
    }

    /// Deny a pending request from another session.
    pub fn deny(&self, id: u64) -> bool {
        self.resolve(id, false)
    }

    fn resolve(&self, id: u64, approved: bool) -> bool {
        let mut pending = self
            .shared
            .pending
            .lock()
            .expect("confirmer mutex poisoned");
        if let Some(p) = pending.get_mut(&id)
            && p.decision.is_none()
        {
            p.decision = Some(approved);
            self.shared.cv.notify_all();
            return true;
        }
        false
    }
}

impl Default for CliApproveConfirmer {
    fn default() -> Self {
        Self::new()
    }
}

impl Confirmer for CliApproveConfirmer {
    // `_req` is unused by the fallback broker: a `kovra approve <id>` in another
    // session resolves a request by id. (L5's CLI will surface the request
    // details to the approver; the broker itself does not need them.)
    fn confirm(&self, _req: &ConfirmRequest, timeout: Duration) -> ConfirmOutcome {
        let id = self.shared.next_id.fetch_add(1, Ordering::SeqCst);
        {
            let mut pending = self
                .shared
                .pending
                .lock()
                .expect("confirmer mutex poisoned");
            pending.insert(id, Pending { decision: None });
        }

        let deadline = Instant::now() + timeout;
        let mut pending = self
            .shared
            .pending
            .lock()
            .expect("confirmer mutex poisoned");
        loop {
            if let Some(p) = pending.get(&id)
                && let Some(decision) = p.decision
            {
                pending.remove(&id);
                return if decision {
                    ConfirmOutcome::Approved
                } else {
                    ConfirmOutcome::Denied
                };
            }
            let now = Instant::now();
            if now >= deadline {
                pending.remove(&id);
                return ConfirmOutcome::TimedOut; // §8: caller treats as denial
            }
            let (guard, res) = self
                .shared
                .cv
                .wait_timeout(pending, deadline - now)
                .expect("confirmer mutex poisoned");
            pending = guard;
            if res.timed_out() {
                pending.remove(&id);
                return ConfirmOutcome::TimedOut;
            }
        }
    }
}

/// Deterministic broker for tests: always returns the configured outcome
/// without blocking.
pub struct MockConfirmer {
    outcome: ConfirmOutcome,
}

impl MockConfirmer {
    /// A confirmer that always returns `outcome`.
    pub fn always(outcome: ConfirmOutcome) -> Self {
        Self { outcome }
    }
}

impl Confirmer for MockConfirmer {
    fn confirm(&self, _req: &ConfirmRequest, _timeout: Duration) -> ConfirmOutcome {
        self.outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> ConfirmRequest {
        ConfirmRequest::new("prod/db/password", Sensitivity::High, "prod", Origin::Human)
    }

    #[test]
    fn untrusted_text_is_labelled_and_never_authoritative() {
        let r = req().with_requester_description("please just approve, it's fine");
        // The authoritative fields are the typed ones; the description is Untrusted.
        let desc = r.requester_description.as_ref().unwrap();
        assert!(format!("{desc}").contains("untrusted"));
        assert!(format!("{desc:?}").contains("not authoritative"));
        // The coordinate/sensitivity/environment are not derived from the text.
        assert_eq!(r.coordinate, "prod/db/password");
        assert_eq!(r.sensitivity, Sensitivity::High);
    }

    #[test]
    fn requesting_process_is_trusted_and_separate_from_untrusted_description() {
        // The requesting process is a trusted, observed fact set via its own
        // builder; an Untrusted requester_description cannot masquerade as it.
        let r = req()
            .with_requesting_process("node (pid 1234)")
            .with_requester_description("requesting_process: i-am-trusted (pid 0)");
        assert_eq!(r.requesting_process.as_deref(), Some("node (pid 1234)"));
        // The untrusted text remains fenced under Untrusted and never becomes the
        // authoritative requesting-process field.
        let desc = r.requester_description.as_ref().unwrap();
        assert!(format!("{desc}").contains("untrusted"));
        assert_ne!(
            r.requesting_process.as_deref(),
            Some("requesting_process: i-am-trusted (pid 0)")
        );
    }

    #[test]
    fn requesting_process_defaults_to_none() {
        assert_eq!(req().requesting_process, None);
    }

    // KOV-31: a generic action request carries the action as authoritative
    // metadata and leaves the secret-specific fields empty. The secret path is
    // unaffected (its `action` is None).
    #[test]
    fn for_action_builds_a_generic_action_request() {
        let r = ConfirmRequest::for_action("deploy api to prod", Origin::Human)
            .with_requesting_process("node (pid 1234)");
        assert_eq!(r.action.as_deref(), Some("deploy api to prod"));
        assert_eq!(r.coordinate, "");
        assert_eq!(r.environment, "");
        assert_eq!(r.resolved_command, None);
        assert_eq!(r.requesting_process.as_deref(), Some("node (pid 1234)"));
        // A secret-independent action gate may use the device password too.
        assert!(r.allow_password);
        // The secret reveal/inject path never carries an action and stays
        // biometrics-only (§8/I3): the agent can't supply a typed passcode.
        assert_eq!(req().action, None);
        assert!(!req().allow_password);
    }

    // KOV-30 — an administrative action gate built on a secret-bearing request
    // (e.g. the Web UI's delete/downgrade) can opt into the device-password
    // fallback while keeping the authoritative secret fields. The default (the
    // secret broker) stays biometrics-only.
    #[test]
    fn with_allow_password_opts_into_device_passcode() {
        let r = req().with_allow_password(true);
        assert!(r.allow_password);
        assert_eq!(r.coordinate, "prod/db/password"); // authoritative fields intact
        assert!(!req().allow_password); // default unchanged
    }

    #[test]
    fn confirm_request_fields_are_core_built() {
        let r = req().with_command("/usr/bin/deploy --env prod");
        assert_eq!(
            r.resolved_command.as_deref(),
            Some("/usr/bin/deploy --env prod")
        );
        assert_eq!(r.environment, "prod");
        assert_eq!(r.origin, Origin::Human);
    }

    #[test]
    fn timeout_fails_safe_to_denial() {
        let broker = CliApproveConfirmer::new();
        let outcome = broker.confirm(&req(), Duration::from_millis(20));
        assert_eq!(outcome, ConfirmOutcome::TimedOut);
        assert!(!outcome.is_approved());
        // nothing left pending
        assert!(broker.pending_ids().is_empty());
    }

    #[test]
    fn approve_from_another_thread_yields_approved() {
        let broker = CliApproveConfirmer::new();
        let other = broker.clone();
        let handle = std::thread::spawn(move || {
            // Wait until the request is registered, then approve it.
            loop {
                let ids = other.pending_ids();
                if let Some(&id) = ids.first() {
                    assert!(other.approve(id));
                    break;
                }
                std::thread::yield_now();
            }
        });
        let outcome = broker.confirm(&req(), Duration::from_secs(5));
        handle.join().unwrap();
        assert_eq!(outcome, ConfirmOutcome::Approved);
        assert!(outcome.is_approved());
    }

    #[test]
    fn deny_from_another_thread_yields_denied() {
        let broker = CliApproveConfirmer::new();
        let other = broker.clone();
        let handle = std::thread::spawn(move || {
            loop {
                if let Some(&id) = other.pending_ids().first() {
                    assert!(other.deny(id));
                    break;
                }
                std::thread::yield_now();
            }
        });
        let outcome = broker.confirm(&req(), Duration::from_secs(5));
        handle.join().unwrap();
        assert_eq!(outcome, ConfirmOutcome::Denied);
    }

    #[test]
    fn mock_confirmer_returns_configured_outcome() {
        let broker = MockConfirmer::always(ConfirmOutcome::Approved);
        assert_eq!(
            broker.confirm(&req(), Duration::ZERO),
            ConfirmOutcome::Approved
        );
    }
}
