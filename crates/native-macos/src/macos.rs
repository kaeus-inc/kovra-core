//! macOS LocalAuthentication (`LAContext`) implementation of [`Biometric`].
//!
//! **`[host]` — not exercised by automated tests.** Showing a Touch ID dialog
//! requires real hardware and a real human finger; this path is validated by a
//! human on an M4 (KOV-15 checklist). The OS-independent contract (rendering,
//! timeout⇒deny, no-self-approve, no leak) is covered by mock-based tests in the
//! parent module and in `render`. Everything here is the thin native bridge.
//!
//! ## Threading (KOV-15 decision 1)
//!
//! `LAContext evaluatePolicy:localizedReason:reply:` is **non-blocking**: it
//! returns immediately and invokes `reply` later "on a private queue internal to
//! the framework, in an unspecified threading context" (Apple docs). It does
//! **not** require the caller to pump a runloop — the framework owns the queue
//! that fires the callback. So we deliberately do **not** build a dedicated
//! runloop pump (decision 1). Instead:
//!
//! - We call this from the CLI **main thread** (the CLI is synchronous; `kovra
//!   run` / `kovra show` block here).
//! - The reply block signals a `std::sync::mpsc` channel; we block the main
//!   thread on `recv_timeout(timeout)`.
//! - We keep a strong reference to the `LAContext` for the whole wait (Apple:
//!   "keep a strong reference while evaluation is in progress").
//! - On `recv_timeout` elapsing we return [`ConfirmOutcome::TimedOut`] (deny, §8);
//!   the dropped context cancels the in-flight evaluation.
//!
//! The reply is an **`RcBlock`** (heap-allocated, reference-counted), not a
//! `StackBlock`: `evaluatePolicy:…:reply:` is an *escaping* async callback, so
//! the block must outlive this stack frame. On timeout we return (unwinding the
//! frame) while the framework may still hold the queued reply; a heap `RcBlock`
//! stays valid for that late call (a stack block could be a use-after-free).
//!
//! ## `extern "C"` shim (KOV-15 decision 2)
//!
//! Not needed. `objc2-local-authentication` 0.3.2 exposes `LAContext::new`,
//! `canEvaluatePolicy:`, and `evaluatePolicy:localizedReason:reply:` (with the
//! `block2` feature) — the full surface this Confirmer needs. No private shim is
//! required.

use std::sync::mpsc;
use std::time::Duration;

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};

use kovra_core::{ConfirmOutcome, ConfirmRequest};

use crate::render;

/// `LAPolicyDeviceOwnerAuthenticationWithBiometrics` — biometrics only (no
/// passcode fallback). The **default** for secret deliveries (`high` reveal /
/// inject): we want the attended *biometric* gesture (§8 / I3), not a typed
/// passcode that an agent-driven keystroke could supply. The generic, secret-
/// independent `kovra confirm` action gate opts into the password fallback via
/// [`ConfirmRequest::allow_password`] (see [`policy_for`]).
const BIOMETRICS_ONLY: LAPolicy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;

/// The `LAPolicy` to evaluate for `req`. Secret deliveries stay biometrics-only;
/// a generic action gate (`allow_password`, set only by
/// [`ConfirmRequest::for_action`]) also accepts the OS device password — still
/// attended (the user is at the keyboard) and not something the agent knows.
fn policy_for(req: &ConfirmRequest) -> LAPolicy {
    if req.allow_password {
        LAPolicy::DeviceOwnerAuthentication
    } else {
        BIOMETRICS_ONLY
    }
}

/// Cheap, dialog-free capability probe: can we evaluate the biometric policy on
/// this host right now (hardware present, user enrolled)?
///
/// `[host]` — depends on the machine. Returns `false` when biometrics is absent
/// or not enrolled, which drives the CLI's fallback to the file broker.
pub(crate) fn can_evaluate() -> bool {
    // SAFETY: `LAContext::new` and `canEvaluatePolicy:` are standard, thread-safe
    // ObjC calls with no preconditions beyond a valid context, which `new`
    // guarantees.
    unsafe {
        let ctx = LAContext::new();
        ctx.canEvaluatePolicy_error(BIOMETRICS_ONLY).is_ok()
    }
}

/// The real `LAContext`-backed biometric prompt.
pub(crate) struct MacBiometric {
    _private: (),
}

impl MacBiometric {
    pub(crate) fn new() -> Self {
        Self { _private: () }
    }

    /// Show the Touch ID dialog with the core-authored prompt text and block the
    /// (main) thread until the human decides or `timeout` elapses.
    ///
    /// `[host]` — real hardware path.
    pub(crate) fn prompt(&self, req: &ConfirmRequest, timeout: Duration) -> ConfirmOutcome {
        // I16: the dialog text is built solely from the core request.
        let reason = render::prompt_text(req);
        let reason = NSString::from_str(&reason);

        let (tx, rx) = mpsc::channel::<bool>();

        // The reply block: maps biometric success → approval. It fires on the
        // framework's private queue (not our thread); the channel hands the result
        // back to the blocked main thread. Anything that is not an explicit
        // success is a denial (fail safe, §8) — including user cancel, fallback,
        // and any LAError. We never inspect or surface a secret here (I7/I12); the
        // only inputs are the boolean and an opaque error.
        //
        // `RcBlock` (heap, refcounted) because the callback escapes this frame:
        // on timeout we return before the reply fires, and the framework's queued
        // call must still land on a valid block.
        let reply = RcBlock::new(move |success: Bool, _error: *mut NSError| {
            // Ignore send errors: if the receiver already timed out and dropped,
            // the decision no longer matters (already denied).
            let _ = tx.send(success.as_bool());
        });

        // SAFETY: `evaluatePolicy:localizedReason:reply:` requires a valid context,
        // a non-empty localized reason (we always pass one), and a sendable reply
        // block. `RcBlock` satisfies the block ABI and outlives this frame; we keep
        // `ctx` alive for the whole wait below (Apple: strong reference during
        // evaluation).
        let ctx = unsafe { LAContext::new() };
        unsafe {
            ctx.evaluatePolicy_localizedReason_reply(policy_for(req), &reason, &reply);
        }

        // Block the calling (main) thread on the reply. No runloop pump needed:
        // the callback runs on the framework queue (decision 1).
        let outcome = match rx.recv_timeout(timeout) {
            Ok(true) => ConfirmOutcome::Approved,
            Ok(false) => ConfirmOutcome::Denied,
            Err(mpsc::RecvTimeoutError::Timeout) => ConfirmOutcome::TimedOut, // §8: deny
            Err(mpsc::RecvTimeoutError::Disconnected) => ConfirmOutcome::Denied,
        };

        // Explicitly hold the context until here so the evaluation is not canceled
        // by an early drop; on timeout, dropping it now cancels the in-flight prompt.
        keep_alive(ctx);
        outcome
    }
}

/// Hold a value until this call returns; documents the "keep `LAContext` alive
/// during evaluation" requirement at the use site.
#[inline]
fn keep_alive<T>(_v: Retained<T>) {}
