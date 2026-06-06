//! `kovra-native-macos` — the macOS Touch ID [`Confirmer`] (spec §8, §14.1; L8
//! `[host]`).
//!
//! This crate is the **native half** of the confirmation broker: it renders the
//! core-authored [`ConfirmRequest`] in a macOS LocalAuthentication dialog and
//! returns [`ConfirmOutcome::Approved`] / [`ConfirmOutcome::Denied`] /
//! [`ConfirmOutcome::TimedOut`]. It is a *third* [`Confirmer`] implementation
//! beside [`kovra_core::CliApproveConfirmer`] and [`kovra_core::FileConfirmer`].
//!
//! Design constraints (immutable — see `CLAUDE.md`, spec §2):
//!
//! - **I16 — the prompt is authoritative from the core.** The native dialog
//!   *only* renders what the core put in [`ConfirmRequest`] (resolved `argv`,
//!   coordinate, sensitivity, environment, origin). It never fabricates its own
//!   prompt, and any requester-supplied free text is shown clearly segregated as
//!   untrusted. See [`render::prompt_text`].
//! - **No self-approve (§8.2).** Approval is performed by a human at the Touch ID
//!   sensor — a channel outside the model's process. The agent only *triggers*
//!   the prompt; it cannot satisfy it.
//! - **Timeout ⇒ deny (§8).** Anything that is not an explicit biometric success
//!   is a denial. A timeout is reported distinctly for audit but never delivers.
//! - **No secret value is ever rendered, logged, or returned (I7/I12).** Only the
//!   coordinate *address* and the resolved command appear in the dialog.
//!
//! ## `core` does not depend on this crate
//!
//! Trait injection points *into* core: `native-macos` depends on `kovra-core`,
//! never the reverse (spec §17). The CLI selects a [`Confirmer`] at the edge.
//!
//! ## Cross-platform
//!
//! The real LocalAuthentication binding lives under `cfg(target_os = "macos")`.
//! On every other target the crate compiles to a no-op stub whose
//! [`Biometric::prompt`] reports "unavailable" (denies) and whose
//! [`biometrics_available`] returns `false`, so the CLI auto-falls-back to the
//! file broker and the whole workspace builds on Linux CI.
//!
//! ## `[host]` validation
//!
//! The real Touch ID path (`LAContext`) is **not** exercised by automated tests —
//! it requires real hardware and a real human finger. It is validated by a human
//! on an M4 (see the crate's README / KOV-15 checklist). Automated tests here use
//! a deterministic mock [`Biometric`] and assert the OS-independent contract
//! (rendering, timeout⇒deny, no-self-approve, no leak).

use std::time::Duration;

use kovra_core::{Biometric, ConfirmOutcome, ConfirmRequest, Confirmer};

pub mod formatter;
pub mod render;

pub use formatter::DiskutilFormatter;

#[cfg(target_os = "macos")]
mod macos;

/// Whether an attended biometric prompt can actually be shown on this host
/// right now: macOS with biometrics present and enrolled. On non-macOS, or when
/// no hardware is present / the user is not enrolled, this is `false` and the
/// caller should fall back to [`kovra_core::FileConfirmer`].
///
/// This is a cheap, side-effect-free capability probe (`LAContext
/// canEvaluatePolicy:`); it does **not** show a dialog.
#[must_use]
pub fn biometrics_available() -> bool {
    #[cfg(target_os = "macos")]
    {
        macos::can_evaluate()
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// The native [`Biometric`] for this host.
///
/// On macOS this is the real `LAContext`-backed prompt (`[host]`). On other
/// targets it is a stub that always denies (biometrics is unavailable), which
/// keeps the type usable in cross-platform builds even though the CLI will never
/// select it off-macOS.
pub struct NativeBiometric {
    #[cfg(target_os = "macos")]
    inner: macos::MacBiometric,
}

impl NativeBiometric {
    /// Construct the host biometric handle.
    #[must_use]
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "macos")]
            inner: macos::MacBiometric::new(),
        }
    }
}

impl Default for NativeBiometric {
    fn default() -> Self {
        Self::new()
    }
}

impl Biometric for NativeBiometric {
    fn prompt(&self, req: &ConfirmRequest, timeout: Duration) -> ConfirmOutcome {
        #[cfg(target_os = "macos")]
        {
            self.inner.prompt(req, timeout)
        }
        #[cfg(not(target_os = "macos"))]
        {
            // No biometrics off-macOS: fail safe to denial. The CLI never selects
            // this path (it falls back to the file broker), but the trait must be
            // total.
            let _ = (req, timeout);
            ConfirmOutcome::Denied
        }
    }
}

/// A [`Confirmer`] that resolves a request through an attended biometric prompt.
///
/// This is the adapter from the OS-independent [`Confirmer`] surface (what the
/// wrapper/CLI consume) onto a [`Biometric`] implementation (the native dialog).
/// The biometric does the work; this type just maps the trait. The `B` generic
/// lets tests inject a deterministic mock [`Biometric`] without touching hardware.
pub struct BiometricConfirmer<B: Biometric = NativeBiometric> {
    biometric: B,
}

impl BiometricConfirmer<NativeBiometric> {
    /// A confirmer backed by the host's native biometric prompt.
    #[must_use]
    pub fn new() -> Self {
        Self {
            biometric: NativeBiometric::new(),
        }
    }
}

impl Default for BiometricConfirmer<NativeBiometric> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: Biometric> BiometricConfirmer<B> {
    /// A confirmer backed by an explicit [`Biometric`] (tests inject a mock).
    pub fn with_biometric(biometric: B) -> Self {
        Self { biometric }
    }
}

impl<B: Biometric> Confirmer for BiometricConfirmer<B> {
    fn confirm(&self, req: &ConfirmRequest, timeout: Duration) -> ConfirmOutcome {
        // The biometric prompt is the *only* way this resolves. There is no
        // in-process approve path (§8.2): the human authorizes at the sensor.
        self.biometric.prompt(req, timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovra_core::{Origin, Sensitivity};
    use std::cell::Cell;

    fn req() -> ConfirmRequest {
        ConfirmRequest::new("prod/db/password", Sensitivity::High, "prod", Origin::Agent)
            .with_command("/usr/bin/deploy --env prod")
    }

    /// A deterministic stand-in for the native dialog. Records that it was asked
    /// and returns a preset outcome — no hardware, no Touch ID.
    struct MockBiometric {
        outcome: ConfirmOutcome,
        prompted: Cell<u32>,
        last_text: std::cell::RefCell<Option<String>>,
    }

    impl MockBiometric {
        fn new(outcome: ConfirmOutcome) -> Self {
            Self {
                outcome,
                prompted: Cell::new(0),
                last_text: std::cell::RefCell::new(None),
            }
        }
    }

    impl Biometric for MockBiometric {
        fn prompt(&self, req: &ConfirmRequest, _timeout: Duration) -> ConfirmOutcome {
            self.prompted.set(self.prompted.get() + 1);
            // Mirror the real impl: render the authoritative text from the core
            // request (so a leak in rendering would be caught here too).
            *self.last_text.borrow_mut() = Some(render::prompt_text(req));
            self.outcome
        }
    }

    // I3: a high/prod confirmation drives the confirmer and the outcome decides
    // delivery — Approved delivers, Denied/TimedOut never do.
    #[test]
    fn i3_high_prod_drives_confirm_and_outcome_gates_delivery() {
        for outcome in [
            ConfirmOutcome::Approved,
            ConfirmOutcome::Denied,
            ConfirmOutcome::TimedOut,
        ] {
            let bio = MockBiometric::new(outcome);
            let confirmer = BiometricConfirmer::with_biometric(bio);
            let got = confirmer.confirm(&req(), Duration::from_secs(1));
            assert_eq!(got, outcome);
            assert_eq!(got.is_approved(), outcome == ConfirmOutcome::Approved);
        }
    }

    // §8: timeout fails safe to denial (is_approved() is false).
    #[test]
    fn timeout_fails_safe_to_denial() {
        let confirmer =
            BiometricConfirmer::with_biometric(MockBiometric::new(ConfirmOutcome::TimedOut));
        let got = confirmer.confirm(&req(), Duration::ZERO);
        assert_eq!(got, ConfirmOutcome::TimedOut);
        assert!(!got.is_approved());
    }

    // §8.2: the confirmer has no in-process approve method — resolution comes only
    // from the biometric (the human at the sensor). Confirming a request always
    // routes through the biometric prompt; there is no path that approves without
    // it. We assert structurally: every confirm() invokes the biometric exactly
    // once and returns precisely what it decided (no override, no self-approve).
    #[test]
    fn no_self_approve_resolution_only_via_biometric() {
        let bio = MockBiometric::new(ConfirmOutcome::Denied);
        let confirmer = BiometricConfirmer::with_biometric(bio);
        let got = confirmer.confirm(&req(), Duration::from_secs(1));
        // The only resolution is the biometric's denial — the confirmer cannot
        // turn it into an approval.
        assert_eq!(got, ConfirmOutcome::Denied);
        assert_eq!(confirmer.biometric.prompted.get(), 1);
    }

    // I7/I12: the value never reaches the confirm path. We attach a realistic
    // (fake) secret-looking string only as the *coordinate address* would never
    // contain it; assert the rendered dialog the biometric sees carries no value,
    // only the address + command.
    #[test]
    fn i7_i12_no_secret_value_in_confirm_path() {
        let bio = MockBiometric::new(ConfirmOutcome::Approved);
        let confirmer = BiometricConfirmer::with_biometric(bio);
        let _ = confirmer.confirm(&req(), Duration::from_secs(1));
        let text = confirmer.biometric.last_text.borrow().clone().unwrap();
        // The dialog contains the address (environment + secret, env prefix
        // stripped) and the command, never a value (there is no value field on
        // ConfirmRequest to begin with — this guards rendering).
        assert!(text.contains("Environment: prod"));
        assert!(text.contains("Secret: db/password"));
        assert!(text.contains("/usr/bin/deploy --env prod"));
        // No accidental value-shaped leakage.
        assert!(!text.to_lowercase().contains("secret-value"));
    }
}
