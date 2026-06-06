//! The sensitivity/scope decision — the single funnel every face calls
//! (spec §3, invariants I2/I3/I5/I11/I13/I14).
//!
//! [`decide`] takes an [`AccessRequest`] and an [`AgentScope`] and returns a
//! [`Decision`]. Policy lives **here**, in the core; the CLI, Wrapper, Web UI,
//! and MCP server consume the decision and never re-derive it (spec §2, §15).
//!
//! Order of evaluation:
//! 1. **Scope first (I13).** A coordinate or operation outside scope is
//!    [`Decision::Unaddressable`] — it does not exist for the channel, it is not
//!    "denied after the fact".
//! 2. **Sensitivity × environment × surface × origin** — the §3.1 table plus
//!    I2 (`inject-only` never revealed), I11 (MCP never reveals critical), I14
//!    (`prod` plaintext into context only by a human-initiated reveal).
//! 3. **`high` ⇒ confirmation (I3).**

use crate::coordinate::{Coordinate, EnvSegment};
use crate::scope::{AgentScope, Operation, Origin, Surface};
use crate::sensitivity::Sensitivity;

/// The canonical `prod` environment name.
pub const PROD: &str = "prod";

/// The outcome of a policy decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Permitted to proceed with no interactive confirmation.
    Allow,
    /// Permitted only after attended confirmation (biometric / `kovra approve`).
    RequireConfirmation,
    /// Forbidden; carries the reason (for audit, never a value).
    Deny(DenyReason),
    /// Not addressable in this scope (I13) — distinct from `Deny`.
    Unaddressable,
}

/// Why a request was denied. Carries no secret material (I12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// `inject-only` may never be revealed (I2).
    InjectOnlyNeverRevealed,
    /// MCP may not reveal `high`/`prod`/`inject-only` plaintext (I11).
    McpCriticalForbidden,
    /// The Web UI may not render `high`/`inject-only` plaintext (I1).
    WebUiCriticalMasked,
    /// An agent may not pull `prod` plaintext into context (I14).
    ProdRevealIntoAgentContext,
    /// The secret is not marked revealable.
    NotRevealable,
}

/// A request to act on a secret. The environment is read from the coordinate.
#[derive(Debug, Clone)]
pub struct AccessRequest<'a> {
    /// The (resolved) coordinate being acted on.
    pub coordinate: &'a Coordinate,
    /// The owning project, or `None` for the global vault.
    pub project: Option<&'a str>,
    /// The secret's sensitivity.
    pub sensitivity: Sensitivity,
    /// Whether the secret is opted into reveal (the §3.1 "revealable" flag).
    ///
    /// This MUST be sourced from the **stored secret**, never from caller
    /// intent — otherwise a face could fabricate `revealable: true` and defeat
    /// I11. It is persisted on [`crate::SecretRecord`] (L9) and read back via
    /// [`crate::SecretRecord::revealable`], like `sensitivity`. The CLI reveal
    /// path leaves it `false` (it never consults the MCP-only opt-in); the FFI
    /// reveal path populates it from the record.
    pub revealable: bool,
    /// What the caller wants to do.
    pub operation: Operation,
    /// Which face is asking.
    pub surface: Surface,
    /// Who initiated it.
    pub origin: Origin,
}

impl AccessRequest<'_> {
    /// Whether the coordinate's environment is `prod` (literal). A `${ENV}`
    /// placeholder is never `prod` here — it is unaddressable until resolved.
    fn is_prod(&self) -> bool {
        matches!(&self.coordinate.environment, EnvSegment::Literal(e) if e == PROD)
    }
}

/// The policy funnel (spec §3, I2/I3/I11/I13/I14).
pub fn decide(req: &AccessRequest, scope: &AgentScope) -> Decision {
    // 1. Scope first (I13): unaddressable coordinate or ungranted operation.
    if !scope.addresses(req.coordinate, req.project) || !scope.permits(req.operation) {
        return Decision::Unaddressable;
    }

    let prod = req.is_prod();
    let high = req.sensitivity == Sensitivity::High;
    let inject_only = req.sensitivity == Sensitivity::InjectOnly;

    match req.operation {
        // Metadata never exposes a value — addressable ⇒ allowed.
        Operation::Metadata => Decision::Allow,

        // Injection moves the value *through* an operation; it never enters the
        // caller's context. `high`/`prod` injection requires confirmation
        // (I3/I15); other levels (incl. inject-only, its only delivery) proceed.
        Operation::Inject => {
            // The biometric confirmation gate is sensitivity-only (I3 — orthogonal
            // to environment). The executor-allowlist gate (I15, high/prod) is a
            // separate containment enforced by the Wrapper, not a `decide` outcome.
            if inject_requires_confirmation(req.sensitivity) {
                Decision::RequireConfirmation
            } else {
                Decision::Allow
            }
        }

        // Reveal returns plaintext *into* the caller's context — the guarded path.
        Operation::Reveal => {
            if inject_only {
                return Decision::Deny(DenyReason::InjectOnlyNeverRevealed);
            }
            match req.surface {
                // I11: MCP never reveals high/prod/inject-only; otherwise only
                // a revealable, non-prod, non-high secret.
                Surface::Mcp => {
                    if prod || high {
                        Decision::Deny(DenyReason::McpCriticalForbidden)
                    } else if !req.revealable {
                        Decision::Deny(DenyReason::NotRevealable)
                    } else {
                        Decision::Allow
                    }
                }
                // I1: the Web UI never renders high/inject-only plaintext (masked
                // + fingerprint); low/medium reveal on explicit click.
                Surface::WebUi => {
                    if high {
                        Decision::Deny(DenyReason::WebUiCriticalMasked)
                    } else {
                        Decision::Allow
                    }
                }
                // CLI is the only path that can reveal critical plaintext, and
                // only deliberately: prod into an agent's context is forbidden
                // (I14); a human prod reveal is the biometric point-reveal door;
                // any high reveal requires confirmation (I3).
                Surface::Cli => {
                    if prod {
                        match req.origin {
                            Origin::Agent => Decision::Deny(DenyReason::ProdRevealIntoAgentContext),
                            Origin::Human => Decision::RequireConfirmation,
                        }
                    } else if high {
                        Decision::RequireConfirmation
                    } else {
                        Decision::Allow
                    }
                }
            }
        }
    }
}

/// The sensitivity a newly created secret is born with (I5): `prod` ⇒ `high`,
/// otherwise the caller's chosen default. Lowering it later is a deliberate,
/// audited act (see the audit module's `SensitivityDowngrade`).
pub fn birth_sensitivity(environment: &str, non_prod_default: Sensitivity) -> Sensitivity {
    if environment == PROD {
        Sensitivity::High
    } else {
        non_prod_default
    }
}

/// I5 — whether changing sensitivity `from` → `to` is a **downgrade** (a
/// deliberate, audited act; see the audit module's `SensitivityDowngrade`).
/// Ordered by interactive-reveal strictness: `low < medium < high`, with
/// `inject-only` the strictest (never revealed). The classification lives here,
/// not in any face, so every interface records the same I5 trigger.
pub fn is_downgrade(from: Sensitivity, to: Sensitivity) -> bool {
    fn rank(s: Sensitivity) -> u8 {
        match s {
            Sensitivity::Low => 0,
            Sensitivity::Medium => 1,
            Sensitivity::High => 2,
            Sensitivity::InjectOnly => 3,
        }
    }
    rank(to) < rank(from)
}

/// I5 + I16 — whether lowering sensitivity `from` → `to` requires an **attended
/// confirmation** (Touch ID / `kovra approve`) *before* it is applied, on top of
/// the audit trail. A downgrade *from* a **critical** level (`high` or
/// `inject-only`) removes protection the secret had — it could become revealable
/// where it was not — so it is gated like any other critical delivery (I3/I16).
/// A downgrade from a non-critical level (e.g. `medium` → `low`) is audited but
/// not gated. `true` only when `from → to` is a downgrade AND `from` is `high`
/// or `inject-only`. Single-sourced here so every face gates it the same way.
pub fn downgrade_requires_confirmation(from: Sensitivity, to: Sensitivity) -> bool {
    is_downgrade(from, to) && matches!(from, Sensitivity::High | Sensitivity::InjectOnly)
}

/// A **destructive** action (delete) requires an attended broker confirmation
/// (Touch ID / `kovra approve`) only for the **critical** tier — `high` /
/// `inject-only` — i.e. exactly the secrets that already require attended
/// delivery to even *view* (I1/I2/I3). Non-critical (`low`/`medium`) secrets are
/// viewable on demand without biometrics, so their deletion is guarded by
/// lighter, surface-local friction (e.g. the Web UI's type-the-name modal)
/// rather than the broker. Single-sourced here so every face gates it the same.
pub fn delete_requires_confirmation(sensitivity: Sensitivity) -> bool {
    matches!(sensitivity, Sensitivity::High | Sensitivity::InjectOnly)
}

/// I4a — a `prod` secret may not be packaged into an artifact (§7). Enforced at
/// the package layer (L7); exposed here so the policy meaning is single-sourced.
pub fn prod_not_packageable(environment: &str) -> bool {
    environment == PROD
}

/// I4b — a `prod` secret may not be consumed via an unattended token (§7.2).
/// Enforced at L7.
pub fn prod_blocks_unattended(environment: &str) -> bool {
    environment == PROD
}

/// I4c — a `prod` coordinate may not use a `| default` fallback in resolution.
/// Enforced by the resolver (L4).
pub fn prod_forbids_fallback(environment: &str) -> bool {
    environment == PROD
}

/// I3 — injecting this value requires an **attended biometric confirmation**:
/// `true` iff the secret is `high`. **Orthogonal to environment** (I3): a
/// deliberately-downgraded `prod` secret (e.g. `low`) injects without a prompt,
/// so a downgrade is *effective* for friction — `prod` defaults to `high` at
/// birth (I5), which is what gates it by default, not the environment itself.
///
/// This is **distinct** from the executor-allowlist gate
/// ([`inject_requires_allowlist`], I15) — the allowlist remains environment-aware
/// (`high`/`prod`), but the allowlist is a config check, not a per-command prompt
/// (KOV-25 decision, §21). Single source of the confirmation trigger; the
/// `Operation::Inject` branch of [`decide`] and the Wrapper (L5) both consume it.
pub fn inject_requires_confirmation(sensitivity: Sensitivity) -> bool {
    sensitivity == Sensitivity::High
}

/// I15 — injecting this value requires the target command to be on the **executor
/// allowlist** of reviewed executables: `true` for `high` sensitivity or a `prod`
/// environment. This containment is environment-aware (a `prod` injection must
/// target a reviewed executable even when the secret was downgraded below
/// `high`), and is enforced by the Wrapper (L5) *before* launch. It is a config
/// gate, **not** a biometric prompt — the prompt is governed separately by
/// [`inject_requires_confirmation`] (I3, sensitivity-only). See the KOV-25
/// decision (§21) on why the two gates are split.
pub fn inject_requires_allowlist(sensitivity: Sensitivity, is_prod: bool) -> bool {
    sensitivity == Sensitivity::High || is_prod
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn coord(s: &str) -> Coordinate {
        Coordinate::from_str(s).unwrap()
    }

    fn req<'a>(
        c: &'a Coordinate,
        sensitivity: Sensitivity,
        operation: Operation,
        surface: Surface,
        origin: Origin,
    ) -> AccessRequest<'a> {
        AccessRequest {
            coordinate: c,
            project: None,
            sensitivity,
            revealable: false,
            operation,
            surface,
            origin,
        }
    }

    #[test]
    fn metadata_is_allowed_when_addressable() {
        let c = coord("secret:prod/db/password");
        let d = decide(
            &req(
                &c,
                Sensitivity::High,
                Operation::Metadata,
                Surface::Mcp,
                Origin::Agent,
            ),
            &AgentScope::full(),
        );
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn out_of_scope_is_unaddressable_not_denied() {
        let c = coord("secret:prod/db/password");
        let scope = AgentScope::metadata_only(); // reveal not permitted
        let d = decide(
            &req(
                &c,
                Sensitivity::Low,
                Operation::Reveal,
                Surface::Cli,
                Origin::Human,
            ),
            &scope,
        );
        assert_eq!(d, Decision::Unaddressable);
    }

    #[test]
    fn inject_only_is_never_revealed_on_any_surface() {
        let c = coord("secret:dev/app/key");
        for surface in [Surface::Cli, Surface::WebUi, Surface::Mcp] {
            let d = decide(
                &req(
                    &c,
                    Sensitivity::InjectOnly,
                    Operation::Reveal,
                    surface,
                    Origin::Human,
                ),
                &AgentScope::full(),
            );
            assert_eq!(d, Decision::Deny(DenyReason::InjectOnlyNeverRevealed));
        }
    }

    #[test]
    fn high_inject_requires_confirmation_low_does_not() {
        let c = coord("secret:dev/app/key");
        assert_eq!(
            decide(
                &req(
                    &c,
                    Sensitivity::High,
                    Operation::Inject,
                    Surface::Cli,
                    Origin::Human
                ),
                &AgentScope::full()
            ),
            Decision::RequireConfirmation
        );
        assert_eq!(
            decide(
                &req(
                    &c,
                    Sensitivity::Low,
                    Operation::Inject,
                    Surface::Cli,
                    Origin::Human
                ),
                &AgentScope::full()
            ),
            Decision::Allow
        );
    }

    #[test]
    fn mcp_never_reveals_critical() {
        let prod = coord("secret:prod/db/password");
        let dev = coord("secret:dev/app/key");
        // prod → deny
        assert_eq!(
            decide(
                &req(
                    &prod,
                    Sensitivity::Medium,
                    Operation::Reveal,
                    Surface::Mcp,
                    Origin::Agent
                ),
                &AgentScope::full()
            ),
            Decision::Deny(DenyReason::McpCriticalForbidden)
        );
        // high → deny
        assert_eq!(
            decide(
                &req(
                    &dev,
                    Sensitivity::High,
                    Operation::Reveal,
                    Surface::Mcp,
                    Origin::Agent
                ),
                &AgentScope::full()
            ),
            Decision::Deny(DenyReason::McpCriticalForbidden)
        );
        // non-prod medium but not revealable → deny
        assert_eq!(
            decide(
                &req(
                    &dev,
                    Sensitivity::Medium,
                    Operation::Reveal,
                    Surface::Mcp,
                    Origin::Agent
                ),
                &AgentScope::full()
            ),
            Decision::Deny(DenyReason::NotRevealable)
        );
        // non-prod medium revealable → allow
        let mut r = req(
            &dev,
            Sensitivity::Medium,
            Operation::Reveal,
            Surface::Mcp,
            Origin::Agent,
        );
        r.revealable = true;
        assert_eq!(decide(&r, &AgentScope::full()), Decision::Allow);
    }

    #[test]
    fn prod_reveal_into_agent_context_is_denied_human_requires_confirmation() {
        let c = coord("secret:prod/db/password");
        // I14: agent pulling prod into context → deny (even if downgraded to medium)
        assert_eq!(
            decide(
                &req(
                    &c,
                    Sensitivity::Medium,
                    Operation::Reveal,
                    Surface::Cli,
                    Origin::Agent
                ),
                &AgentScope::full()
            ),
            Decision::Deny(DenyReason::ProdRevealIntoAgentContext)
        );
        // human point reveal → confirmation (the deliberate door)
        assert_eq!(
            decide(
                &req(
                    &c,
                    Sensitivity::High,
                    Operation::Reveal,
                    Surface::Cli,
                    Origin::Human
                ),
                &AgentScope::full()
            ),
            Decision::RequireConfirmation
        );
    }

    #[test]
    fn webui_masks_high_reveals_low_medium() {
        let c = coord("secret:dev/app/key");
        assert_eq!(
            decide(
                &req(
                    &c,
                    Sensitivity::High,
                    Operation::Reveal,
                    Surface::WebUi,
                    Origin::Human
                ),
                &AgentScope::full()
            ),
            Decision::Deny(DenyReason::WebUiCriticalMasked)
        );
        assert_eq!(
            decide(
                &req(
                    &c,
                    Sensitivity::Medium,
                    Operation::Reveal,
                    Surface::WebUi,
                    Origin::Human
                ),
                &AgentScope::full()
            ),
            Decision::Allow
        );
    }

    #[test]
    fn cli_high_reveal_requires_confirmation() {
        let c = coord("secret:dev/app/key");
        assert_eq!(
            decide(
                &req(
                    &c,
                    Sensitivity::High,
                    Operation::Reveal,
                    Surface::Cli,
                    Origin::Human
                ),
                &AgentScope::full()
            ),
            Decision::RequireConfirmation
        );
    }

    #[test]
    fn birth_sensitivity_prod_is_high() {
        assert_eq!(birth_sensitivity(PROD, Sensitivity::Low), Sensitivity::High);
        assert_eq!(birth_sensitivity("dev", Sensitivity::Low), Sensitivity::Low);
        assert_eq!(
            birth_sensitivity("staging", Sensitivity::Medium),
            Sensitivity::Medium
        );
    }

    #[test]
    fn prod_structural_predicates() {
        assert!(prod_not_packageable(PROD));
        assert!(prod_blocks_unattended(PROD));
        assert!(prod_forbids_fallback(PROD));
        assert!(!prod_forbids_fallback("dev"));
    }

    #[test]
    fn downgrade_from_critical_requires_confirmation() {
        // From high: any downgrade is gated.
        assert!(downgrade_requires_confirmation(
            Sensitivity::High,
            Sensitivity::Medium
        ));
        assert!(downgrade_requires_confirmation(
            Sensitivity::High,
            Sensitivity::Low
        ));
        // From inject-only (the strictest): loosening to a revealable level is gated.
        assert!(downgrade_requires_confirmation(
            Sensitivity::InjectOnly,
            Sensitivity::High
        ));
        assert!(downgrade_requires_confirmation(
            Sensitivity::InjectOnly,
            Sensitivity::Low
        ));
        // From a non-critical level: audited, but not gated.
        assert!(!downgrade_requires_confirmation(
            Sensitivity::Medium,
            Sensitivity::Low
        ));
        // Not a downgrade → never gated (raising, or no change).
        assert!(!downgrade_requires_confirmation(
            Sensitivity::Low,
            Sensitivity::High
        ));
        assert!(!downgrade_requires_confirmation(
            Sensitivity::High,
            Sensitivity::High
        ));
    }

    // KOV-30 — delete confirmation mirrors the reveal tier: the broker gates only
    // the critical levels (high / inject-only); low / medium are not broker-gated
    // (the Web UI guards them with a type-the-name modal instead).
    #[test]
    fn delete_requires_confirmation_for_critical_only() {
        assert!(delete_requires_confirmation(Sensitivity::High));
        assert!(delete_requires_confirmation(Sensitivity::InjectOnly));
        assert!(!delete_requires_confirmation(Sensitivity::Medium));
        assert!(!delete_requires_confirmation(Sensitivity::Low));
    }

    #[test]
    fn downgrade_detection_follows_reveal_strictness() {
        assert!(is_downgrade(Sensitivity::High, Sensitivity::Medium));
        assert!(is_downgrade(Sensitivity::High, Sensitivity::Low));
        assert!(is_downgrade(Sensitivity::Medium, Sensitivity::Low));
        assert!(!is_downgrade(Sensitivity::Low, Sensitivity::High));
        assert!(!is_downgrade(Sensitivity::High, Sensitivity::High));
        // inject-only is the strictest: tightening to it is not a downgrade;
        // loosening from it to a revealable level is.
        assert!(!is_downgrade(Sensitivity::High, Sensitivity::InjectOnly));
        assert!(is_downgrade(Sensitivity::InjectOnly, Sensitivity::High));
    }

    // I3 (KOV-25): the biometric confirmation gate is SENSITIVITY-ONLY — `high`
    // is gated, everything else is not, regardless of environment. A deliberately
    // downgraded `prod` secret therefore injects without a prompt (the downgrade
    // is effective); `prod` is gated by default only because it is born `high`.
    #[test]
    fn inject_confirmation_is_sensitivity_only() {
        assert!(inject_requires_confirmation(Sensitivity::High));
        assert!(!inject_requires_confirmation(Sensitivity::Medium));
        assert!(!inject_requires_confirmation(Sensitivity::Low));
        // inject-only's normal delivery is injection — not a `high` reveal — so it
        // is not confirmation-gated.
        assert!(!inject_requires_confirmation(Sensitivity::InjectOnly));
    }

    // I15: the executor-allowlist gate stays environment-aware — `high` OR `prod`
    // injection must target a reviewed executable, even a downgraded prod secret.
    #[test]
    fn inject_allowlist_is_high_or_prod() {
        assert!(inject_requires_allowlist(Sensitivity::High, false));
        assert!(inject_requires_allowlist(Sensitivity::Medium, true));
        assert!(inject_requires_allowlist(Sensitivity::Low, true)); // downgraded prod
        assert!(inject_requires_allowlist(Sensitivity::InjectOnly, true));
        // non-prod, non-high → no allowlist requirement (throwaway dev/test, §5.1).
        assert!(!inject_requires_allowlist(Sensitivity::Low, false));
        assert!(!inject_requires_allowlist(Sensitivity::Medium, false));
    }

    // KOV-25 end-to-end at the funnel: a downgraded `prod` secret injects WITHOUT
    // confirmation (the prompt is sensitivity-only, I3).
    #[test]
    fn downgraded_prod_inject_is_allowed_without_confirmation() {
        let c = coord("secret:prod/db/password");
        // prod + low → Inject → Allow (no biometric prompt).
        assert_eq!(
            decide(
                &req(
                    &c,
                    Sensitivity::Low,
                    Operation::Inject,
                    Surface::Cli,
                    Origin::Human
                ),
                &AgentScope::full()
            ),
            Decision::Allow
        );
        // prod + high (the birth default) → still gated.
        assert_eq!(
            decide(
                &req(
                    &c,
                    Sensitivity::High,
                    Operation::Inject,
                    Surface::Cli,
                    Origin::Human
                ),
                &AgentScope::full()
            ),
            Decision::RequireConfirmation
        );
    }
}
