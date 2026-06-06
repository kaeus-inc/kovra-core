//! The Wrapper (spec §5) — `kovra run`'s engine.
//!
//! Ties the layers together for a single launch:
//! 1. **Resolve** the `.env.refs` (L4) into concrete values — the resolver does
//!    *not* confirm or gate; that is this module's job.
//! 2. Compute the two **independent** injection gates (KOV-25): the
//!    **allowlist** set (I15 — `high` or `prod`, via
//!    [`kovra_core::inject_requires_allowlist`]) and the **confirm** set (I3 —
//!    `high` only, via [`kovra_core::inject_requires_confirmation`], orthogonal
//!    to environment).
//! 3. If any var is allowlist-gated, enforce the **executor allowlist** (I15):
//!    the resolved program must be a reviewed, allowlisted executable, else
//!    injection is refused before anything launches.
//! 4. If any var is confirm-gated (`high`), **confirm** through the broker (I3)
//!    with an authoritative [`ConfirmRequest`] whose `resolved_command` is the
//!    exact `argv` (I16). Denied / timed-out ⇒ refuse; the child never launches.
//!    A deliberately-downgraded `prod` secret is allowlist-gated but **not**
//!    confirm-gated — it injects without a prompt (KOV-25).
//! 5. **Inject** the resolved values into the child process environment and
//!    launch it. Nothing is written to disk (I7).
//! 6. Optionally **mask** injected vault-backed secret values in the child's
//!    output (§5.1 margin defense — a net, never a boundary; plain literals and
//!    `${env:}` passthrough are not masked).
//!
//! `inject-only` is **not** gated for confirmation: injection is its only
//! delivery, and it is not `high`. dev/test throwaway (`low`/`medium`, non-prod)
//! values inject freely with no allowlist and no prompt (§5.1).

use std::path::Path;
use std::time::Duration;

use kovra_core::{
    AuditAction, AuditEvent, AuditSink, Clock, ConfirmOutcome, ConfirmRequest, Confirmer, EnvRefs,
    EnvSource, Keyring, Origin, PROD, Registry, SecretProvider, Sensitivity,
    inject_requires_allowlist, inject_requires_confirmation, outcome_result, resolve,
};

use crate::allowlist::Allowlist;
use crate::error::WrapperError;
use crate::runner::{Command, Output, ProcessRunner};
use crate::sanitize::mask_secrets;

/// The Wrapper bundles the core dependencies (all behind traits, so the whole
/// thing is mock-testable) and the launch policy knobs.
pub struct Wrapper<'a> {
    /// The vault registry (L2) consulted during resolution.
    pub registry: &'a Registry,
    /// The keyring providing the master key (L2).
    pub keyring: &'a dyn Keyring,
    /// The execution environment source for `${env:}` passthrough (L4).
    pub env_source: &'a dyn EnvSource,
    /// The provider used to materialize references (L4/L6).
    pub provider: &'a dyn SecretProvider,
    /// The confirmation broker for `high`/`prod` injection (L3/L8).
    pub confirmer: &'a dyn Confirmer,
    /// The audit sink (L3).
    pub audit: &'a dyn AuditSink,
    /// The clock used to stamp audit events (L3).
    pub clock: &'a dyn Clock,
    /// The executor allowlist gating `high`/`prod` injection (I15, §5.1).
    pub allowlist: &'a Allowlist,
    /// The process runner that actually launches the child (or mocks it).
    pub runner: &'a dyn ProcessRunner,
    /// How long to wait for an attended confirmation before failing safe to
    /// denial (§8).
    pub confirm_timeout: Duration,
    /// Whether to mask injected values in the child's output before returning
    /// (margin defense, §5.1 — a net, never a boundary).
    pub sanitize_output: bool,
    /// The **trusted, observed** requesting-process identity for the I16 prompt
    /// (§8.3). For `kovra run` this is the observed parent of the wrapper process
    /// (who launched the run — see [`crate::observe_parent`]); for the MCP/FFI
    /// face it is the client/agent identity threaded through the trusted PyO3
    /// boundary. `None` (e.g. examples/tests) simply omits the line. Never
    /// sourced from untrusted requester text; carries no secret value (I7/I12).
    pub requesting_process: Option<String>,
}

impl Wrapper<'_> {
    /// Resolve `refs` under `env`, gate/confirm, inject, and launch
    /// `program args...`. `origin` distinguishes an agent-initiated run from a
    /// human one (weighs into the prompt, §8.3). `project_override` wins over the
    /// `.env.refs` `project =` line.
    pub fn run(
        &self,
        refs: &EnvRefs,
        env: &str,
        project_override: Option<&str>,
        program: &Path,
        args: &[String],
        origin: Origin,
    ) -> Result<Output, WrapperError> {
        // 1. Resolve (L4). `high`/`prod` are intentionally NOT confirmed here.
        let resolved = resolve(
            refs,
            env,
            self.registry,
            self.keyring,
            self.env_source,
            self.provider,
            self.audit,
            self.clock,
            origin,
            project_override,
        )?;

        // 2. Two independent injection gates (KOV-25), each from its own core
        //    predicate so they cannot drift (collect owned facts so the borrow on
        //    `resolved` ends here and the values move into the child env below):
        //    - allowlist (I15): `high` OR `prod` — the executable must be reviewed.
        //    - confirm (I3): `high` only — attended biometric prompt, orthogonal
        //      to environment (a deliberately-downgraded `prod` secret injects
        //      without a prompt, but still needs an allowlisted executable).
        let mut allowlist_gated: Vec<GatedVar> = Vec::new();
        let mut confirm_gated: Vec<GatedVar> = Vec::new();
        for v in &resolved.vars {
            let Some(coordinate) = v.coordinate.clone() else {
                continue;
            };
            let sensitivity = v.sensitivity.unwrap_or(Sensitivity::Low);
            let is_prod = v.environment == PROD;
            if inject_requires_allowlist(sensitivity, is_prod) {
                allowlist_gated.push(GatedVar {
                    coordinate: coordinate.clone(),
                    environment: v.environment.clone(),
                    sensitivity,
                });
            }
            if inject_requires_confirmation(sensitivity) {
                confirm_gated.push(GatedVar {
                    coordinate,
                    environment: v.environment.clone(),
                    sensitivity,
                });
            }
        }

        let resolved_command = render_argv(program, args);

        // 3. I15 — only a reviewed, allowlisted executable may receive high/prod
        //    injection. Refuse before confirming or launching. Environment-aware:
        //    a downgraded prod secret is still allowlist-gated (containment), even
        //    though it is no longer confirmation-gated.
        if !allowlist_gated.is_empty() && !self.allowlist.allows(program) {
            for g in &allowlist_gated {
                self.record(
                    AuditEvent::new(self.clock, AuditAction::Deny, "denied:not-allowlisted")
                        .at(&g.coordinate, &g.environment)
                        .by(origin),
                );
            }
            return Err(WrapperError::NotAllowlisted {
                program: program.display().to_string(),
            });
        }

        // 4. I3/I16 — a `high` injection blocks on the broker (sensitivity-only;
        //    orthogonal to environment). The authoritative prompt's headline is the
        //    resolved command (what varies between legit and suspicious). One
        //    scarce prompt per run.
        if !confirm_gated.is_empty() {
            let coordinates = confirm_gated
                .iter()
                .map(|g| g.coordinate.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let mut req = ConfirmRequest::new(
                coordinates,
                representative_sensitivity(&confirm_gated),
                representative_environment(&confirm_gated),
                origin,
            )
            .with_command(resolved_command);
            // The resolved command is the headline (what runs); the requesting
            // process is the observed/threaded caller (who asked). Trusted fact.
            if let Some(proc) = self.requesting_process.as_deref() {
                req = req.with_requesting_process(proc);
            }
            let outcome = self.confirmer.confirm(&req, self.confirm_timeout);

            let action = match outcome {
                ConfirmOutcome::Approved => AuditAction::Approve,
                ConfirmOutcome::Denied => AuditAction::Deny,
                ConfirmOutcome::TimedOut => AuditAction::Timeout,
            };
            for g in &confirm_gated {
                self.record(
                    AuditEvent::new(self.clock, action, outcome_result(outcome))
                        .at(&g.coordinate, &g.environment)
                        .by(origin),
                );
            }
            match outcome {
                ConfirmOutcome::Approved => {}
                ConfirmOutcome::Denied => return Err(WrapperError::ConfirmationDenied),
                ConfirmOutcome::TimedOut => return Err(WrapperError::ConfirmationTimedOut),
            }
        }

        // 5. Build the child command, moving the resolved values into the env
        //    (no copy, no disk — I7). Audit each vault-backed injection (§11), and
        //    remember which variables are vault-backed secrets (the masking net
        //    targets those, not plain literals / `${env:}` passthrough — §5.1).
        let mut env = Vec::with_capacity(resolved.vars.len());
        let mut secret_names: Vec<String> = Vec::new();
        for v in resolved.vars {
            if let Some(coordinate) = &v.coordinate {
                self.record(
                    AuditEvent::new(self.clock, AuditAction::Inject, "injected")
                        .at(coordinate, &v.environment)
                        .by(origin),
                );
                secret_names.push(v.name.clone());
            }
            env.push((v.name, v.value));
        }
        let command = Command {
            program: program.to_path_buf(),
            args: args.to_vec(),
            env,
        };

        // 6. Launch, then optionally mask the vault-backed secret values in the
        //    output (margin defense, §5.1 — a net, never a boundary).
        let mut output = self.runner.run(&command)?;
        if self.sanitize_output {
            let secrets: Vec<&[u8]> = command
                .env
                .iter()
                .filter(|(name, _)| secret_names.contains(name))
                .map(|(_, v)| v.expose())
                .collect();
            output.stdout = mask_secrets(&output.stdout, &secrets);
            output.stderr = mask_secrets(&output.stderr, &secrets);
        }
        Ok(output)
    }

    /// Record an audit event, ignoring a sink error (audit is detection, not a
    /// gate; a logging failure must not silently allow a value to flow, but
    /// neither should it abort an already-decided action — the broker decision
    /// has already been made and recorded by the caller's intent).
    fn record(&self, event: AuditEvent) {
        let _ = self.audit.record(&event);
    }
}

/// A variable that triggered the injection gate, with the facts needed for the
/// allowlist refusal, the confirmation prompt, and the audit trail.
struct GatedVar {
    coordinate: String,
    environment: String,
    sensitivity: Sensitivity,
}

/// Render the exact `argv` for the authoritative prompt (I16): program then
/// arguments, space-joined, not paraphrased.
fn render_argv(program: &Path, args: &[String]) -> String {
    let mut s = program.display().to_string();
    for a in args {
        s.push(' ');
        s.push_str(a);
    }
    s
}

/// The sensitivity to show in the prompt: `high` if any gated var is high, else
/// the first gated var's level (a deliberately-downgraded prod secret).
fn representative_sensitivity(gated: &[GatedVar]) -> Sensitivity {
    if gated.iter().any(|g| g.sensitivity == Sensitivity::High) {
        Sensitivity::High
    } else {
        gated[0].sensitivity
    }
}

/// The environment to show: `prod` (highlighted by the renderer) if any gated
/// var is prod, else the first gated var's environment.
fn representative_environment(gated: &[GatedVar]) -> String {
    if let Some(g) = gated.iter().find(|g| g.environment == PROD) {
        g.environment.clone()
    } else {
        gated[0].environment.clone()
    }
}
