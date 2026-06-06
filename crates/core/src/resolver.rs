//! The single-pass resolver (spec §4.3).
//!
//! At launch, `resolve` turns a parsed [`EnvRefs`] contract into concrete values
//! by, per variable: substituting `${ENV}`, reading the vault through the L2
//! registry (project→global override), reading the execution environment for
//! `${env:}` passthrough, applying fallbacks (forbidden for `prod`, I4c), and
//! materializing references through a provider **once per distinct ref**.
//!
//! It returns per-variable metadata (sensitivity, environment, coordinate) but
//! does **not** itself confirm `high` secrets or apply the executor allowlist —
//! that is the Wrapper's job at injection time (L5, I15). Keeping the resolver
//! free of the broker is what lets it be tested with only mock vault + provider.

use std::collections::HashMap;

use zeroize::Zeroizing;

use crate::audit::{AuditAction, AuditEvent, AuditSink};
use crate::clock::Clock;
use crate::coordinate::{Coordinate, EnvSegment, KeyHalf};
use crate::env_source::EnvSource;
use crate::envrefs::{EnvRefs, Source};
use crate::error::CoreError;
use crate::keyring::Keyring;
use crate::policy::prod_forbids_fallback;
use crate::provider::{SecretProvider, reference_scheme};
use crate::record::SecretRecord;
use crate::registry::{Registry, Resolution, VaultOrigin};
use crate::scope::Origin;
use crate::secret::SecretValue;
use crate::sensitivity::Sensitivity;

/// A single resolved variable, ready for the Wrapper to inject. The value is a
/// [`SecretValue`] regardless of source (everything flows into a child env next).
#[derive(Debug)]
pub struct ResolvedVar {
    /// The local variable name.
    pub name: String,
    /// The resolved value (zeroized, redacted `Debug`).
    pub value: SecretValue,
    /// Sensitivity of the backing secret — `Some` only for a vault coordinate;
    /// `None` for literals / env passthrough. The Wrapper uses it to decide
    /// confirmation (L5).
    pub sensitivity: Option<Sensitivity>,
    /// The environment this variable resolved under.
    pub environment: String,
    /// The canonical coordinate, `Some` only for a vault coordinate.
    pub coordinate: Option<String>,
    /// Which vault produced it (project vs global) — `Some` only for a vault hit.
    /// Carried so the Wrapper/audit (§10/§13) need not re-look-up the origin.
    pub origin: Option<VaultOrigin>,
    /// The external reference URI when the value was materialized from a
    /// reference (e.g. `azure-kv://…`), else `None`. `Some` ⇒ this was a
    /// reference (the bool the audit log's scheme field is derived from).
    pub reference: Option<String>,
}

impl ResolvedVar {
    /// A non-vault variable (literal / env passthrough / fallback): no
    /// sensitivity, no origin, not a reference.
    fn plain(
        name: &str,
        value: SecretValue,
        environment: String,
        coordinate: Option<String>,
    ) -> Self {
        Self {
            name: name.to_string(),
            value,
            sensitivity: None,
            environment,
            coordinate,
            origin: None,
            reference: None,
        }
    }
}

/// The full resolution of an `.env.refs`, in file order.
#[derive(Debug)]
pub struct Resolved {
    /// One entry per variable, in the order declared.
    pub vars: Vec<ResolvedVar>,
}

/// Run the §4.3 algorithm. `project_override` (e.g. a CLI flag) wins over the
/// `.env.refs` `project =` line.
///
/// Each distinct external reference is materialized **once per run** through
/// `provider`, and every such materialization is audited via `audit` as
/// [`AuditAction::ProviderInvocation`] (§11, I12): the event records the
/// coordinate, environment, and the URI **scheme** (`azure-kv`), and **never**
/// the materialized value. `clock` stamps the event and `origin` records who
/// drove the run. Audit is detection, not prevention — a sink failure is
/// swallowed so it never blocks a legitimate run (mirrors the Wrapper, §11).
#[allow(clippy::too_many_arguments)]
pub fn resolve(
    refs: &EnvRefs,
    env: &str,
    registry: &Registry,
    keyring: &dyn Keyring,
    env_source: &dyn EnvSource,
    provider: &dyn SecretProvider,
    audit: &dyn AuditSink,
    clock: &dyn Clock,
    origin: Origin,
    project_override: Option<&str>,
) -> Result<Resolved, CoreError> {
    let project = project_override.or(refs.project.as_deref());
    // Fetch the master key once: a passphrase-derived key would otherwise be
    // re-derived (Argon2id) on every vault lookup in the loop below.
    let master = keyring.get_master_key()?;
    // Dedup by ref: a provider is invoked once per distinct reference per run.
    let mut cache: HashMap<String, Zeroizing<Vec<u8>>> = HashMap::new();
    let mut out = Vec::with_capacity(refs.vars.len());

    for (name, source) in &refs.vars {
        let resolved = match source {
            Source::Literal(v) => {
                ResolvedVar::plain(name, SecretValue::from(v.as_str()), env.to_string(), None)
            }

            Source::EnvPassthrough { var, fallback } => {
                let value = env_source
                    .get(var)
                    .or_else(|| fallback.clone())
                    .ok_or_else(|| {
                        CoreError::EnvRefs(format!(
                            "`{name}`: env var `{var}` is unset and has no fallback"
                        ))
                    })?;
                ResolvedVar::plain(name, SecretValue::from(value), env.to_string(), None)
            }

            Source::Uri { uri, fallback } => {
                let coord = uri.parse::<Coordinate>()?.with_env(env);
                let coord_env = literal_env(&coord, name)?;

                // I4c: a `prod` coordinate may not carry a `| default` fallback.
                if prod_forbids_fallback(&coord_env) && fallback.is_some() {
                    return Err(CoreError::EnvRefs(format!(
                        "`{name}`: a `| fallback` is forbidden for prod (I4c)"
                    )));
                }

                let coordinate = coord.canonical_path()?;
                match registry.resolve_with_key(&coord, project, master.expose())? {
                    Resolution::Found {
                        record,
                        origin: vault_origin,
                    } => materialize_found(
                        name,
                        record,
                        coord_env,
                        coordinate,
                        vault_origin,
                        coord.half,
                        provider,
                        &mut cache,
                        audit,
                        clock,
                        origin,
                    )?,
                    Resolution::NotFound => match fallback {
                        Some(fb) => ResolvedVar::plain(
                            name,
                            SecretValue::from(fb.as_str()),
                            coord_env,
                            Some(coordinate),
                        ),
                        None => {
                            return Err(CoreError::EnvRefs(format!(
                                "`{name}`: coordinate `{coord}` did not resolve and has no fallback"
                            )));
                        }
                    },
                }
            }
        };
        out.push(resolved);
    }

    Ok(Resolved { vars: out })
}

/// Turn a found record into a [`ResolvedVar`], materializing a reference through
/// the provider (deduped by ref via `cache`).
#[allow(clippy::too_many_arguments)]
fn materialize_found(
    name: &str,
    record: SecretRecord,
    environment: String,
    coordinate: String,
    origin: VaultOrigin,
    half: KeyHalf,
    provider: &dyn SecretProvider,
    cache: &mut HashMap<String, Zeroizing<Vec<u8>>>,
    audit: &dyn AuditSink,
    clock: &dyn Clock,
    run_origin: Origin,
) -> Result<ResolvedVar, CoreError> {
    match record {
        SecretRecord::Literal {
            value, sensitivity, ..
        } => Ok(ResolvedVar {
            name: name.to_string(),
            value,
            sensitivity: Some(sensitivity),
            environment,
            coordinate: Some(coordinate),
            origin: Some(origin),
            reference: None,
        }),
        SecretRecord::Reference {
            reference,
            sensitivity,
            ..
        } => {
            // I8: the reference is materialized at run time, never stored.
            let bytes = match cache.get(&reference) {
                Some(b) => b.clone(),
                None => {
                    // §11/I12: audit each provider invocation BEFORE the value
                    // exists in scope — record the coordinate, environment, and
                    // the URI scheme only. The materialized value is NEVER put on
                    // the event (the result string is the scheme, not bytes).
                    let scheme = reference_scheme(&reference).unwrap_or("unknown");
                    let _ = audit.record(
                        &AuditEvent::new(
                            clock,
                            AuditAction::ProviderInvocation,
                            format!("scheme:{scheme}"),
                        )
                        .at(&coordinate, &environment)
                        .by(run_origin),
                    );
                    let materialized = provider.materialize(&reference)?;
                    let b = Zeroizing::new(materialized.expose().to_vec());
                    cache.insert(reference.clone(), b.clone());
                    b
                }
            };
            Ok(ResolvedVar {
                name: name.to_string(),
                value: SecretValue::new(bytes.to_vec()),
                sensitivity: Some(sensitivity),
                environment,
                coordinate: Some(coordinate),
                origin: Some(origin),
                reference: Some(reference),
            })
        }
        SecretRecord::Keypair {
            private,
            public,
            sensitivity,
            ..
        } => {
            // KOV-12: a keypair coordinate in `.env.refs` injects ONE half into
            // the child env (never returned to the caller/model — inject-only
            // delivery, I11/I14; never argv/disk, I6/I7). The `#public`/`#private`
            // fragment chooses which; an unspecified half defaults to **public**
            // (the safe, non-secret default).
            match half {
                KeyHalf::Private => {
                    // The private half is a private-key op: carry the record's
                    // real sensitivity and the coordinate so the Wrapper gates it
                    // exactly like any inject (broker-gated for high/prod, I3/I15).
                    let private = private.ok_or_else(|| {
                        CoreError::EnvRefs(format!(
                            "`{name}`: coordinate selects `#private` but this is a public-only keypair"
                        ))
                    })?;
                    Ok(ResolvedVar {
                        name: name.to_string(),
                        value: private,
                        sensitivity: Some(sensitivity),
                        environment,
                        coordinate: Some(coordinate),
                        origin: Some(origin),
                        reference: None,
                    })
                }
                KeyHalf::Public | KeyHalf::Unspecified => {
                    // The public half is not a secret — inject it like a plain
                    // literal: no sensitivity, no gating (even in prod), not
                    // masked. (`coordinate: None` keeps it out of the inject gate
                    // and the §5.1 masking set, matching a non-secret value.)
                    Ok(ResolvedVar::plain(
                        name,
                        SecretValue::from(public.as_str()),
                        environment,
                        None,
                    ))
                }
            }
        }
        SecretRecord::Totp { .. } => {
            // KOV-11: a TOTP code is time-varying and single-use — injecting it
            // into a long-lived child env is a footgun (it would go stale and
            // could be reused), and the seed must never be injected (I11/I14).
            // So a TOTP coordinate is NOT resolvable as an env var: it fails
            // explicitly here rather than silently emitting nothing or the seed.
            // A code is produced on demand via `kovra code`, never `.env.refs`.
            Err(CoreError::EnvRefs(format!(
                "`{name}`: coordinate `{coordinate}` is a TOTP enrollment — its code is time-varying and single-use, so it cannot be injected via `.env.refs`; produce one on demand with `kovra code`"
            )))
        }
    }
}

/// Extract the concrete environment from a coordinate, erroring if a placeholder
/// somehow survived or the environment is empty (no `--env` provided).
fn literal_env(coord: &Coordinate, name: &str) -> Result<String, CoreError> {
    match &coord.environment {
        EnvSegment::Literal(e) if !e.is_empty() => Ok(e.clone()),
        _ => Err(CoreError::EnvRefs(format!(
            "`{name}`: a `${{ENV}}` coordinate needs a non-empty --env"
        ))),
    }
}
