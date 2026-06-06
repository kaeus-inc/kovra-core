//! Behavior for each `kovra` subcommand. All policy lives in `kovra-core`; these
//! handlers are thin adapters that build requests, call the core, and render
//! results — never re-deriving policy.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use kovra_core::{
    AccessRequest, AgentScope, AuditAction, AuditEvent, AuditSink, BackupKind, Clock,
    ConfirmOutcome, ConfirmRequest, Confirmer, Coordinate, Decision, EnvSegment, FileConfirmer,
    KEY_LEN, Keyring as _, MasterKey, Operation, Origin, OsKeyring, Registry, Resolution,
    SecretRecord, SecretValue, Sensitivity, Surface, SystemEnvSource, VaultOrigin,
    birth_sensitivity, decide, fingerprint, is_downgrade, seal, store,
};
use kovra_wrapper::{Allowlist, SystemRunner, Wrapper};
use zeroize::Zeroizing;

use crate::cli::SensitivityArg;
use crate::context::Ctx;
use crate::provider::build_router;
use crate::value_input::{
    prompt_with_default, read_new_passphrase, read_passphrase, read_public_text, read_secret,
};

const CONFIRM_TIMEOUT: Duration = Duration::from_secs(120);
const ALLOWLIST_FILE: &str = "allowlist";

/// A parsed, concrete coordinate plus its destructured segments and canonical
/// path — computed once. Rejects an unresolved `${ENV}` (CLI coordinates are
/// concrete).
struct Target {
    coord: Coordinate,
    env: String,
    component: String,
    key: String,
    canonical: String,
}

fn target(s: &str) -> Result<Target> {
    let coord = Coordinate::from_str(s).map_err(|e| anyhow!("{e}"))?;
    // `canonical_path` is the one validation that rejects `${ENV}`; after it
    // succeeds the environment is a literal and the fields are read directly.
    let canonical = coord
        .canonical_path()
        .map_err(|e| anyhow!("{e} (a CLI coordinate must be concrete, not ${{ENV}})"))?;
    let env = match &coord.environment {
        EnvSegment::Literal(e) => e.clone(),
        EnvSegment::Placeholder => unreachable!("canonical_path rejects placeholders"),
    };
    let component = coord.component.clone();
    let key = coord.key.clone();
    Ok(Target {
        coord,
        env,
        component,
        key,
        canonical,
    })
}

/// The target vault directory: a named project vault, else the global vault.
fn vault_dir(registry: &Registry, project: Option<&str>) -> PathBuf {
    match project {
        Some(p) => registry.project_dir(p),
        None => registry.global_dir(),
    }
}

fn record_meta(record: &SecretRecord) -> (Sensitivity, &str, &str, &str, &str, &str) {
    match record {
        SecretRecord::Literal {
            sensitivity,
            environment,
            component,
            key,
            created,
            updated,
            ..
        }
        | SecretRecord::Reference {
            sensitivity,
            environment,
            component,
            key,
            created,
            updated,
            ..
        }
        | SecretRecord::Keypair {
            sensitivity,
            environment,
            component,
            key,
            created,
            updated,
            ..
        }
        | SecretRecord::Totp {
            sensitivity,
            environment,
            component,
            key,
            created,
            updated,
            ..
        } => (*sensitivity, environment, component, key, created, updated),
    }
}

fn audit(ctx: &Ctx, action: AuditAction, result: &str, canonical: &str, env: &str) {
    let _ = ctx.audit().record(
        &AuditEvent::new(&ctx.clock, action, result)
            .at(canonical, env)
            .by(Origin::Human),
    );
}

// ───────────────────────────── init ─────────────────────────────

pub fn init(ctx: &Ctx, force: bool) -> Result<()> {
    if ctx.passphrase_mode() {
        let created = ctx.ensure_salt(force)?;
        if !created {
            bail!("already initialized (passphrase mode) — pass --force to regenerate the salt");
        }
        // Deriving the key proves the passphrase + salt unlock the vault.
        ctx.master_key()?;
        println!(
            "Initialized vault at {} (passphrase/Argon2 mode).",
            ctx.root.display()
        );
    } else {
        let keyring = ctx.keyring()?;
        if keyring.get_master_key().is_ok() && !force {
            bail!("already initialized (OS keyring) — pass --force to regenerate the master key");
        }
        let mut key = [0u8; kovra_core::KEY_LEN];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut key);
        keyring
            .set_master_key(&MasterKey::new(key))
            .context("persisting the master key to the OS keyring")?;
        println!("Initialized vault at {} (OS keyring).", ctx.root.display());
    }
    Ok(())
}

// ───────────────────────────── add / set ─────────────────────────────

#[allow(clippy::too_many_arguments)]
pub fn add(
    ctx: &Ctx,
    coordinate: &str,
    from_stdin: bool,
    sensitivity: Option<SensitivityArg>,
    description: Option<String>,
    reference: Option<String>,
    public_key: bool,
    totp: bool,
    revealable: bool,
    project: Option<&str>,
) -> Result<()> {
    ctx.require_initialized()?;
    if public_key && reference.is_some() {
        bail!("`--public-key` and `--reference` are mutually exclusive");
    }
    if totp && (reference.is_some() || public_key) {
        bail!("`--totp` is mutually exclusive with `--reference` and `--public-key`");
    }
    let Target {
        coord,
        env,
        component,
        key,
        canonical,
    } = target(coordinate)?;
    if coord.half != kovra_core::KeyHalf::Unspecified {
        bail!("`add` takes a plain coordinate, not a `#public`/`#private` half selector");
    }
    let dir = vault_dir(&ctx.registry, project);
    let master = ctx.master_key()?;

    if store::read_record(&dir, &coord, master.expose())?.is_some() {
        bail!("`{coordinate}` already exists — use `kovra set` (value) or `kovra edit` (metadata)");
    }

    let chosen = sensitivity
        .map(Sensitivity::from)
        .unwrap_or(Sensitivity::Medium);
    let born = birth_sensitivity(&env, chosen); // prod ⇒ high (I5)
    let now = ctx.now();
    let record = if totp {
        // KOV-11: custody a TOTP seed. The seed is read via stdin / hidden prompt
        // (never argv, I6) as a base32 seed or a full `otpauth://` URI; parsing
        // extracts the raw seed bytes + params (defaults SHA1/6/30, overridable
        // through the URI). The seed moves straight into a sealed SecretValue;
        // it is never printed or written to disk in plaintext (I7), and is born
        // non-revealable (I11) — `kovra code` derives the code, never the seed.
        let raw = read_secret(
            &format!("TOTP seed or otpauth:// URI for {coordinate}: "),
            from_stdin,
        )?;
        let enrollment = kovra_core::parse_seed_input(
            std::str::from_utf8(raw.expose())
                .map_err(|_| anyhow!("the TOTP seed input is not valid UTF-8"))?,
        )
        .map_err(|e| anyhow!("{e}"))?;
        SecretRecord::Totp {
            seed: SecretValue::new(enrollment.seed),
            algorithm: enrollment.params.algorithm,
            digits: enrollment.params.digits,
            period: enrollment.params.period,
            sensitivity: born,
            revealable,
            environment: env.clone(),
            component,
            key,
            description,
            created: now.clone(),
            updated: now,
        }
    } else if public_key {
        // A public-only keypair entry (KOV-12): the recipient/peer public key.
        // It holds no secret, so it is born `low` by default (still `high` if
        // prod, per I5 — though prod public keys are unusual). Read via stdin/
        // prompt to keep it off argv (I6), then validate it is a real OpenSSH key.
        let raw = read_public_text(&format!("Public key for {coordinate}: "), from_stdin)?;
        let public = raw.trim().to_string();
        let algorithm = kovra_core::public_algorithm(&public).map_err(|e| anyhow!("{e}"))?;
        let chosen = sensitivity
            .map(Sensitivity::from)
            .unwrap_or(Sensitivity::Low);
        SecretRecord::Keypair {
            algorithm,
            private: None,
            public,
            sensitivity: birth_sensitivity(&env, chosen),
            revealable,
            environment: env.clone(),
            component,
            key,
            description,
            created: now.clone(),
            updated: now,
        }
    } else {
        match reference {
            Some(reference) => SecretRecord::Reference {
                reference,
                sensitivity: born,
                revealable,
                environment: env.clone(),
                component,
                key,
                description,
                created: now.clone(),
                updated: now,
            },
            None => SecretRecord::Literal {
                value: read_secret(&format!("Value for {coordinate}: "), from_stdin)?,
                sensitivity: born,
                revealable,
                environment: env.clone(),
                component,
                key,
                description,
                created: now.clone(),
                updated: now,
            },
        }
    };
    store::write_record(&dir, &coord, &seal(&record, master.expose())?)?;
    audit(ctx, AuditAction::Create, "created", &canonical, &env);
    let born = record.sensitivity();
    println!("Added {canonical} ({born:?}).");
    Ok(())
}

pub fn set(ctx: &Ctx, coordinate: &str, from_stdin: bool, project: Option<&str>) -> Result<()> {
    ctx.require_initialized()?;
    let Target {
        coord,
        env,
        component,
        key,
        canonical,
    } = target(coordinate)?;
    let dir = vault_dir(&ctx.registry, project);
    let master = ctx.master_key()?;

    let value = read_secret(&format!("New value for {coordinate}: "), from_stdin)?;
    let now = ctx.now();

    // Preserve metadata (and created) when the secret already exists. A keypair
    // is not a plain value — its key material is created via `kovra keygen` /
    // `add --public-key`, never `set` — so overwriting one with `set` is refused.
    let (sensitivity, revealable, description, created) = match store::read_record(
        &dir,
        &coord,
        master.expose(),
    )? {
        Some(SecretRecord::Keypair { .. }) => {
            bail!(
                "`{coordinate}` is a keypair — use `kovra keygen` to regenerate it, not `kovra set`"
            );
        }
        // A TOTP enrollment is not a plain value — its seed is ingested via
        // `kovra add --totp`, never overwritten by `set` (which would silently
        // turn it into a literal and break code derivation).
        Some(SecretRecord::Totp { .. }) => {
            bail!(
                "`{coordinate}` is a TOTP enrollment — re-enroll with `kovra add --totp`, not `kovra set`"
            );
        }
        Some(SecretRecord::Literal {
            sensitivity,
            revealable,
            description,
            created,
            ..
        })
        | Some(SecretRecord::Reference {
            sensitivity,
            revealable,
            description,
            created,
            ..
        }) => (sensitivity, revealable, description, created),
        None => (
            birth_sensitivity(&env, Sensitivity::Medium),
            false,
            None,
            now.clone(),
        ),
    };

    let record = SecretRecord::Literal {
        value,
        sensitivity,
        revealable,
        environment: env.clone(),
        component,
        key,
        description,
        created,
        updated: now,
    };
    store::write_record(&dir, &coord, &seal(&record, master.expose())?)?;
    audit(ctx, AuditAction::Edit, "value-updated", &canonical, &env);
    println!("Updated {canonical}.");
    Ok(())
}

// ───────────────────────────── edit ─────────────────────────────

/// Build the attended-confirmation request for a CLI sensitivity **downgrade**
/// (KOV-26). A downgrade confirms an *action* (lowering protection) — it does not
/// deliver a secret value — so it offers the device-password fallback
/// (`allow_password`, "Use Password"), matching the Web UI's downgrade gate
/// (KOV-30/KOV-33). The secret broker (reveal/inject of `high`) stays
/// biometric-only by design (§8/I3) and is built with plain `ConfirmRequest::new`.
fn downgrade_confirm_request(
    canonical: &str,
    current: Sensitivity,
    new: Sensitivity,
    env: &str,
) -> ConfirmRequest {
    ConfirmRequest::new(canonical, current, env, Origin::Human)
        .with_command(format!(
            "kovra edit {canonical} --sensitivity {} (downgrade from {current:?})",
            format!("{new:?}").to_lowercase()
        ))
        .with_allow_password(true)
}

pub fn edit(
    ctx: &Ctx,
    coordinate: &str,
    sensitivity: Option<SensitivityArg>,
    description: Option<String>,
    reference: Option<String>,
    revealable: Option<bool>,
    project: Option<&str>,
) -> Result<()> {
    ctx.require_initialized()?;
    let Target {
        coord,
        env,
        canonical,
        ..
    } = target(coordinate)?;
    let dir = vault_dir(&ctx.registry, project);
    let master = ctx.master_key()?;

    let existing = store::read_record(&dir, &coord, master.expose())?
        .ok_or_else(|| anyhow!("`{coordinate}` not found"))?;
    let now = ctx.now();
    let current_sensitivity = record_meta(&existing).0;
    let new_sensitivity = sensitivity.map(Sensitivity::from);
    let lowered = matches!(new_sensitivity, Some(s) if is_downgrade(current_sensitivity, s));

    // I5 + I16: lowering a CRITICAL secret (a downgrade from `high`/`inject-only`)
    // removes protection it had, so it requires an attended confirmation (Touch
    // ID, or `kovra approve` via the file broker) BEFORE it is applied — gated
    // here through the same broker the rest of the CLI uses. A downgrade from a
    // non-critical level is audited but not gated.
    if let Some(new) = new_sensitivity
        && kovra_core::downgrade_requires_confirmation(current_sensitivity, new)
    {
        let broker = ctx.confirmer();
        let mut req = downgrade_confirm_request(&canonical, current_sensitivity, new, &env);
        if let Some(proc) = kovra_wrapper::observe_parent() {
            req = req.with_requesting_process(proc);
        }
        eprintln!(
            "{canonical} is {current_sensitivity:?} — lowering its sensitivity needs approval. Approve at the biometric prompt, or (file broker) run `kovra approve --list` then `kovra approve <id>` in another terminal. Waiting…"
        );
        match broker.confirm(&req, CONFIRM_TIMEOUT) {
            ConfirmOutcome::Approved => {
                audit(
                    ctx,
                    AuditAction::Approve,
                    "approved-downgrade",
                    &canonical,
                    &env,
                );
            }
            ConfirmOutcome::Denied => {
                audit(ctx, AuditAction::Deny, "denied-downgrade", &canonical, &env);
                bail!("denied — sensitivity not lowered");
            }
            ConfirmOutcome::TimedOut => {
                audit(
                    ctx,
                    AuditAction::Timeout,
                    "timeout-downgrade",
                    &canonical,
                    &env,
                );
                bail!("timed out — sensitivity not lowered");
            }
        }
    }

    let updated = apply_edits(
        existing,
        new_sensitivity,
        description,
        reference,
        revealable,
        &env,
        now,
    )?;
    store::write_record(&dir, &coord, &seal(&updated, master.expose())?)?;

    if lowered {
        // I5: lowering sensitivity is a deliberate, audited act.
        audit(
            ctx,
            AuditAction::SensitivityDowngrade,
            "downgraded",
            &canonical,
            &env,
        );
    }
    audit(ctx, AuditAction::Edit, "metadata-updated", &canonical, &env);
    println!("Edited {canonical}.");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn apply_edits(
    existing: SecretRecord,
    new_sensitivity: Option<Sensitivity>,
    new_description: Option<String>,
    new_reference: Option<String>,
    new_revealable: Option<bool>,
    env: &str,
    now: String,
) -> Result<SecretRecord> {
    match existing {
        SecretRecord::Literal {
            value,
            sensitivity,
            revealable,
            component,
            key,
            description,
            created,
            ..
        } => {
            if new_reference.is_some() {
                bail!("`--reference` edits a reference secret; this is a literal");
            }
            Ok(SecretRecord::Literal {
                value,
                sensitivity: new_sensitivity.unwrap_or(sensitivity),
                revealable: new_revealable.unwrap_or(revealable),
                environment: env.to_string(),
                component,
                key,
                description: new_description.or(description),
                created,
                updated: now,
            })
        }
        SecretRecord::Reference {
            reference,
            sensitivity,
            revealable,
            component,
            key,
            description,
            created,
            ..
        } => Ok(SecretRecord::Reference {
            reference: new_reference.unwrap_or(reference),
            sensitivity: new_sensitivity.unwrap_or(sensitivity),
            revealable: new_revealable.unwrap_or(revealable),
            environment: env.to_string(),
            component,
            key,
            description: new_description.or(description),
            created,
            updated: now,
        }),
        SecretRecord::Keypair {
            algorithm,
            private,
            public,
            sensitivity,
            revealable,
            component,
            key,
            description,
            created,
            ..
        } => {
            // A keypair's key material is immutable through `edit`; only its
            // metadata changes. `--reference` is meaningless here.
            if new_reference.is_some() {
                bail!("`--reference` edits a reference secret; this is a keypair");
            }
            Ok(SecretRecord::Keypair {
                algorithm,
                private,
                public,
                sensitivity: new_sensitivity.unwrap_or(sensitivity),
                revealable: new_revealable.unwrap_or(revealable),
                environment: env.to_string(),
                component,
                key,
                description: new_description.or(description),
                created,
                updated: now,
            })
        }
        SecretRecord::Totp {
            seed,
            algorithm,
            digits,
            period,
            sensitivity,
            revealable,
            component,
            key,
            description,
            created,
            ..
        } => {
            // A TOTP enrollment's seed/params are immutable through `edit`; only
            // its metadata changes. `--reference` is meaningless here.
            if new_reference.is_some() {
                bail!("`--reference` edits a reference secret; this is a TOTP enrollment");
            }
            Ok(SecretRecord::Totp {
                seed,
                algorithm,
                digits,
                period,
                sensitivity: new_sensitivity.unwrap_or(sensitivity),
                revealable: new_revealable.unwrap_or(revealable),
                environment: env.to_string(),
                component,
                key,
                description: new_description.or(description),
                created,
                updated: now,
            })
        }
    }
}

// ───────────────────────────── rm ─────────────────────────────

pub fn rm(ctx: &Ctx, coordinate: &str, project: Option<&str>) -> Result<()> {
    ctx.require_initialized()?;
    let Target {
        coord,
        env,
        canonical,
        ..
    } = target(coordinate)?;
    let dir = vault_dir(&ctx.registry, project);
    let master = ctx.master_key()?;

    if store::read_record(&dir, &coord, master.expose())?.is_none() {
        bail!("`{coordinate}` not found");
    }
    store::delete_record(&dir, &coord)?;
    audit(ctx, AuditAction::Delete, "deleted", &canonical, &env);
    println!("Removed {canonical}.");
    Ok(())
}

// ───────────────────────────── list ─────────────────────────────

pub fn list(
    ctx: &Ctx,
    env_filter: Option<&str>,
    component_filter: Option<&str>,
    project: Option<&str>,
) -> Result<()> {
    let master = ctx.master_key()?;
    let mut rows: Vec<Row> = Vec::new();

    let mut collect = |dir: PathBuf, origin: String| -> Result<()> {
        let outcome = store::load_all(&dir, master.expose())?;
        for (_, record) in outcome.records {
            rows.push(Row::from_record(&record, origin.clone()));
        }
        Ok(())
    };

    match project {
        Some(p) => collect(ctx.registry.project_dir(p), format!("project:{p}"))?,
        None => {
            collect(ctx.registry.global_dir(), "global".to_string())?;
            for name in ctx.registry.list_projects()? {
                collect(ctx.registry.project_dir(&name), format!("project:{name}"))?;
            }
        }
    }

    // Shadow mark: a project coordinate that also exists in the global vault.
    let global_coords: std::collections::BTreeSet<String> = rows
        .iter()
        .filter(|r| r.origin == "global")
        .map(|r| r.coordinate.clone())
        .collect();

    rows.retain(|r| {
        env_filter.is_none_or(|e| r.environment == e)
            && component_filter.is_none_or(|c| r.component == c)
    });
    rows.sort_by(|a, b| (&a.origin, &a.coordinate).cmp(&(&b.origin, &b.coordinate)));

    if rows.is_empty() {
        println!("(no secrets)");
        return Ok(());
    }
    print!("{}", render_list_table(&rows, &global_coords));
    Ok(())
}

/// Render the inventory as a terminal-width-aware table. Columns size to their
/// content and the whole table wraps to fit the terminal (falling back to a
/// sane 100-col width when stdout is not a tty, e.g. a pipe), so a long
/// `origin`/`coordinate` no longer pushes the other columns out of alignment.
fn render_list_table(rows: &[Row], global_coords: &std::collections::BTreeSet<String>) -> String {
    use comfy_table::{Cell, ContentArrangement, Table, presets::UTF8_FULL};

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(["ORIGIN", "COORDINATE", "SENSITIVITY", "MODE", "FINGERPRINT"]);

    // Match the terminal width when stdout is a tty; otherwise leave the table
    // unconstrained so piped output is stable and never truncated.
    if let Ok((cols, _)) = crossterm::terminal::size() {
        table.set_width(cols);
    }

    for r in rows {
        let fingerprint =
            if r.origin.starts_with("project:") && global_coords.contains(&r.coordinate) {
                format!("{}  *shadows global", r.fingerprint)
            } else {
                r.fingerprint.clone()
            };
        table.add_row([
            Cell::new(&r.origin),
            Cell::new(&r.coordinate),
            Cell::new(&r.sensitivity),
            Cell::new(&r.mode),
            Cell::new(fingerprint),
        ]);
    }

    format!("{table}\n")
}

struct Row {
    origin: String,
    coordinate: String,
    environment: String,
    component: String,
    sensitivity: String,
    mode: String,
    fingerprint: String,
}

impl Row {
    fn from_record(record: &SecretRecord, origin: String) -> Self {
        let (sens, env, comp, key, _, _) = record_meta(record);
        let (mode, fingerprint) = match record {
            SecretRecord::Literal { value, .. } => {
                ("literal".to_string(), fingerprint(value.expose()))
            }
            SecretRecord::Reference { reference, .. } => {
                ("reference".to_string(), format!("→ {reference}"))
            }
            SecretRecord::Keypair {
                algorithm,
                private,
                public,
                ..
            } => {
                // The keypair fingerprint is of the **public** key (public
                // material — never the private half, I12). A public-only entry
                // is marked so it is clear it holds no secret.
                let mode = if private.is_some() {
                    format!("keypair:{}", algorithm.as_str())
                } else {
                    format!("pubkey:{}", algorithm.as_str())
                };
                (mode, fingerprint(public.as_bytes()))
            }
            SecretRecord::Totp {
                algorithm,
                digits,
                period,
                ..
            } => {
                // The TOTP fingerprint is of the **non-secret params** only —
                // never the seed (I12).
                let mode = format!("totp:{}", algorithm.as_str().to_lowercase());
                (
                    mode,
                    fingerprint(
                        format!("totp:{}:{digits}:{period}", algorithm.as_str()).as_bytes(),
                    ),
                )
            }
        };
        Self {
            origin,
            coordinate: format!("{env}/{comp}/{key}"),
            environment: env.to_string(),
            component: comp.to_string(),
            sensitivity: format!("{sens:?}").to_lowercase(),
            mode,
            fingerprint,
        }
    }
}

// ───────────────────────────── show ─────────────────────────────

pub fn show(ctx: &Ctx, coordinate: &str, project: Option<&str>) -> Result<()> {
    let Target {
        coord,
        env,
        canonical,
        ..
    } = target(coordinate)?;
    let keyring = ctx.keyring()?;

    let resolution = ctx
        .registry
        .resolve(&coord, project, keyring.as_ref())
        .context("resolving the coordinate")?;
    let record = match resolution {
        Resolution::Found { record, origin } => {
            if let VaultOrigin::Project(p) = &origin {
                eprintln!("(from project vault `{p}`)");
            }
            record
        }
        Resolution::NotFound => bail!("no secret at `{coordinate}`"),
    };

    // References hold no value — show the pointer, never a fabricated value (I8).
    if let SecretRecord::Reference { reference, .. } = &record {
        println!("reference → {reference}");
        eprintln!("(value not stored; materialized at run time by the provider)");
        return Ok(());
    }
    // A keypair is custodied, not exported (KOV-12, decision §21 #32): `show`
    // renders the public key + metadata only. The private half is never printed
    // — it is used *through* `sign`/`decrypt`/`ssh-add` (I11/I14). Handle it
    // before the literal `let-else` so it cannot fall through.
    if let SecretRecord::Keypair {
        algorithm,
        private,
        public,
        ..
    } = &record
    {
        let kind = if private.is_some() {
            "keypair"
        } else {
            "public-only"
        };
        println!("{public}");
        eprintln!(
            "({kind}, {alg}) — public key shown; the private half is custodied, used via `kovra sign` / `kovra decrypt` / `kovra ssh-add`",
            alg = algorithm.as_str()
        );
        return Ok(());
    }
    // A TOTP enrollment is custodied, not exported (KOV-11): `show` renders the
    // parameters + a hint to use `kovra code`. The seed is NEVER printed — it is
    // used only *through* code derivation (I11/I14). Handle it before the literal
    // `let-else` so it cannot fall through to a value reveal.
    if let SecretRecord::Totp {
        algorithm,
        digits,
        period,
        sensitivity,
        ..
    } = &record
    {
        println!(
            "totp ({alg}, {digits} digits, {period}s period) — {sensitivity:?}",
            alg = algorithm.as_str()
        );
        eprintln!(
            "(seed custodied; never shown — run `kovra code {coordinate}` to derive the current code)"
        );
        return Ok(());
    }
    let SecretRecord::Literal {
        sensitivity, value, ..
    } = &record
    else {
        unreachable!("reference, keypair, and totp handled above");
    };
    let sensitivity = *sensitivity;

    let request = AccessRequest {
        coordinate: &coord,
        project,
        sensitivity,
        revealable: false, // CLI reveal of low/medium/high does not consult this (L9/MCP only)
        operation: Operation::Reveal,
        surface: Surface::Cli,
        origin: Origin::Human,
    };
    match decide(&request, &AgentScope::full()) {
        Decision::Allow => reveal(ctx, &canonical, &env, value),
        Decision::RequireConfirmation => {
            let broker = ctx.confirmer();
            // I16 (§8.3): show the observed parent process as the requesting
            // caller (trusted fact), not always "kovra".
            let mut req = ConfirmRequest::new(&canonical, sensitivity, &env, Origin::Human);
            if let Some(proc) = kovra_wrapper::observe_parent() {
                req = req.with_requesting_process(proc);
            }
            eprintln!(
                "{canonical} is {sensitivity:?} — approval required. Approve at the biometric prompt, or (file broker) in another terminal run `kovra approve --list`, then `kovra approve <id>`. Waiting…"
            );
            match broker.confirm(&req, CONFIRM_TIMEOUT) {
                ConfirmOutcome::Approved => reveal(ctx, &canonical, &env, value),
                ConfirmOutcome::Denied => {
                    audit(ctx, AuditAction::Deny, "denied", &canonical, &env);
                    bail!("denied — value not revealed");
                }
                ConfirmOutcome::TimedOut => {
                    audit(ctx, AuditAction::Timeout, "timeout", &canonical, &env);
                    bail!("timed out — value not revealed");
                }
            }
        }
        Decision::Deny(reason) => bail!("denied: {reason:?}"),
        Decision::Unaddressable => bail!("`{coordinate}` is not addressable"),
    }
}

/// Reveal a value to ephemeral stdout (one coordinate), audited.
fn reveal(ctx: &Ctx, canonical: &str, env: &str, value: &SecretValue) -> Result<()> {
    eprintln!("(revealing {canonical} to stdout — ephemeral, not stored)");
    std::io::stdout()
        .write_all(value.expose())
        .context("writing value to stdout")?;
    println!();
    audit(ctx, AuditAction::Reveal, "revealed", canonical, env);
    Ok(())
}

// ───────────────────────────── generate ─────────────────────────────

pub fn generate(
    ctx: &Ctx,
    coordinate: &str,
    length: usize,
    sensitivity: Option<SensitivityArg>,
    description: Option<String>,
    project: Option<&str>,
) -> Result<()> {
    ctx.require_initialized()?;
    if length == 0 {
        bail!("--length must be at least 1");
    }
    let Target {
        coord,
        env,
        component,
        key,
        canonical,
    } = target(coordinate)?;
    let dir = vault_dir(&ctx.registry, project);
    let master = ctx.master_key()?;

    if store::read_record(&dir, &coord, master.expose())?.is_some() {
        bail!("`{coordinate}` already exists");
    }

    // Random alphanumeric, born server-side, never printed (AC3).
    use rand::Rng;
    use rand::distributions::Alphanumeric;
    let generated: String = rand::rngs::OsRng
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();
    let chosen = sensitivity
        .map(Sensitivity::from)
        .unwrap_or(Sensitivity::Medium);
    let born = birth_sensitivity(&env, chosen);
    let now = ctx.now();
    let record = SecretRecord::Literal {
        value: SecretValue::from(generated),
        sensitivity: born,
        // Generated secrets are non-revealable by default; opt in later via
        // `kovra edit --revealable true` if a non-prod value must be shown.
        revealable: false,
        environment: env.clone(),
        component,
        key,
        description,
        created: now.clone(),
        updated: now,
    };
    store::write_record(&dir, &coord, &seal(&record, master.expose())?)?;
    audit(ctx, AuditAction::Create, "generated", &canonical, &env);
    println!("Generated {canonical} ({length} chars, {born:?}) — value stored, not shown.");
    Ok(())
}

// ───────────────────────────── code (TOTP, KOV-11) ─────────────────────────────

/// Print the current RFC-6238 TOTP code for a TOTP enrollment. The **derived
/// code** is printed — never the seed (I11/I14). The code is produced *through*
/// the seed, exactly like a private-key op: broker-gated for high/prod (I3/I15)
/// via the same `Operation::Inject` policy funnel, and audited (I12, no seed).
/// low/medium print directly.
pub fn code(
    ctx: &Ctx,
    coordinate: &str,
    project: Option<&str>,
    min_validity: Option<u64>,
) -> Result<()> {
    let Target {
        coord,
        env,
        canonical,
        ..
    } = target(coordinate)?;
    let keyring = ctx.keyring()?;

    let record = match ctx
        .registry
        .resolve(&coord, project, keyring.as_ref())
        .context("resolving the coordinate")?
    {
        Resolution::Found { record, origin } => {
            if let VaultOrigin::Project(p) = &origin {
                eprintln!("(from project vault `{p}`)");
            }
            record
        }
        Resolution::NotFound => bail!("no secret at `{coordinate}`"),
    };

    let (seed, algorithm, digits, period) = match &record {
        SecretRecord::Totp {
            seed,
            algorithm,
            digits,
            period,
            ..
        } => (seed, *algorithm, *digits, *period),
        _ => bail!(
            "`{coordinate}` is not a TOTP enrollment — use `kovra code` only for `--totp` secrets"
        ),
    };

    // The code is a reveal-class delivery of a derived credential, gated through
    // the SAME funnel as a private-key op (broker for high/prod, I3/I15). The
    // seed is never returned — only the short-lived code (analogous to a keypair
    // signing through its private half).
    gate_private_key_op(ctx, &coord, &record, &canonical, &env, "code")?;

    // Derive the code from the seed via the existing Clock trait (deterministic
    // under MockClock in tests). The seed is exposed only to the in-crate HOTP
    // function and never leaves this scope (I11/I14); no seed byte is printed.
    // A tiny closure re-derives at the current instant for each countdown tick;
    // the only secret-derived value that ever escapes is the short-lived code.
    let derive = |unix_secs: u64| -> Result<String> {
        kovra_core::code_at(seed.expose(), unix_secs, algorithm, digits, period)
            .map_err(|e| anyhow!("{e}"))
    };

    let now = ctx.clock.unix_secs();
    let derived = derive(now)?;
    // Audit once per `code` invocation — the op + coordinate, never the seed
    // (I12). The live view re-derives the same credential window-by-window but
    // is a single logical "show me my code" action.
    audit(ctx, AuditAction::Reveal, "code-derived", &canonical, &env);

    // `--min-validity N` (scripting) takes precedence over everything else — it
    // forces non-interactive output regardless of TTY: only the code + newline
    // to stdout, guaranteeing the returned code has MORE than N seconds of life.
    if let Some(min) = min_validity {
        return emit_min_validity(ctx, &derived, period, now, min, derive);
    }

    // Scriptability is the invariant for the non-interactive path: when stdout
    // (or stdin) is not a TTY — e.g. `TOKEN=$(kovra code x)` — print just the
    // code + newline and exit, exactly as before. The live countdown is opt-in
    // to an interactive terminal only.
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        println!("{derived}");
        return Ok(());
    }

    countdown_view(ctx, &derived, period, derive)
}

/// `--min-validity N` scripting path: emit a single code (plus newline) to stdout
/// that is guaranteed to have MORE than `N` seconds of validity. If the current
/// window already qualifies (per the pure [`returns_current`](kovra_core::returns_current)
/// decision) the `current` code is printed at once; otherwise we sleep out the
/// rest of the window — real wall-clock, a `[host]` step, never simulated through
/// `MockClock` — then re-read the clock and derive the fresh code.
///
/// No new secret is exposed: only the already-authorized derived code is printed.
/// Nothing is logged or written; the audit already happened once upstream.
fn emit_min_validity(
    ctx: &Ctx,
    current: &str,
    period: u8,
    now: u64,
    min_validity: u64,
    derive: impl Fn(u64) -> Result<String>,
) -> Result<()> {
    let period64 = (period as u64).max(1);
    // A code is valid for at most `period` seconds, so a guarantee of "more than
    // N seconds left" is impossible when N ≥ period — reject it instead of looping
    // forever / returning a code that can't satisfy the request.
    if min_validity >= period64 {
        bail!(
            "--min-validity ({min_validity}s) must be less than the TOTP period ({period64}s): a code is never valid for more than {period64}s"
        );
    }
    let remaining = kovra_core::seconds_remaining(now, period64);
    if kovra_core::returns_current(remaining, min_validity) {
        println!("{current}");
        return Ok(());
    }
    // Wait out the rest of the current window so the next code starts fresh (a
    // full `period` of validity, > N). `[host]`: real elapsed time — do not try
    // to advance a MockClock through a sleep.
    std::thread::sleep(Duration::from_secs(remaining));
    let after = ctx.clock.unix_secs();
    let next = derive(after)?;
    println!("{next}");
    Ok(())
}

/// Live countdown view for `kovra code` on an interactive terminal. Renders a
/// single status line refreshed in place (carriage return) each second with the
/// current code and the seconds left in its RFC-6238 window. The countdown does
/// NOT stop at expiry: when the window rolls over it shows the **next** code and
/// the seconds reset to the full period — it keeps going. The ONLY exit is a
/// keypress (any `KeyEvent`, which in raw mode includes Ctrl-C, delivered as an
/// event rather than a signal). On exit the terminal is restored and the final
/// code is left on its own line for scrollback.
///
/// No new secret is exposed here: the only secret-derived value rendered is the
/// already-authorized code (gated above). Each rolled window derives a fresh code
/// from the same custodied seed — never the seed itself. Nothing is logged or
/// written.
fn countdown_view(
    ctx: &Ctx,
    initial_code: &str,
    period: u8,
    derive: impl Fn(u64) -> Result<String>,
) -> Result<()> {
    use crossterm::event::{Event, poll, read};
    use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
    use std::io::Write;

    /// RAII guard: enabling raw mode is undone on every exit path — normal
    /// return, early `?` error, or panic — so the user's terminal is never left
    /// in raw mode. `Drop` disables raw mode and moves to a fresh line.
    struct RawGuard;
    impl Drop for RawGuard {
        fn drop(&mut self) {
            let _ = disable_raw_mode();
            // Move off the (in-place) status line so the final code stands alone.
            let mut err = std::io::stderr();
            let _ = write!(err, "\r\n");
            let _ = err.flush();
        }
    }

    enable_raw_mode().context("entering raw mode for the live countdown")?;
    let _guard = RawGuard;

    let period64 = (period as u64).max(1);
    let mut last_secs = ctx.clock.unix_secs();
    let mut code = initial_code.to_string();

    // Render a single status line in place. `\r` returns to column 0 and the
    // trailing spaces clear any longer prior line. stderr keeps stdout clean
    // (stdout carries only the final code, plain, for scrollback / capture).
    let render = |code: &str, remaining: u64| {
        let mut err = std::io::stderr();
        let _ = write!(
            err,
            "\r  {code}   {remaining}s left   ·  press any key to stop          "
        );
        let _ = err.flush();
    };

    render(&code, kovra_core::seconds_remaining(last_secs, period64));

    loop {
        // Poll with a short timeout so a keypress is detected promptly rather
        // than only on the 1s boundary. In raw mode Ctrl-C is delivered as a
        // KeyEvent (Char('c') + CONTROL), so ANY key event means "stop".
        if poll(Duration::from_millis(250)).unwrap_or(false) {
            match read() {
                Ok(Event::Key(_)) => break, // any key (incl. Ctrl-C) stops
                Ok(_) => {}                 // resize / focus / paste — ignore
                Err(_) => break,            // treat a read error as stop
            }
        }

        // Tick whenever the wall clock advances. We never stop on rollover: when
        // a new window begins, `derive(now)` yields the next code and
        // `seconds_remaining` resets to the full period — the loop just keeps
        // running. The only exit is the keypress handled above.
        let now = ctx.clock.unix_secs();
        if now != last_secs {
            last_secs = now;
            code = derive(now)?;
            render(&code, kovra_core::seconds_remaining(now, period64));
        }
    }

    // On exit the `RawGuard` restores the terminal and moves to a fresh line; the
    // last status line (which already shows the code) stays visible. We do NOT
    // reprint the code — the live line is enough.
    Ok(())
}

// ───────────────────────────── run ─────────────────────────────

pub fn run(
    ctx: &Ctx,
    env: &str,
    refs: Option<PathBuf>,
    project: Option<&str>,
    extra_allow: &[PathBuf],
    command: &[String],
) -> Result<()> {
    let refs_path = refs.unwrap_or_else(|| PathBuf::from(".env.refs"));
    let refs_src = std::fs::read_to_string(&refs_path)
        .with_context(|| format!("reading {}", refs_path.display()))?;
    let env_refs = kovra_core::EnvRefs::parse(&refs_src)
        .map_err(|e| anyhow!("parsing {}: {e}", refs_path.display()))?;

    let (program, args) = command
        .split_first()
        .ok_or_else(|| anyhow!("no command given after `--`"))?;
    let program = PathBuf::from(program);

    let keyring = ctx.keyring()?;
    let allowlist = load_allowlist(&ctx.root, extra_allow);
    // L6: dispatch references by scheme — Azure Key Vault via the real `az` CLI
    // (ambient identity, §6.2). An unknown scheme falls through to a clear error.
    let provider = build_router();
    let confirmer = ctx.confirmer();
    let audit_sink = ctx.audit();
    let runner = SystemRunner;
    let env_source = SystemEnvSource;

    let wrapper = Wrapper {
        registry: &ctx.registry,
        keyring: keyring.as_ref(),
        env_source: &env_source,
        provider: &provider,
        confirmer: confirmer.as_ref(),
        audit: &audit_sink,
        clock: &ctx.clock,
        allowlist: &allowlist,
        runner: &runner,
        confirm_timeout: CONFIRM_TIMEOUT,
        sanitize_output: true,
        // I16 (§8.3): the requesting process is the observed parent of this
        // `kovra run` invocation (who launched it). Trusted, observed fact.
        requesting_process: kovra_wrapper::observe_parent(),
    };

    let output = wrapper
        .run(&env_refs, env, project, &program, args, Origin::Human)
        .map_err(|e| anyhow!("{e}"))?;

    std::io::stdout().write_all(&output.stdout).ok();
    std::io::stderr().write_all(&output.stderr).ok();
    std::process::exit(output.status.unwrap_or(0));
}

fn load_allowlist(root: &Path, extra: &[PathBuf]) -> Allowlist {
    let mut allow = Allowlist::empty();
    if let Ok(content) = std::fs::read_to_string(root.join(ALLOWLIST_FILE)) {
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                allow.allow(PathBuf::from(trimmed));
            }
        }
    }
    for path in extra {
        allow.allow(path.clone());
    }
    allow
}

// ───────────────────────── package / unpack (KOV-21, L7) ─────────────────────────

/// Environment variable carrying the recipient's OpenSSH private key for
/// `unpack` when `--identity-file` is not given. Keeps the key off argv (I6).
const RECIPIENT_KEY_ENV: &str = "KOVRA_RECIPIENT_KEY";

/// `kovra package` — seal the non-prod secrets of an environment into an
/// encrypted package for a peer, plus a separate access token (L7, §7). Refuses
/// `prod` (I4a, enforced in core); references travel as pointers (I8); values
/// never touch argv (I6) and are never printed (I12).
/// Enumerate the in-scope records (env + optional components) from a vault and
/// seal them to `recipient_pubkey`, returning the sealed package, its access
/// token, and the entry count. Shared by `package` (writes to files) and
/// `exchange seal` (writes to the USB + token to stdout). I4a (`prod` refused) is
/// enforced inside `seal_package`; the value never reaches the bytes (I12).
fn seal_scope(
    ctx: &Ctx,
    env: &str,
    components: &[String],
    recipient_pubkey: &str,
    ttl: u64,
    project: Option<&str>,
) -> Result<(kovra_core::Package, kovra_core::AccessToken, usize)> {
    let dir = vault_dir(&ctx.registry, project);
    let master = ctx.master_key()?;

    // A reference contributes only its pointer; literals/keypair/totp contribute
    // their sealed material — `seal` copies the records verbatim into the (then
    // sealed) payload.
    let outcome = store::load_all(&dir, master.expose())?;
    let mut entries: Vec<SecretRecord> = outcome
        .records
        .into_iter()
        .map(|(_, record)| record)
        .filter(|r| r.environment() == env)
        .filter(|r| components.is_empty() || components.iter().any(|c| c == r.component()))
        .collect();
    entries.sort_by_key(|r| r.canonical_path());

    if entries.is_empty() {
        bail!(
            "no secrets match env `{env}`{} in the {} vault — nothing to package",
            if components.is_empty() {
                String::new()
            } else {
                format!(" / components {components:?}")
            },
            project
                .map(|p| format!("project `{p}`"))
                .unwrap_or_else(|| "global".to_string()),
        );
    }
    let count = entries.len();

    let expires_at = ctx.clock.unix_secs() + ttl;
    let payload = kovra_core::PackagePayload::new(env, ctx.now(), expires_at, entries);
    // I4a is enforced inside `seal_package`: a prod entry fails here with an
    // explicit error naming the coordinate (the value never reaches the bytes).
    let (sealed_pkg, token) =
        kovra_core::seal_package(payload, recipient_pubkey).map_err(|e| anyhow!("{e}"))?;
    Ok((sealed_pkg, token, count))
}

#[allow(clippy::too_many_arguments)]
pub fn package(
    ctx: &Ctx,
    env: &str,
    components: &[String],
    recipient: &str,
    ttl: u64,
    out: &Path,
    token_out: &Path,
    project: Option<&str>,
) -> Result<()> {
    ctx.require_initialized()?;
    let recipient_pubkey = read_recipient_pubkey(recipient)?;
    let (sealed_pkg, token, count) =
        seal_scope(ctx, env, components, &recipient_pubkey, ttl, project)?;

    write_private_artifact(out, &sealed_pkg.to_bytes())
        .with_context(|| format!("writing package to {}", out.display()))?;
    write_private_artifact(token_out, &token.to_bytes().map_err(|e| anyhow!("{e}"))?)
        .with_context(|| format!("writing access token to {}", token_out.display()))?;

    // Audit the seal — env scope + entry count, never a value (I12).
    let _ = ctx.audit().record(
        &kovra_core::AuditEvent::new(
            &ctx.clock,
            AuditAction::Package,
            format!(
                "sealed {count} entr{} (env={env})",
                if count == 1 { "y" } else { "ies" }
            ),
        )
        .at(format!("{env}/*/*"), env)
        .by(Origin::Human),
    );

    eprintln!(
        "Sealed {count} secret(s) from env `{env}` → {} (expires in {ttl}s).",
        out.display()
    );
    eprintln!(
        "Access token → {} (deliver over a SEPARATE channel; it enables unattended consumption).",
        token_out.display()
    );
    Ok(())
}

/// `kovra unpack` — open an encrypted package and import its secrets into the
/// local vault (L7, §7). Decrypts with the recipient ed25519 private key, given
/// one of two ways: a **custodied** keypair addressed by coordinate
/// (`--identity`), loaded under the master key and broker-gated for `high`
/// keystones exactly like `decrypt` (I3/I15); or an on-disk / env key
/// (`--identity-file` or `KOVRA_RECIPIENT_KEY`, never argv — I6). Either way the
/// private is used only in memory and never printed or returned to context
/// (I7/I11/I14). With a token, `high` entries are delivered unattended
/// (audited); without, each `high` entry requires an attended approval.
/// References import as pointers (I8).
#[allow(clippy::too_many_arguments)]
pub fn unpack(
    ctx: &Ctx,
    in_path: &Path,
    identity_file: Option<&Path>,
    identity_coord: Option<&str>,
    token_path: Option<&Path>,
    project: Option<&str>,
    force: bool,
) -> Result<()> {
    ctx.require_initialized()?;
    // Belt-and-suspenders: clap already rejects both via `conflicts_with`, but
    // never feed two identities to `open_attended`.
    if identity_coord.is_some() && identity_file.is_some() {
        bail!("`--identity` and `--identity-file` are mutually exclusive");
    }

    let package_bytes =
        std::fs::read(in_path).with_context(|| format!("reading package {}", in_path.display()))?;
    let package = kovra_core::Package::from_bytes(&package_bytes).map_err(|e| anyhow!("{e}"))?;

    // Factor 1: decrypt with the recipient identity (also rejects an expired
    // package). The private key is used only here and never printed (I7/I11/I14).
    // The two branches own the private differently (a borrowed `&SecretValue`
    // from the vault vs. an owned zeroizing buffer), so each computes `payload`
    // in-arm to keep the exposed plaintext borrow tightly scoped.
    let payload = match identity_coord {
        // Custodied keypair (coordinate): mirror `decrypt` — load under the
        // master key, broker-gate (I3/I15), then open. The private never leaves
        // kovra (I7).
        Some(coordinate) => {
            let (coord, record, canonical, env) = resolve_keypair(ctx, coordinate, project)?;
            let private = keypair_private(&record, &canonical)?;
            gate_private_key_op(ctx, &coord, &record, &canonical, &env, "unpack")?;
            kovra_core::open_attended(
                &package,
                std::str::from_utf8(private.expose())
                    .map_err(|_| anyhow!("stored key is not valid UTF-8"))?,
                &ctx.clock,
            )
            .map_err(|e| anyhow!("{e}"))?
        }
        // On-disk / env identity (unchanged path, I6).
        None => {
            let identity = read_identity(identity_file)?;
            kovra_core::open_attended(
                &package,
                std::str::from_utf8(&identity)
                    .map_err(|_| anyhow!("identity is not valid UTF-8"))?,
                &ctx.clock,
            )
            .map_err(|e| anyhow!("{e}"))?
        }
    };

    // Factor 2 (optional): a valid token enables unattended delivery of `high`
    // entries via TokenConfirmer; otherwise each `high` entry prompts a human.
    let token = match token_path {
        Some(p) => Some(
            kovra_core::AccessToken::from_bytes(
                &std::fs::read(p).with_context(|| format!("reading token {}", p.display()))?,
            )
            .map_err(|e| anyhow!("{e}"))?,
        ),
        None => None,
    };
    let unattended = token.is_some();
    let broker: Box<dyn Confirmer> = match &token {
        Some(t) => {
            // Validate the token up front for a clean error, and re-check I4b
            // (no prod under a token) before importing anything.
            kovra_core::verify_token(&package, &payload, t, &ctx.clock)
                .map_err(|e| anyhow!("{e}"))?;
            kovra_core::enforce_no_prod_unattended(&payload).map_err(|e| anyhow!("{e}"))?;
            Box::new(kovra_core::TokenConfirmer::new(
                &package, &payload, t, &ctx.clock,
            ))
        }
        None => ctx.confirmer(),
    };

    let dir = vault_dir(&ctx.registry, project);
    let master = ctx.master_key()?;
    let mut imported = 0usize;
    let mut skipped = 0usize;

    for entry in &payload.entries {
        let canonical = entry.canonical_path();
        let env = entry.environment().to_string();
        let coord = Coordinate::from_str(&format!("secret:{canonical}"))
            .map_err(|e| anyhow!("packaged coordinate `{canonical}` is malformed: {e}"))?;

        if store::read_record(&dir, &coord, master.expose())?.is_some() && !force {
            eprintln!("skip {canonical} — already exists (use --force to overwrite)");
            skipped += 1;
            continue;
        }

        // Gate `high`/`prod` entries through the broker (token or human), exactly
        // as the rest of the CLI gates a high delivery. prod cannot appear (I4a/
        // I4b), so in practice this gates non-prod `high` entries.
        let sensitivity = entry.sensitivity();
        // Confirmation is sensitivity-only (I3, KOV-25): a `high` entry is gated;
        // prod cannot appear at all here (I4a/I4b), so this gates `high` imports.
        let needs_confirm = kovra_core::inject_requires_confirmation(sensitivity);
        if needs_confirm {
            let mut req = ConfirmRequest::new(&canonical, sensitivity, &env, Origin::Human)
                .with_command(format!("kovra unpack (import {canonical})"));
            if let Some(proc) = kovra_wrapper::observe_parent() {
                req = req.with_requesting_process(proc);
            }
            if !unattended {
                eprintln!(
                    "{canonical} is {sensitivity:?} — approval required to import. Approve at the biometric prompt, or (file broker) run `kovra approve --list` then `kovra approve <id>` in another terminal. Waiting…"
                );
            }
            match broker.confirm(&req, CONFIRM_TIMEOUT) {
                ConfirmOutcome::Approved => {
                    if unattended {
                        audit(
                            ctx,
                            AuditAction::UnattendedDelivery,
                            "token-import",
                            &canonical,
                            &env,
                        );
                    } else {
                        audit(
                            ctx,
                            AuditAction::Approve,
                            "approved-import",
                            &canonical,
                            &env,
                        );
                    }
                }
                ConfirmOutcome::Denied => {
                    audit(ctx, AuditAction::Deny, "denied-import", &canonical, &env);
                    eprintln!("skip {canonical} — approval denied");
                    skipped += 1;
                    continue;
                }
                ConfirmOutcome::TimedOut => {
                    audit(
                        ctx,
                        AuditAction::Timeout,
                        "timeout-import",
                        &canonical,
                        &env,
                    );
                    eprintln!("skip {canonical} — approval timed out");
                    skipped += 1;
                    continue;
                }
            }
        }

        store::write_record(&dir, &coord, &seal(entry, master.expose())?)?;
        if !needs_confirm {
            audit(ctx, AuditAction::Access, "imported", &canonical, &env);
        }
        imported += 1;
    }

    println!(
        "Imported {imported} secret(s){} into the {} vault.",
        if skipped > 0 {
            format!(" ({skipped} skipped)")
        } else {
            String::new()
        },
        project
            .map(|p| format!("project `{p}`"))
            .unwrap_or_else(|| "global".to_string()),
    );
    Ok(())
}

/// Read a recipient OpenSSH public key from a file, or from stdin when `src` is
/// `-`. Trimmed of surrounding whitespace. The public key is not a secret.
fn read_recipient_pubkey(src: &str) -> Result<String> {
    let raw = if src == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)
            .context("reading recipient public key from stdin")?;
        s
    } else {
        std::fs::read_to_string(src)
            .with_context(|| format!("reading recipient public key from {src}"))?
    };
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        bail!("recipient public key is empty");
    }
    Ok(trimmed)
}

/// Read the recipient private key for `unpack`: from `--identity-file` if given,
/// else from the [`RECIPIENT_KEY_ENV`] environment variable. Never from argv
/// (I6). Held in a zeroizing buffer; never printed.
fn read_identity(identity_file: Option<&Path>) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    match identity_file {
        Some(path) => {
            let bytes = std::fs::read(path)
                .with_context(|| format!("reading identity file {}", path.display()))?;
            Ok(zeroize::Zeroizing::new(bytes))
        }
        None => match std::env::var_os(RECIPIENT_KEY_ENV) {
            Some(v) => Ok(zeroize::Zeroizing::new(v.into_encoded_bytes())),
            None => bail!(
                "no recipient identity — pass `--identity-file <key>` or set `{RECIPIENT_KEY_ENV}` (never on argv, I6)"
            ),
        },
    }
}

/// Write an artifact (package or token) to `path` at `0600`. Both are sensitive:
/// the token is a bearer credential and the package is ciphertext.
fn write_private_artifact(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// ──────────────────── exchange (USB offline kit, KOV-41) ────────────────────

/// Offer the rail-eligible external/removable devices and let the user pick one
/// (KOV-41 device picker). Used by `exchange init` when `--device` is omitted, so
/// the user does not have to hunt for a `/dev/diskN` via `diskutil list`.
/// Interactive: reads the choice from stdin.
fn choose_device(formatter: &dyn kovra_core::Formatter) -> Result<String> {
    let all = formatter.list_devices().map_err(|e| anyhow!("{e}"))?;
    let candidates = kovra_core::eligible_targets(all);
    if candidates.is_empty() {
        bail!(
            "no eligible external/removable device found — plug in a USB/SD card and retry, or pass `--device <node>`"
        );
    }
    eprintln!("Eligible devices to format (ALL DATA on the chosen one is erased):");
    for (i, d) in candidates.iter().enumerate() {
        let name = if d.name.trim().is_empty() {
            "unnamed"
        } else {
            &d.name
        };
        eprintln!(
            "  [{}] {} — \"{}\" ({}){}",
            i + 1,
            d.node,
            name,
            d.human_size(),
            if d.non_empty() { " — NOT empty" } else { "" }
        );
    }
    eprint!(
        "Choose a device to ERASE [1-{}] (or 'q' to cancel): ",
        candidates.len()
    );
    use std::io::Write as _;
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading the device choice")?;
    let choice = line.trim();
    if choice.eq_ignore_ascii_case("q") || choice.is_empty() {
        bail!("cancelled — no device chosen");
    }
    let idx: usize = choice
        .parse::<usize>()
        .ok()
        .filter(|n| *n >= 1 && *n <= candidates.len())
        .ok_or_else(|| {
            anyhow!(
                "invalid choice `{choice}` — expected 1-{}",
                candidates.len()
            )
        })?;
    Ok(candidates[idx - 1].node.clone())
}

/// `kovra exchange init [--device <node>]` — build the bootstrap USB on the
/// **origin** (KOV-41, §7.3). With no `--device`, lists the eligible
/// external/removable devices and lets you pick. Formats the chosen device
/// (broker-gated; the hard boot/internal-fixed rail and the I16 confirmation
/// live in [`kovra_core::format_removable`], KOV-40), then drops the `kovra`
/// binary and `install.sh` onto the freshly-mounted volume so the destination
/// can install kovra, create a portable passphrase vault, generate its recipient
/// identity, and write `recipient.pub` back. **macOS only**; the device is erased.
pub fn exchange_init(ctx: &Ctx, device: Option<&str>) -> Result<()> {
    ctx.require_initialized()?;
    let formatter = ctx.formatter();
    let broker = ctx.confirmer();

    // Pick the device: explicit `--device`, else the interactive chooser.
    let device = match device {
        Some(d) => d.to_string(),
        None => choose_device(formatter.as_ref())?,
    };
    let device = device.as_str();

    // Format. The destructive step is gated in the core: a boot/internal-fixed
    // disk is refused outright (no prompt), and an attended confirmation carrying
    // the I16 "ALL DATA WILL BE ERASED" headline is required before the wipe
    // (deny/timeout fail closed).
    let info = kovra_core::format_removable(
        formatter.as_ref(),
        broker.as_ref(),
        device,
        kovra_core::VOLUME_LABEL,
        CONFIRM_TIMEOUT,
    )
    .map_err(|e| anyhow!("{e}"))?;
    audit(ctx, AuditAction::Create, "exchange-init-format", device, "");

    // Populate the freshly-mounted volume with the bootstrap kit (binary +
    // install.sh). The install script never carries a secret (the destination
    // chooses its passphrase locally).
    let mount = kovra_core::mount_point();
    let exe = std::env::current_exe().context("locating the kovra binary to bundle")?;
    kovra_core::write_bootstrap(&mount, &exe, &kovra_core::render_install_script())
        .map_err(|e| anyhow!("{e}"))?;
    audit(
        ctx,
        AuditAction::Create,
        "exchange-init-bootstrap",
        device,
        "",
    );

    eprintln!(
        "Bootstrap USB ready: erased {} ({}); wrote `kovra` + `install.sh` to {}.",
        info.node,
        info.human_size(),
        mount.display()
    );
    eprintln!(
        "On the destination Mac: run `./install.sh` from the USB, then bring it back for `kovra exchange seal`."
    );
    Ok(())
}

/// `kovra exchange seal --env <e> [--component …] [--usb <path>]` — seal the
/// env's secrets to the destination's custodied recipient (KOV-42, §7.3). Reads
/// `recipient.pub` from the USB (default `/Volumes/KOVRA`), packages the scope
/// (`prod` rejected I4a), writes `package.kovra` + `unpack.sh` to the USB, and
/// emits the access token to **stdout** — the second channel, deliberately never
/// written to the USB (§7.2).
pub fn exchange_seal(
    ctx: &Ctx,
    env: &str,
    components: &[String],
    ttl: u64,
    usb: &Path,
    project: Option<&str>,
) -> Result<()> {
    ctx.require_initialized()?;
    let pub_path = usb.join(kovra_core::RECIPIENT_PUB);
    let recipient_pubkey = read_recipient_pubkey(
        pub_path
            .to_str()
            .ok_or_else(|| anyhow!("USB path is not valid UTF-8"))?,
    )
    .with_context(|| {
        format!(
            "reading {} — run `kovra exchange init` then the destination `install.sh` first",
            pub_path.display()
        )
    })?;

    let (sealed_pkg, token, count) =
        seal_scope(ctx, env, components, &recipient_pubkey, ttl, project)?;

    let pkg_path = usb.join(kovra_core::PACKAGE_FILE);
    write_private_artifact(&pkg_path, &sealed_pkg.to_bytes())
        .with_context(|| format!("writing package to {}", pkg_path.display()))?;

    // The destination open helper (no secret embedded).
    let unpack_path = usb.join(kovra_core::UNPACK_SCRIPT);
    std::fs::write(&unpack_path, kovra_core::render_unpack_script())
        .with_context(|| format!("writing {}", unpack_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&unpack_path, std::fs::Permissions::from_mode(0o755)).ok();
    }

    // Audit the seal — env scope + entry count, never a value (I12).
    let _ = ctx.audit().record(
        &kovra_core::AuditEvent::new(
            &ctx.clock,
            AuditAction::Package,
            format!(
                "exchange-sealed {count} entr{} (env={env})",
                if count == 1 { "y" } else { "ies" }
            ),
        )
        .at(format!("{env}/*/*"), env)
        .by(Origin::Human),
    );

    eprintln!(
        "Sealed {count} secret(s) from env `{env}` → {} (+ unpack.sh). Expires in {ttl}s.",
        pkg_path.display()
    );
    eprintln!(
        "Access token below — deliver it over a SEPARATE channel (NOT the USB). The destination runs `kovra exchange open` (or `./unpack.sh`)."
    );
    // The token (a bearer credential) goes to STDOUT — the out-of-band second
    // channel. It is deliberately NOT written to the USB (§7.2): holding the
    // stick is not enough, package + token are two factors over two channels.
    let mut out = std::io::stdout();
    out.write_all(&token.to_bytes().map_err(|e| anyhow!("{e}"))?)
        .context("writing the access token to stdout")?;
    out.write_all(b"\n").ok();
    Ok(())
}

/// Where the registered exchange token lives (0600). It is a bearer credential,
/// so it never touches argv and is stored owner-only under the vault root.
fn exchange_token_path(ctx: &Ctx) -> PathBuf {
    ctx.root.join("exchange").join("registered.token")
}

/// `kovra exchange register-token [--from <file>]` — register the out-of-band
/// access token so `exchange open` is a single action (KOV-43, §7.3). Reads the
/// token from `--from <file>` or **stdin** (never argv — it is a bearer
/// credential, I6), validates that it parses, and stores it owner-only at
/// `<root>/exchange/registered.token`.
pub fn exchange_register_token(ctx: &Ctx, from: Option<&Path>) -> Result<()> {
    let raw = match from {
        Some(p) => {
            std::fs::read(p).with_context(|| format!("reading token from {}", p.display()))?
        }
        None => {
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)
                .context("reading token from stdin")?;
            buf
        }
    };
    let text = String::from_utf8(raw).map_err(|_| anyhow!("token is not valid UTF-8"))?;
    let trimmed = text.trim().as_bytes();
    // Validate it really is an access token before storing (no value involved).
    kovra_core::AccessToken::from_bytes(trimmed)
        .map_err(|e| anyhow!("not a valid kovra access token: {e}"))?;

    let path = exchange_token_path(ctx);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    write_private_artifact(&path, trimmed)
        .with_context(|| format!("storing the registered token at {}", path.display()))?;
    eprintln!("Access token registered. Run `kovra exchange open` to import.");
    Ok(())
}

/// `kovra exchange open [--usb <path>] [--token <file>] [--force]` — the
/// destination one-action import (KOV-43, §7.3). Discovers `package.kovra` on the
/// USB (default `/Volumes/KOVRA`) and opens it with the custodied recipient
/// identity (KOV-39), using the registered token (or `--token`) for unattended
/// `high` entries. The registered token is consumed (deleted) after a successful
/// open — it is single-use, bound to this package.
pub fn exchange_open(
    ctx: &Ctx,
    usb: &Path,
    token: Option<&Path>,
    project: Option<&str>,
    force: bool,
) -> Result<()> {
    ctx.require_initialized()?;
    let pkg = usb.join(kovra_core::PACKAGE_FILE);
    if !pkg.exists() {
        bail!(
            "no {} on {} — is the exchange USB mounted? (the origin runs `kovra exchange seal` first)",
            kovra_core::PACKAGE_FILE,
            usb.display()
        );
    }

    // Token: an explicit `--token` wins; otherwise the registered one, if any.
    let registered = exchange_token_path(ctx);
    let token_path: Option<PathBuf> = match token {
        Some(t) => Some(t.to_path_buf()),
        None if registered.exists() => Some(registered.clone()),
        None => None,
    };

    unpack(
        ctx,
        &pkg,
        None,
        Some(kovra_core::RECIPIENT_COORDINATE),
        token_path.as_deref(),
        project,
        force,
    )?;

    // Consume the registered token on success — it is single-use and bound to
    // this package (the explicit `--token` file is the caller's, left alone).
    if token.is_none() && registered.exists() {
        let _ = std::fs::remove_file(&registered);
    }
    Ok(())
}

// ───────────────────────────── ui (KOV-22, L10) ─────────────────────────────

/// `kovra ui` — bring up the on-demand loopback Web UI (L10, §9.3). Resolves the
/// master key from the host keyring, binds `127.0.0.1:PORT` only (I10), mints an
/// ephemeral session token, opens the browser, and serves until Ctrl-C or
/// `idle` seconds of inactivity. The UI never renders `high`/`inject-only`
/// plaintext (I1/I2) — that is enforced in the core and reveals via the CLI.
///
/// With `docker`, the UI runs in a container instead (L11) — see [`ui_docker`].
pub fn ui(
    ctx: &Ctx,
    port: u16,
    idle: u64,
    no_open: bool,
    docker: bool,
    no_confirm: bool,
) -> Result<()> {
    if docker {
        return ui_docker(ctx, port, idle, no_open, no_confirm);
    }
    ctx.require_initialized()?;
    confirm_ui_launch(ctx, no_confirm)?;
    let master = ctx.master_key()?;
    // The same broker the rest of kovra uses, handed to the server so UI-side
    // delete / sensitivity-downgrade run through it (KOV-30, I3/I5/I16).
    let confirmer: Arc<dyn Confirmer + Send + Sync> = Arc::from(ctx.confirmer());
    let state = kovra_webui::AppState::new(ctx.root.clone(), master, confirmer);
    let token = state.session_token().to_string();
    let idle = Duration::from_secs(idle);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;

    runtime.block_on(async move {
        let addr = kovra_webui::default_addr(port);
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding {addr} (is the Web UI already running?)"))?;
        let bound = listener.local_addr().context("reading the bound address")?;
        let url = format!("http://{bound}/?session={token}");
        println!("kovra ui → {url}");
        eprintln!(
            "(loopback only; ephemeral session; auto-shutdown after {}s idle or Ctrl-C)",
            idle.as_secs()
        );
        if !no_open {
            open_browser(&url);
        }
        kovra_webui::serve(listener, state, idle)
            .await
            .context("serving the Web UI")
    })
}

/// KOV-30 — opening the admin Web UI is an **attended action** (I3/I16): before
/// the server binds, the operator must approve at the broker — Touch ID on
/// `[host]` macOS, or `kovra approve` via the file broker elsewhere. Mirrors
/// [`confirm`] (the generic `kovra confirm` action gate). The prompt headline is
/// trusted, core-authored text (never requester input). `--no-confirm`
/// (`KOVRA_UI_NO_CONFIRM`) bypasses the gate for dev/CI/Docker per the plan.
fn confirm_ui_launch(ctx: &Ctx, no_confirm: bool) -> Result<()> {
    if no_confirm {
        return Ok(());
    }
    eprintln!(
        "Opening the kovra admin UI needs approval. Approve at the biometric prompt, or (file broker) run `kovra approve --list` then `kovra approve <id>` in another terminal. Waiting…"
    );
    run_ui_launch_gate(ctx, ctx.confirmer().as_ref())
}

/// The launch-gate decision against an explicit `broker` (split out so tests can
/// drive it with a deterministic [`kovra_core::MockConfirmer`]). The request is a
/// generic, secret-independent **action** (I16 authoritative headline), so it may
/// be approved with Touch ID *or* the device password (`for_action`).
fn run_ui_launch_gate(ctx: &Ctx, broker: &dyn Confirmer) -> Result<()> {
    let mut req = ConfirmRequest::for_action("Approve opening the kovra admin UI", Origin::Human);
    if let Some(proc) = kovra_wrapper::observe_parent() {
        req = req.with_requesting_process(proc);
    }
    match broker.confirm(&req, CONFIRM_TIMEOUT) {
        ConfirmOutcome::Approved => {
            audit(
                ctx,
                AuditAction::Approve,
                "approved-ui-launch",
                "kovra ui",
                "",
            );
            Ok(())
        }
        ConfirmOutcome::Denied => {
            audit(ctx, AuditAction::Deny, "denied-ui-launch", "kovra ui", "");
            bail!("denied — Web UI not started");
        }
        ConfirmOutcome::TimedOut => {
            audit(
                ctx,
                AuditAction::Timeout,
                "timeout-ui-launch",
                "kovra ui",
                "",
            );
            bail!("timed out — Web UI not started");
        }
    }
}

/// Best-effort: open `url` in the host browser. Never fails the command — the
/// URL is already printed for manual use.
fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let opener = "open";
    #[cfg(all(unix, not(target_os = "macos")))]
    let opener = "xdg-open";
    #[cfg(not(unix))]
    let opener = "explorer";
    let _ = std::process::Command::new(opener)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// Published image `kovra ui --docker` runs (KOV-49, DQ-13). Pull-only: Docker
/// pulls it on first use; we never `docker build` from the source tree. The tag
/// tracks the crate version so a release bump points the CLI at the matching
/// image. (Pre-go-live `[host]` verification: a locally-built image with this
/// exact tag satisfies the `docker image inspect` check below without a remote
/// pull.)
const UI_IMAGE_TAG: &str = concat!("ghcr.io/kaeus-inc/kovra-ui:", env!("CARGO_PKG_VERSION"));

/// Build the `docker run` argument vector for the Web UI container. Pure and
/// side-effect-free so it can be asserted in a unit test: the master key is
/// staged as a tmpfs secret file (I9) and mounted, so its **value** must never
/// appear in argv (I6) — only the in-container *path* to the secret file does.
fn docker_run_args(
    container: &str,
    publish: &str,
    vault_mount: &str,
    secret_mount: &str,
    port: u16,
    idle: u64,
    session: &str,
) -> Vec<String> {
    vec![
        "run".into(),
        "--rm".into(),
        "-d".into(),
        "--name".into(),
        container.into(),
        "-p".into(),
        publish.into(),
        "--mount".into(),
        vault_mount.into(),
        "--mount".into(),
        secret_mount.into(),
        "-e".into(),
        format!("KOVRA_UI_PORT={port}"),
        "-e".into(),
        format!("KOVRA_UI_IDLE_SECS={idle}"),
        "-e".into(),
        format!("KOVRA_UI_SESSION={session}"),
        // Only the path to the tmpfs secret file — never the key value (I6).
        "-e".into(),
        "KOVRA_MASTER_KEY_FILE=/run/secrets/kovra_master_key".into(),
        UI_IMAGE_TAG.into(),
    ]
}

/// `kovra ui --docker` — run the Web UI in a container (L11, §12). `[host]`:
/// requires Docker on the host; the container path + image are validated on
/// hardware (CLAUDE.md rule 4), not in CI.
///
/// The master key is read from the host keyring and handed to the container as a
/// **Docker secret in tmpfs** (I9) — written to a `0600` file in a private temp
/// dir, bind-mounted read-only at `/run/secrets`, and removed on teardown. It is
/// never baked into an image layer and never passed as an env *value*. The port
/// is published loopback-only `-p 127.0.0.1:PORT:PORT` (I10); `~/.vaults` is a rw
/// bind-mount. The ephemeral session token is generated here so the opened URL
/// matches the in-container server (passed via `KOVRA_UI_SESSION`).
fn ui_docker(ctx: &Ctx, port: u16, idle: u64, no_open: bool, no_confirm: bool) -> Result<()> {
    ctx.require_initialized()?;
    // Attended launch (KOV-30) runs host-side, before the container starts —
    // Touch ID is unavailable inside the container.
    confirm_ui_launch(ctx, no_confirm)?;
    which_docker()?;
    ensure_image()?;

    // Resolve the master key (host keyring) and stage it as a tmpfs-style secret.
    let master = ctx.master_key()?;
    let key_hex: String = master.expose().iter().map(|b| format!("{b:02x}")).collect();
    let secret_dir = stage_secret_dir(&key_hex)?;
    // Best-effort cleanup of the staged key on every exit path.
    let _guard = SecretDirGuard(secret_dir.clone());

    // Ephemeral session token (host-generated so the opened URL matches).
    let mut buf = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let session: String = buf.iter().map(|b| format!("{b:02x}")).collect();

    let container = format!("kovra-ui-{port}");
    let publish = format!("127.0.0.1:{port}:{port}"); // I10 — loopback publish only
    let vault_mount = format!("type=bind,src={},dst=/vaults", ctx.root.display());
    let secret_mount = format!("type=bind,src={},dst=/run/secrets,ro", secret_dir.display());

    // Detached run; teardown on Enter / Ctrl-C.
    let args = docker_run_args(
        &container,
        &publish,
        &vault_mount,
        &secret_mount,
        port,
        idle,
        &session,
    );
    let status = std::process::Command::new("docker")
        .args(&args)
        .status()
        .context("running `docker run` (is Docker running?)")?;
    if !status.success() {
        bail!("`docker run` failed (exit {:?})", status.code());
    }

    let url = format!("http://127.0.0.1:{port}/?session={session}");
    println!("kovra ui (docker) → {url}");
    eprintln!(
        "(container `{container}`; loopback publish {publish}; key via Docker secret in tmpfs — I9)"
    );
    if !no_open {
        open_browser(&url);
    }
    eprintln!("Press Enter to stop and remove the container…");
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);

    let _ = std::process::Command::new("docker")
        .args(["stop", &container])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    eprintln!("Stopped {container}.");
    Ok(())
}

/// Verify the `docker` CLI is on PATH; a clear error beats an opaque failure.
fn which_docker() -> Result<()> {
    let ok = std::process::Command::new("docker")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        bail!(
            "Docker is not available on PATH — `kovra ui --docker` needs Docker installed and running"
        )
    }
}

/// Ensure the published UI image is available locally, pull-only (KOV-49, DQ-13).
/// We never `docker build` from the source tree: `kovra ui --docker` runs the
/// released `ghcr.io/kaeus-inc/kovra-ui` image, matching what the docs describe.
///
/// If the image is already present (already pulled, or built locally with this
/// exact tag for pre-go-live `[host]` verification), this is a no-op. Otherwise
/// we pull it and surface a clear, actionable error if the pull fails (offline,
/// not yet published, or the tag is wrong) instead of an opaque `docker run`
/// failure later.
fn ensure_image() -> Result<()> {
    let present = std::process::Command::new("docker")
        .args(["image", "inspect", UI_IMAGE_TAG])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if present {
        return Ok(());
    }
    eprintln!("Pulling {UI_IMAGE_TAG} (first run)…");
    let status = std::process::Command::new("docker")
        .args(["pull", UI_IMAGE_TAG])
        .status()
        .context("running `docker pull`")?;
    if !status.success() {
        bail!(
            "could not pull `{UI_IMAGE_TAG}` — check your network and that the image/tag exists. \
             `kovra ui --docker` runs the published image; it does not build one locally."
        );
    }
    Ok(())
}

/// Stage the master key as a `0600` file in a private temp dir (the tmpfs-style
/// secret bind-mounted into the container, I9). Returns the dir to mount.
fn stage_secret_dir(key_hex: &str) -> Result<PathBuf> {
    use rand::RngCore;
    let mut buf = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let suffix: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    let dir = std::env::temp_dir().join(format!("kovra-ui-secret-{suffix}"));
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    let key_path = dir.join("kovra_master_key");
    std::fs::write(&key_path, key_hex)
        .with_context(|| format!("writing {}", key_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(dir)
}

/// RAII: remove the staged secret dir on every exit path (the host-side copy of
/// the key never outlives the `kovra ui --docker` invocation).
struct SecretDirGuard(PathBuf);
impl Drop for SecretDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ───────────────────────── import (KOV-24, 1Password) ─────────────────────────

/// `kovra import` — copy a credential from 1Password into the vault as a literal
/// (KOV-24). Reads the value once via the `op` CLI and seals it; **no
/// relationship is kept** (not a reference). The value never touches argv (only
/// the `op://` address does — I6) and is never printed (I12); `prod` is born
/// `high` (I5).
pub fn import(
    ctx: &Ctx,
    coordinate: &str,
    from: &str,
    sensitivity: Option<SensitivityArg>,
    description: Option<String>,
    revealable: bool,
    project: Option<&str>,
) -> Result<()> {
    ctx.require_initialized()?;
    let Target {
        coord,
        env,
        component,
        key,
        canonical,
    } = target(coordinate)?;
    if coord.half != kovra_core::KeyHalf::Unspecified {
        bail!("`import` takes a plain coordinate, not a `#public`/`#private` half selector");
    }
    let dir = vault_dir(&ctx.registry, project);
    let master = ctx.master_key()?;
    if store::read_record(&dir, &coord, master.expose())?.is_some() {
        bail!("`{coordinate}` already exists — use `kovra set` (value) or `kovra edit` (metadata)");
    }

    // Read the value out of 1Password (the only secret-bearing step). The `op`
    // runner is the single seam to the outside world; the value is zeroized.
    let value = crate::onepassword::read_value(&crate::onepassword::SystemOpRunner, from)?;
    let value = SecretValue::new(value.to_vec());

    let chosen = sensitivity
        .map(Sensitivity::from)
        .unwrap_or(Sensitivity::Medium);
    let born = birth_sensitivity(&env, chosen); // prod ⇒ high (I5)
    let now = ctx.now();
    let record = SecretRecord::Literal {
        value,
        sensitivity: born,
        revealable,
        environment: env.clone(),
        component,
        key,
        description,
        created: now.clone(),
        updated: now,
    };
    store::write_record(&dir, &coord, &seal(&record, master.expose())?)?;
    audit(
        ctx,
        AuditAction::Create,
        "imported-1password",
        &canonical,
        &env,
    );
    println!("Imported {canonical} from 1Password ({born:?}) — value stored, not shown.");
    Ok(())
}

// ───────────────────────────── approve ─────────────────────────────

pub fn approve(ctx: &Ctx, list: bool, deny: bool, id: Option<String>) -> Result<()> {
    let broker = FileConfirmer::under_root(&ctx.root);
    if list {
        let pending = broker.list_pending()?;
        if pending.is_empty() {
            println!("(no pending requests)");
            return Ok(());
        }
        for p in pending {
            let r = &p.request;
            // I16/§8.3 trusted, observed requesting-process identity.
            let process = r.requesting_process.as_deref().unwrap_or("-");
            if let Some(action) = r.action.as_deref() {
                // A generic action confirmation (KOV-31): no secret involved.
                println!(
                    "{}\n    action  : {}\n    origin  : {}\n    process : {}",
                    p.id,
                    action,
                    r.origin.as_str(),
                    process,
                );
            } else {
                println!(
                    "{}\n    command : {}\n    secret  : {}\n    sens/env: {:?} / {}\n    origin  : {}\n    process : {}",
                    p.id,
                    r.resolved_command.as_deref().unwrap_or("-"),
                    r.coordinate,
                    r.sensitivity,
                    r.environment,
                    r.origin.as_str(),
                    process,
                );
            }
        }
        return Ok(());
    }
    let id = id.ok_or_else(|| anyhow!("provide a request id, or `--list` to see pending"))?;
    let resolved = if deny {
        broker.deny(&id)?
    } else {
        broker.approve(&id)?
    };
    if resolved {
        println!("{} {id}", if deny { "Denied" } else { "Approved" });
        Ok(())
    } else {
        bail!("no pending request `{id}`");
    }
}

/// `kovra confirm "<description>" [--ttl]` — request an attended human
/// confirmation for a **generic action** (KOV-31). Secret-independent: it never
/// touches the vault or the master key, only the confirmation broker
/// ([`Ctx::confirmer`] — biometric Touch ID on macOS, `kovra approve` file-broker
/// fallback). Exits 0 on approval; bails (non-zero) on denial or timeout, so a
/// trusted app/host can `kovra confirm … && <do the action>`.
///
/// `description` is the **trusted, caller-authored** prompt headline (the
/// requesting application/host, never untrusted/LLM input). It is shown verbatim
/// (I16 authoritative line) and recorded in the audit trail (it is an action
/// label, not a secret value — I12). This confirm never substitutes for the
/// secret broker: `inject`/reveal of `high`/`prod` still go through their own
/// live confirmation (§8.2).
pub fn confirm(ctx: &Ctx, description: &str, ttl: u64) -> Result<()> {
    let mut req = ConfirmRequest::for_action(description, Origin::Human);
    if let Some(proc) = kovra_wrapper::observe_parent() {
        req = req.with_requesting_process(proc);
    }
    let broker = ctx.confirmer();
    eprintln!(
        "Approval required: {description}\nApprove at the biometric prompt, or (file broker) run `kovra approve --list` then `kovra approve <id>` in another terminal. Waiting…"
    );
    // Audit label: the action description, truncated. Never a secret value (I12).
    let label: String = description.chars().take(120).collect();
    match broker.confirm(&req, Duration::from_secs(ttl)) {
        ConfirmOutcome::Approved => {
            audit(ctx, AuditAction::Approve, "approved-action", &label, "");
            eprintln!("Approved.");
            Ok(())
        }
        ConfirmOutcome::Denied => {
            audit(ctx, AuditAction::Deny, "denied-action", &label, "");
            bail!("denied");
        }
        ConfirmOutcome::TimedOut => {
            audit(ctx, AuditAction::Timeout, "timeout-action", &label, "");
            bail!("timed out");
        }
    }
}

// ───────────────────── master-key backup / restore (KOV-34) ─────────────────────

/// `kovra key export` — write an encrypted **disaster-recovery** backup of what
/// the vault needs to unlock, **respecting its mode** (KOV-34): a keyring vault
/// backs up its stored master key; a passphrase vault backs up its `kdf.salt`
/// (the passphrase stays with you and is never exported). The plaintext never
/// touches disk (I7/I12) — it is sealed into a standard armored `age` blob under
/// a recovery passphrase (restorable by `kovra key import`, or by any `age`
/// implementation if kovra is unavailable). Exporting recovery material is an
/// **attended** action (the broker); the passphrase is asked twice so a typo
/// cannot silently lock the backup.
/// Where `kovra key export` delivers the (encrypted) backup. Targets compose; if
/// none is set, the blob goes to stdout.
pub struct ExportTargets<'a> {
    pub out: Option<&'a Path>,
    pub clipboard: bool,
    pub op: bool,
    pub op_vault: Option<&'a str>,
    pub op_title: Option<&'a str>,
}

pub fn key_export(ctx: &Ctx, targets: ExportTargets) -> Result<()> {
    ctx.require_initialized()?;

    // Per the vault's current mode, gather the recovery material to back up.
    let (kind, data): (BackupKind, Zeroizing<Vec<u8>>) = if ctx.passphrase_mode() {
        let salt = std::fs::read(ctx.salt_path()).context("reading kdf.salt")?;
        (BackupKind::KdfSalt, Zeroizing::new(salt))
    } else {
        let master = ctx.master_key()?;
        (
            BackupKind::MasterKey,
            Zeroizing::new(master.expose().to_vec()),
        )
    };

    let mut req =
        ConfirmRequest::for_action("Export the kovra vault recovery backup", Origin::Human);
    if let Some(proc) = kovra_wrapper::observe_parent() {
        req = req.with_requesting_process(proc);
    }
    eprintln!(
        "Exporting the vault recovery backup needs approval. Approve at the biometric prompt, or (file broker) run `kovra approve --list` then `kovra approve <id>` in another terminal. Waiting…"
    );
    match ctx.confirmer().confirm(&req, CONFIRM_TIMEOUT) {
        ConfirmOutcome::Approved => {}
        ConfirmOutcome::Denied => {
            audit(
                ctx,
                AuditAction::Deny,
                "denied-key-export",
                "vault-backup",
                "",
            );
            bail!("denied — backup not exported");
        }
        ConfirmOutcome::TimedOut => {
            audit(
                ctx,
                AuditAction::Timeout,
                "timeout-key-export",
                "vault-backup",
                "",
            );
            bail!("timed out — backup not exported");
        }
    }

    // With `--op`, resolve the destination 1Password vault + item name *before*
    // the attended confirmation: a flag wins; otherwise pick the vault from a list
    // and prompt for the item name (default = a descriptive title).
    let op_target: Option<(Option<String>, String)> = if targets.op {
        let writer = crate::onepassword::SystemOpWriter;
        let vault = match targets.op_vault {
            Some(v) => Some(v.to_string()),
            None => Some(select_op_vault(&writer)?),
        };
        let default_title = format!("kovra vault backup — {} — {}", kind.label(), ctx.now());
        let title = match targets.op_title {
            Some(t) => t.to_string(),
            None => prompt_with_default("1Password item name", &default_title)?,
        };
        Some((vault, title))
    } else {
        None
    };

    // With `--op`, kovra **generates** a strong recovery passphrase and stores it
    // alongside the blob in the 1Password item — nothing for the user to type or
    // remember. Otherwise the passphrase is prompted (asked twice).
    let pass: Zeroizing<String> = if targets.op {
        generate_recovery_passphrase()
    } else {
        read_new_passphrase(
            "Recovery passphrase (required to restore — store it safely): ",
            "Confirm recovery passphrase: ",
        )?
    };
    let armored =
        kovra_core::export_backup(kind, &data, pass.as_str()).map_err(|e| anyhow!("{e}"))?;

    // Output targets compose: --out writes a file, --clipboard copies, --op
    // stores in 1Password. With none set, the (encrypted) blob goes to stdout.
    let mut delivered = false;
    if let Some(path) = targets.out {
        write_private_file(path, armored.as_bytes())?;
        eprintln!(
            "Vault backup ({}) written to {} (0600). Keep it safe; the recovery passphrase is required to restore.",
            kind.label(),
            path.display()
        );
        delivered = true;
    }
    if targets.clipboard {
        copy_to_clipboard(&armored)?;
        eprintln!(
            "Vault backup ({}) copied to the clipboard (encrypted). Paste it into your password manager now.",
            kind.label()
        );
        delivered = true;
    }
    if let Some((vault, title)) = op_target {
        let note = match kind {
            BackupKind::KdfSalt => format!(
                "Kovra vault recovery backup — kdf.salt (passphrase-mode vault).\n\
                 \n\
                 To restore (with the 1Password CLI signed in), run:\n\
                 \n\
                 kovra key import --op \"{title}\"\n\
                 \n\
                 then set your vault passphrase and unlock:\n\
                 \n\
                 export KOVRA_PASSPHRASE=\"<your vault passphrase>\"\n\
                 kovra list\n\
                 \n\
                 Manual alternative (no op): reveal the \"age backup\" field into a file, then\n\
                 kovra key import <file>   (paste the \"recovery passphrase\" field when asked).\n\
                 \n\
                 Note: your KOVRA_PASSPHRASE is NOT stored here — you also need it to recover."
            ),
            BackupKind::MasterKey => format!(
                "Kovra vault recovery backup — master key (keyring-mode vault).\n\
                 \n\
                 To restore (with the 1Password CLI signed in), run:\n\
                 \n\
                 kovra key import --op \"{title}\"\n\
                 kovra list\n\
                 \n\
                 Manual alternative (no op): reveal the \"age backup\" field into a file, then\n\
                 kovra key import <file>   (paste the \"recovery passphrase\" field when asked)."
            ),
        };
        let item = crate::onepassword::store_backup_item(
            &crate::onepassword::SystemOpWriter,
            &title,
            vault.as_deref(),
            pass.as_str(),
            &armored,
            &note,
        )?;
        eprintln!(
            "Vault backup ({}) stored in 1Password as \"{title}\" [{item}] — recovery passphrase generated and saved in the same item. Nothing to remember.",
            kind.label()
        );
        delivered = true;
    }
    if !delivered {
        print!("{armored}");
        std::io::stdout().flush().ok();
    }
    audit(
        ctx,
        AuditAction::Create,
        "vault backup exported (age)",
        "vault-backup",
        "",
    );
    Ok(())
}

/// `kovra key import` — restore a [`key_export`] backup (KOV-34). The blob is
/// self-describing, so the right material is restored to the right backend,
/// **respecting the vault's mode**: a master-key backup goes to the OS keyring; a
/// `kdf.salt` backup goes to `kdf.salt`. The source is either a **1Password item**
/// (`--op <item>`, which yields both the backup and the recovery passphrase — no
/// files, no prompts) or a `file`/stdin blob (then the recovery passphrase is
/// prompted). Does not require an initialized vault (its purpose is to recover
/// one). Round-tripping is idempotent; `--force` overwrites a *different* existing
/// key/salt.
pub fn key_import(
    ctx: &Ctx,
    file: Option<&Path>,
    force: bool,
    op: Option<&str>,
    op_vault: Option<&str>,
) -> Result<()> {
    let (kind, data) = if let Some(item) = op {
        // Pull the encrypted backup + recovery passphrase straight from 1Password.
        // On a duplicate name, list the matches and let the user pick one.
        let (blob, pass) = crate::onepassword::read_backup_item(
            &crate::onepassword::SystemOpRunner,
            item,
            op_vault,
            |candidates| select_op_item(item, candidates),
        )?;
        eprintln!("Restoring from 1Password item \"{item}\"…");
        kovra_core::import_backup(&blob, &pass).map_err(|e| anyhow!("{e}"))?
    } else {
        let armored = match file {
            Some(path) => std::fs::read_to_string(path)
                .with_context(|| format!("reading backup {}", path.display()))?,
            None => {
                let mut s = String::new();
                std::io::stdin()
                    .read_to_string(&mut s)
                    .context("reading backup from stdin")?;
                s
            }
        };
        let pass = read_passphrase("Recovery passphrase: ")?;
        kovra_core::import_backup(&armored, pass.as_str()).map_err(|e| anyhow!("{e}"))?
    };

    restore_backup(ctx, kind, &data, force)
}

/// Restore decrypted backup `data` of `kind` to the right backend, respecting the
/// vault's mode and never switching it (KOV-34). Idempotent; `--force` overwrites
/// a *different* existing key/salt.
fn restore_backup(ctx: &Ctx, kind: BackupKind, data: &[u8], force: bool) -> Result<()> {
    match kind {
        BackupKind::MasterKey => {
            let key: [u8; KEY_LEN] = data
                .try_into()
                .map_err(|_| anyhow!("backup is not a 32-byte master key"))?;
            let keyring = OsKeyring::new();
            if keyring.get_master_key().is_ok() && !force {
                bail!("a master key already exists in the keyring — pass --force to overwrite it");
            }
            keyring
                .set_master_key(&MasterKey::new(key))
                .map_err(|e| anyhow!("{e}"))?;
            audit(
                ctx,
                AuditAction::Create,
                "master-key restored (age backup)",
                "vault-backup",
                "",
            );
            eprintln!(
                "Master key restored to the OS keyring. The vault unlocks via the keyring (unset KOVRA_PASSPHRASE if it is set)."
            );
        }
        BackupKind::KdfSalt => {
            let path = ctx.salt_path();
            if path.exists() {
                let current = std::fs::read(&path).unwrap_or_default();
                if current.as_slice() != data && !force {
                    bail!(
                        "a different kdf.salt already exists — pass --force to overwrite (this changes the derived key)"
                    );
                }
            }
            write_private_file(&path, data)?;
            audit(
                ctx,
                AuditAction::Create,
                "kdf-salt restored (age backup)",
                "vault-backup",
                "",
            );
            eprintln!(
                "kdf.salt restored to {}. Set KOVRA_PASSPHRASE to unlock the vault.",
                path.display()
            );
        }
    }
    Ok(())
}

/// Interactively pick a 1Password vault from `op vault list` (KOV-34 `--op` with
/// no `--op-vault`). Prints a numbered menu on stderr and reads a choice from
/// stdin; loops until a valid number is entered.
fn select_op_vault(writer: &dyn crate::onepassword::OpWriter) -> Result<String> {
    let names = crate::onepassword::vault_names(writer)?;
    if names.is_empty() {
        bail!("no 1Password vaults found — is `op` signed in? (run `op signin`)");
    }
    eprintln!("Select the 1Password vault for the backup:");
    for (i, n) in names.iter().enumerate() {
        eprintln!("  {}) {}", i + 1, n);
    }
    loop {
        eprint!("Vault [1-{}]: ", names.len());
        std::io::stderr().flush().ok();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line)? == 0 {
            bail!("no selection (stdin closed)");
        }
        match line.trim().parse::<usize>() {
            Ok(n) if (1..=names.len()).contains(&n) => return Ok(names[n - 1].clone()),
            _ => eprintln!("Please enter a number between 1 and {}.", names.len()),
        }
    }
}

/// Interactively pick one of several 1Password items that share a name (KOV-34
/// `key import --op`). Prints a numbered menu (vault + id) on stderr and returns
/// the chosen item's id.
fn select_op_item(
    name: &str,
    candidates: &[crate::onepassword::OpItemCandidate],
) -> Result<String> {
    eprintln!("More than one 1Password item is named \"{name}\". Select the one to restore:");
    for (i, c) in candidates.iter().enumerate() {
        eprintln!(
            "  {}) updated {}  ·  vault {}  ·  id {}",
            i + 1,
            c.updated,
            c.vault,
            c.id
        );
    }
    loop {
        eprint!("Item [1-{}]: ", candidates.len());
        std::io::stderr().flush().ok();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line)? == 0 {
            bail!("no selection (stdin closed)");
        }
        match line.trim().parse::<usize>() {
            Ok(n) if (1..=candidates.len()).contains(&n) => {
                return Ok(candidates[n - 1].id.clone());
            }
            _ => eprintln!("Please enter a number between 1 and {}.", candidates.len()),
        }
    }
}

/// Generate a strong random recovery passphrase (KOV-34 `--op`): 32 alphanumeric
/// characters (~190 bits of entropy), in a [`Zeroizing`] buffer. Used when kovra
/// mints the passphrase itself and stores it in 1Password — the user never types
/// or remembers it.
fn generate_recovery_passphrase() -> Zeroizing<String> {
    use rand::Rng;
    use rand::distributions::Alphanumeric;
    Zeroizing::new(
        rand::rngs::OsRng
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect(),
    )
}

/// Copy `text` to the OS clipboard by piping it to the platform tool — no extra
/// dependency, mirroring `open_browser`. Safe for the key backup because the blob
/// is **encrypted** (the clipboard never holds plaintext key material).
fn copy_to_clipboard(text: &str) -> Result<()> {
    use std::process::{Command, Stdio};

    #[cfg(target_os = "macos")]
    let candidates: &[(&str, &[&str])] = &[("pbcopy", &[])];
    #[cfg(target_os = "windows")]
    let candidates: &[(&str, &[&str])] = &[("clip", &[])];
    #[cfg(all(unix, not(target_os = "macos")))]
    let candidates: &[(&str, &[&str])] = &[
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("xsel", &["--clipboard", "--input"]),
    ];

    let mut last_err = String::new();
    for (prog, args) in candidates {
        match Command::new(prog).args(*args).stdin(Stdio::piped()).spawn() {
            Ok(mut child) => {
                if let Some(mut stdin) = child.stdin.take() {
                    stdin
                        .write_all(text.as_bytes())
                        .with_context(|| format!("piping the backup to {prog}"))?;
                    // Drop stdin to signal EOF so the tool commits the clipboard.
                    drop(stdin);
                }
                match child.wait() {
                    Ok(status) if status.success() => return Ok(()),
                    Ok(status) => last_err = format!("{prog} exited with {status}"),
                    Err(e) => last_err = format!("{prog}: {e}"),
                }
            }
            Err(e) => last_err = format!("{prog}: {e}"),
        }
    }
    bail!(
        "could not copy to the clipboard ({last_err}). Use --out <file> or pipe the output instead."
    )
}

/// Write `bytes` to `path` with owner-only permissions (0600 on Unix) — the
/// master-key backup is a secret-bearing artifact and must not be world-readable.
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting permissions on {}", path.display()))?;
    }
    Ok(())
}

// ───────────────────────── keypairs (KOV-12) ─────────────────────────

/// Generate and custody a keypair. The private half is sealed and never printed
/// or written to disk (I7); the public key is shown.
pub fn keygen(
    ctx: &Ctx,
    coordinate: &str,
    algorithm: crate::cli::KeyAlgorithmArg,
    sensitivity: Option<SensitivityArg>,
    description: Option<String>,
    project: Option<&str>,
) -> Result<()> {
    ctx.require_initialized()?;
    let Target {
        coord,
        env,
        component,
        key,
        canonical,
    } = target(coordinate)?;
    if coord.half != kovra_core::KeyHalf::Unspecified {
        bail!("`keygen` takes a plain coordinate, not a `#public`/`#private` half selector");
    }
    let dir = vault_dir(&ctx.registry, project);
    let master = ctx.master_key()?;
    if store::read_record(&dir, &coord, master.expose())?.is_some() {
        bail!("`{coordinate}` already exists");
    }

    let algorithm: kovra_core::KeyAlgorithm = algorithm.into();
    let generated = kovra_core::generate(algorithm).map_err(|e| anyhow!("{e}"))?;
    // A keypair's private half is non-revealable by default exactly like a high
    // secret (I11): generated keys never opt into reveal.
    let chosen = sensitivity
        .map(Sensitivity::from)
        .unwrap_or(Sensitivity::High);
    let born = birth_sensitivity(&env, chosen); // prod ⇒ high (I5)
    let now = ctx.now();
    let record = SecretRecord::Keypair {
        algorithm,
        // The private OpenSSH key moves straight into the sealed SecretValue;
        // it is never printed or written to disk in plaintext (I7).
        private: Some(SecretValue::from(generated.private_openssh.as_str())),
        public: generated.public_openssh.clone(),
        sensitivity: born,
        revealable: false,
        environment: env.clone(),
        component,
        key,
        description,
        created: now.clone(),
        updated: now,
    };
    store::write_record(&dir, &coord, &seal(&record, master.expose())?)?;
    audit(ctx, AuditAction::Create, "keygen", &canonical, &env);
    println!("Generated {canonical} ({}, {born:?}).", algorithm.as_str());
    // The public key is not a secret — show it so it can be shared.
    println!("{}", generated.public_openssh.trim_end());
    Ok(())
}

/// Print the OpenSSH public key of a keypair (free — a metadata-class op).
pub fn pubkey(ctx: &Ctx, coordinate: &str, project: Option<&str>) -> Result<()> {
    let (_coord, record, _canonical, _env) = resolve_keypair(ctx, coordinate, project)?;
    let public = keypair_public(&record)?;
    println!("{}", public.trim_end());
    Ok(())
}

/// Load a keypair's private key into the ssh-agent (in memory, never disk — I7).
/// Private-key op ⇒ broker-gated for high/prod (I3/I15).
pub fn ssh_add(ctx: &Ctx, coordinate: &str, project: Option<&str>) -> Result<()> {
    let (coord, record, canonical, env) = resolve_keypair(ctx, coordinate, project)?;
    let private = keypair_private(&record, &canonical)?;
    gate_private_key_op(ctx, &coord, &record, &canonical, &env, "ssh-add")?;
    // The real agent is a `[host]` piece (validated on hardware by the human);
    // it never writes the key to disk.
    let agent = kovra_core::EnvSshAgent;
    use kovra_core::SshAgent as _;
    agent
        .add_identity(
            std::str::from_utf8(private.expose())
                .map_err(|_| anyhow!("stored key is not valid UTF-8"))?,
            &format!("kovra:{canonical}"),
        )
        .map_err(|e| anyhow!("{e}"))?;
    audit(ctx, AuditAction::Inject, "ssh-add", &canonical, &env);
    eprintln!("Loaded {canonical} into the ssh-agent (in memory, not written to disk).");
    Ok(())
}

// ───────────────────────────── ssh-agent (KOV-13) ─────────────────────────────

/// Run kovra as a governed ssh-agent (KOV-13). Foreground: bind the socket,
/// print the `SSH_AUTH_SOCK` to export, sign each challenge in memory with a
/// custodied keypair (I7), confirm `high`/`prod` per signature (I3/I15), audit
/// (I12), scope by `agent.toml` (I13). Refuses to start if `$SSH_AUTH_SOCK` is
/// already set (never hijacks another agent).
pub fn ssh_agent(ctx: &Ctx, socket: Option<PathBuf>) -> Result<()> {
    use kovra_agent::{AgentConfig, run_agent};

    ctx.require_initialized()?;
    // Validate the backend up front (a clear error beats a per-connection one).
    let master = ctx.master_key()?;
    let scope = kovra_agent::load_scope(&ctx.root).map_err(|e| anyhow!("{e}"))?;
    let socket_path = socket.unwrap_or_else(|| kovra_agent::default_socket_path(&ctx.root));

    let config = AgentConfig {
        socket_path,
        scope,
        confirm_timeout: CONFIRM_TIMEOUT,
        requesting_process: kovra_wrapper::observe_parent(),
    };
    let provider = CliSessionProvider {
        root: ctx.root.clone(),
        master,
    };
    run_agent(config, provider).map_err(|e| anyhow!("{e}"))
}

/// The CLI's [`kovra_agent::SessionProvider`]: loads custodied keypairs (with a
/// private half) from the registry and rebuilds the confirmer/audit/clock per
/// request, reusing the exact selection logic the rest of the CLI uses.
struct CliSessionProvider {
    root: PathBuf,
    master: MasterKey,
}

impl kovra_agent::SessionProvider for CliSessionProvider {
    fn load_keys(&self) -> Result<Vec<kovra_agent::KeypairEntry>, kovra_agent::AgentError> {
        let registry = Registry::open(&self.root).map_err(kovra_agent::AgentError::Core)?;
        let mut entries = Vec::new();

        let mut collect =
            |dir: PathBuf, project: Option<String>| -> Result<(), kovra_agent::AgentError> {
                let outcome = store::load_all(&dir, self.master.expose())
                    .map_err(kovra_agent::AgentError::Core)?;
                for (_, record) in outcome.records {
                    if let SecretRecord::Keypair {
                        private: Some(private),
                        public,
                        sensitivity,
                        environment,
                        component,
                        key,
                        ..
                    } = &record
                    {
                        // Build the concrete coordinate from the stored segments.
                        let coord_str = format!("secret:{environment}/{component}/{key}");
                        let coord = match Coordinate::from_str(&coord_str) {
                            Ok(c) => c,
                            Err(_) => continue, // skip a malformed stored coordinate
                        };
                        let private_openssh = match std::str::from_utf8(private.expose()) {
                            Ok(s) => zeroize::Zeroizing::new(s.to_string()),
                            Err(_) => continue, // skip a non-UTF8 key rather than abort
                        };
                        entries.push(kovra_agent::KeypairEntry {
                            coordinate: coord,
                            project: project.clone(),
                            environment: environment.clone(),
                            sensitivity: *sensitivity,
                            public_openssh: public.clone(),
                            private_openssh,
                        });
                    }
                }
                Ok(())
            };

        collect(registry.global_dir(), None)?;
        for name in registry
            .list_projects()
            .map_err(kovra_agent::AgentError::Core)?
        {
            collect(registry.project_dir(&name), Some(name))?;
        }
        Ok(entries)
    }

    fn confirmer(&self) -> Box<dyn Confirmer> {
        // Reuse the CLI's selection (biometric on macOS with file fallback).
        crate::context::select_confirmer(&self.root)
    }

    fn audit(&self) -> Box<dyn AuditSink> {
        Box::new(kovra_core::FileAuditSink::under_root(&self.root))
    }

    fn clock(&self) -> Box<dyn Clock> {
        Box::new(kovra_core::SystemClock)
    }
}

/// Sign data with a keypair's private key (broker-gated for high/prod).
pub fn sign(ctx: &Ctx, coordinate: &str, input: &str, project: Option<&str>) -> Result<()> {
    let (coord, record, canonical, env) = resolve_keypair(ctx, coordinate, project)?;
    let private = keypair_private(&record, &canonical)?;
    let data = read_input_bytes(input)?;
    gate_private_key_op(ctx, &coord, &record, &canonical, &env, "sign")?;
    let signature = kovra_core::sign(
        std::str::from_utf8(private.expose())
            .map_err(|_| anyhow!("stored key is not valid UTF-8"))?,
        &data,
    )
    .map_err(|e| anyhow!("{e}"))?;
    audit(ctx, AuditAction::Inject, "sign", &canonical, &env);
    println!("{signature}");
    Ok(())
}

/// Verify a signature against a public key (free — no confirmation).
pub fn verify(
    ctx: &Ctx,
    coordinate: &str,
    signature_file: &Path,
    input: &str,
    project: Option<&str>,
) -> Result<()> {
    let (_coord, record, _canonical, _env) = resolve_keypair(ctx, coordinate, project)?;
    let public = keypair_public(&record)?;
    let data = read_input_bytes(input)?;
    let signature = std::fs::read_to_string(signature_file)
        .with_context(|| format!("reading signature {}", signature_file.display()))?;
    if kovra_core::verify(&public, &data, &signature).map_err(|e| anyhow!("{e}"))? {
        println!("OK: signature is valid");
        Ok(())
    } else {
        bail!("BAD: signature does not verify");
    }
}

/// Encrypt data *to* a public key (ed25519 only; free — no confirmation).
pub fn encrypt(ctx: &Ctx, coordinate: &str, input: &str, project: Option<&str>) -> Result<()> {
    let (_coord, record, _canonical, _env) = resolve_keypair(ctx, coordinate, project)?;
    let public = keypair_public(&record)?;
    let data = read_input_bytes(input)?;
    let ciphertext = kovra_core::encrypt_to(&public, &data).map_err(|e| anyhow!("{e}"))?;
    std::io::stdout()
        .write_all(&ciphertext)
        .context("writing ciphertext to stdout")?;
    Ok(())
}

/// Decrypt data *with* a keypair's private key (ed25519 only; broker-gated).
pub fn decrypt(ctx: &Ctx, coordinate: &str, input: &str, project: Option<&str>) -> Result<()> {
    let (coord, record, canonical, env) = resolve_keypair(ctx, coordinate, project)?;
    let private = keypair_private(&record, &canonical)?;
    let ciphertext = read_input_bytes(input)?;
    gate_private_key_op(ctx, &coord, &record, &canonical, &env, "decrypt")?;
    let plaintext = kovra_core::decrypt(
        std::str::from_utf8(private.expose())
            .map_err(|_| anyhow!("stored key is not valid UTF-8"))?,
        &ciphertext,
    )
    .map_err(|e| anyhow!("{e}"))?;
    audit(ctx, AuditAction::Inject, "decrypt", &canonical, &env);
    std::io::stdout()
        .write_all(&plaintext)
        .context("writing plaintext to stdout")?;
    Ok(())
}

/// Resolve a coordinate to a keypair record (project→global override). Errors if
/// the coordinate is absent or not a keypair.
fn resolve_keypair(
    ctx: &Ctx,
    coordinate: &str,
    project: Option<&str>,
) -> Result<(Coordinate, SecretRecord, String, String)> {
    let Target {
        coord,
        env,
        canonical,
        ..
    } = target(coordinate)?;
    let keyring = ctx.keyring()?;
    let record = match ctx
        .registry
        .resolve(&coord, project, keyring.as_ref())
        .context("resolving the coordinate")?
    {
        Resolution::Found { record, origin } => {
            if let VaultOrigin::Project(p) = &origin {
                eprintln!("(from project vault `{p}`)");
            }
            record
        }
        Resolution::NotFound => bail!("no secret at `{coordinate}`"),
    };
    if !matches!(record, SecretRecord::Keypair { .. }) {
        bail!("`{coordinate}` is not a keypair");
    }
    Ok((coord, record, canonical, env))
}

/// The OpenSSH public key of a keypair record.
fn keypair_public(record: &SecretRecord) -> Result<String> {
    match record {
        SecretRecord::Keypair { public, .. } => Ok(public.clone()),
        _ => bail!("not a keypair"),
    }
}

/// The sealed private half of a keypair record, or an explicit error for a
/// public-only entry. The private value is returned without ever being printed.
fn keypair_private<'a>(record: &'a SecretRecord, canonical: &str) -> Result<&'a SecretValue> {
    match record {
        SecretRecord::Keypair {
            private: Some(v), ..
        } => Ok(v),
        SecretRecord::Keypair { private: None, .. } => {
            bail!("`{canonical}` is a public-only entry — it has no private key for this operation")
        }
        _ => bail!("not a keypair"),
    }
}

/// Run a private-key op through the policy funnel as `Operation::Inject`
/// (broker-gated for high/prod, I3/I15). The key material is used only *through*
/// the operation; it never enters the caller's context (I11/I14) or argv (I6).
fn gate_private_key_op(
    ctx: &Ctx,
    coord: &Coordinate,
    record: &SecretRecord,
    canonical: &str,
    env: &str,
    op_label: &str,
) -> Result<()> {
    let sensitivity = record.sensitivity();
    let request = AccessRequest {
        coordinate: coord,
        project: None,
        sensitivity,
        revealable: false,
        operation: Operation::Inject,
        surface: Surface::Cli,
        origin: Origin::Human,
    };
    match decide(&request, &AgentScope::full()) {
        Decision::Allow => Ok(()),
        Decision::RequireConfirmation => {
            let broker = FileConfirmer::under_root(&ctx.root);
            let mut req = ConfirmRequest::new(canonical, sensitivity, env, Origin::Human)
                .with_command(format!("kovra {op_label} {canonical}"));
            // I16 (§8.3): observed parent process as the requesting caller.
            if let Some(proc) = kovra_wrapper::observe_parent() {
                req = req.with_requesting_process(proc);
            }
            eprintln!(
                "{canonical} is {sensitivity:?} — approval required for `{op_label}`. In another terminal run `kovra approve --list`, then `kovra approve <id>`. Waiting…"
            );
            match broker.confirm(&req, CONFIRM_TIMEOUT) {
                ConfirmOutcome::Approved => {
                    audit(ctx, AuditAction::Approve, "approved", canonical, env);
                    Ok(())
                }
                ConfirmOutcome::Denied => {
                    audit(ctx, AuditAction::Deny, "denied", canonical, env);
                    bail!("denied — `{op_label}` not performed");
                }
                ConfirmOutcome::TimedOut => {
                    audit(ctx, AuditAction::Timeout, "timeout", canonical, env);
                    bail!("timed out — `{op_label}` not performed");
                }
            }
        }
        Decision::Deny(reason) => bail!("denied: {reason:?}"),
        Decision::Unaddressable => bail!("`{canonical}` is not addressable"),
    }
}

/// Read input bytes from a file path, or from stdin when `input` is `-`.
fn read_input_bytes(input: &str) -> Result<Vec<u8>> {
    if input == "-" {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)
            .context("reading input from stdin")?;
        Ok(buf)
    } else {
        std::fs::read(input).with_context(|| format!("reading input file {input}"))
    }
}

/// `kovra scaffold` — scan a repo and PROPOSE an `.env.refs` (L12). Reads only
/// source for variable *names* (never a value, never an `.env*` file). Prints
/// the proposal to stdout, or writes it to `--out` — refusing to clobber an
/// existing file without `--force` (the proposal never silently overwrites).
/// Vault-independent: it builds a contract, it does not resolve secrets.
pub fn scaffold(_ctx: &Ctx, path: &Path, out: Option<PathBuf>, force: bool) -> Result<()> {
    let proposals = kovra_core::scan_repo(path).map_err(|e| anyhow!("{e}"))?;
    let body = kovra_core::render_env_refs(&proposals);
    match out {
        Some(dest) => {
            if dest.exists() && !force {
                bail!(
                    "{} already exists — refusing to overwrite (re-run with --force to replace it)",
                    dest.display()
                );
            }
            std::fs::write(&dest, &body)
                .with_context(|| format!("writing proposal to {}", dest.display()))?;
            eprintln!(
                "Wrote {} proposed coordinate(s) to {} — review before use.",
                proposals.len(),
                dest.display()
            );
        }
        None => print!("{body}"),
    }
    Ok(())
}

/// `kovra doctor` / `lint` — validate the secret config (L12). Renders findings
/// (coordinate + status, never a value, I11/I12) and exits non-zero on any hard
/// finding. `--refs` defaults to `./.env.refs`; the project is the `--project`
/// override or the `.env.refs` `project =` line.
pub fn doctor(ctx: &Ctx, env: &str, refs: Option<PathBuf>, project: Option<&str>) -> Result<()> {
    let refs_path = refs.unwrap_or_else(|| PathBuf::from(".env.refs"));
    let content = std::fs::read_to_string(&refs_path)
        .with_context(|| format!("reading {}", refs_path.display()))?;
    let parsed = kovra_core::EnvRefs::parse(&content).map_err(|e| anyhow!("{e}"))?;
    let project = project
        .map(str::to_string)
        .or_else(|| parsed.project.clone());

    let key = ctx.master_key()?;
    let report = kovra_core::doctor_check(
        &parsed,
        env,
        &ctx.registry,
        key.expose(),
        project.as_deref(),
    )
    .map_err(|e| anyhow!("{e}"))?;

    for f in &report.findings {
        let loc = f.coordinate.as_deref().unwrap_or("-");
        println!("{:<5} {}  {}", f.severity.tag(), loc, f.message);
    }
    let errors = report.count(kovra_core::Severity::Error);
    let warnings = report.count(kovra_core::Severity::Warning);
    if report.findings.is_empty() {
        println!("doctor: clean — no findings (env `{env}`).");
    } else {
        println!("doctor: {errors} error(s), {warnings} warning(s) (env `{env}`).");
    }
    // A hard finding fails the command so it can gate CI / pre-commit.
    if report.has_errors() {
        std::process::exit(1);
    }
    Ok(())
}

/// `kovra hooks install` — write a pre-commit secret-scan hook into a repo's
/// `.git/hooks` (L12, KOV-19). The hook scans the staged diff and fails the
/// commit on a finding. Refuses to clobber a foreign pre-commit hook without
/// `--force` (a kovra-written hook is recognized by its marker and replaced).
pub fn hooks_install(
    _ctx: &Ctx,
    path: &Path,
    scanner: kovra_core::Scanner,
    force: bool,
) -> Result<()> {
    let git_dir = path.join(".git");
    if !git_dir.is_dir() {
        bail!(
            "{} is not a git repository (no .git/ directory)",
            path.display()
        );
    }
    let hooks_dir = git_dir.join("hooks");
    std::fs::create_dir_all(&hooks_dir)
        .with_context(|| format!("creating {}", hooks_dir.display()))?;

    let hook_path = hooks_dir.join("pre-commit");
    if hook_path.exists() && !force {
        let existing = std::fs::read_to_string(&hook_path).unwrap_or_default();
        if !existing.contains(kovra_core::HOOK_MARKER) {
            bail!(
                "a pre-commit hook already exists at {} — re-run with --force to replace it",
                hook_path.display()
            );
        }
    }
    std::fs::write(&hook_path, kovra_core::hook_script(scanner))
        .with_context(|| format!("writing {}", hook_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&hook_path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&hook_path, perms)?;
    }

    // Ship a gitleaks config that allowlists `.env.refs` (coordinates, not
    // values) so the committable secret contract never trips the scanner.
    if scanner == kovra_core::Scanner::Gitleaks {
        let cfg = path.join(".gitleaks.toml");
        if !cfg.exists() {
            std::fs::write(&cfg, kovra_core::gitleaks_config())
                .with_context(|| format!("writing {}", cfg.display()))?;
            println!("Wrote {}", cfg.display());
        }
    }

    let bin = scanner.binary();
    println!(
        "Installed the {bin} pre-commit hook at {}.",
        hook_path.display()
    );
    Ok(())
}

/// `kovra audit` — query the audit trail (L12, KOV-20). Renders access/operation
/// history filtered by coordinate/env/component/time/action, annotated with
/// per-coordinate sensitivity. Never a value, never a full fingerprint
/// (I11/I12). Reading the log needs no master key; the sensitivity column is
/// best-effort and omitted if the vault can't be unsealed. **Read-only**: the
/// query never mutates the vault.
pub fn audit_view(
    ctx: &Ctx,
    coordinate: Option<String>,
    env: Option<String>,
    component: Option<String>,
    since: Option<String>,
    until: Option<String>,
    action: Option<String>,
) -> Result<()> {
    let action = match action {
        Some(a) => Some(parse_action(&a)?),
        None => None,
    };
    // Accept the user-facing `secret:` / `secret://global/` form and normalize to
    // the canonical `env/component/key` the audit log records.
    let coordinate = coordinate.map(|c| {
        c.trim_start_matches("secret:")
            .trim_start_matches("//global/")
            .to_string()
    });
    // A bare `YYYY-MM-DD` is widened to span the whole day, so a lexical RFC-3339
    // comparison does the intuitive thing (`--until 2026-06-01` includes that day).
    let since = since.map(|s| widen_date(&s, "T00:00:00Z"));
    let until = until.map(|u| widen_date(&u, "T23:59:59Z"));

    let path = ctx.root.join(kovra_core::AUDIT_LOG);
    let events = kovra_core::read_log(&path).map_err(|e| anyhow!("{e}"))?;
    let query = kovra_core::AuditQuery {
        coordinate,
        environment: env,
        component,
        since,
        until,
        action,
    };
    let filtered = kovra_core::query_log(events, &query);

    let sensitivity = sensitivity_inventory(ctx).unwrap_or_default();
    print!("{}", kovra_core::render_log(&filtered, &sensitivity));
    println!("{} event(s).", filtered.len());
    Ok(())
}

/// Widen a bare `YYYY-MM-DD` to a full RFC-3339 instant by appending `suffix`;
/// any other (already time-bearing) string is returned unchanged.
fn widen_date(s: &str, suffix: &str) -> String {
    let b = s.as_bytes();
    let is_bare_date = b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit());
    if is_bare_date {
        format!("{s}{suffix}")
    } else {
        s.to_string()
    }
}

/// Parse an `--action` filter into an [`AuditAction`] (kebab-case via serde).
fn parse_action(s: &str) -> Result<AuditAction> {
    serde_json::from_value::<AuditAction>(serde_json::Value::String(s.to_string())).map_err(|_| {
        anyhow!("unknown action `{s}` (e.g. reveal, inject, create, provider-invocation, deny)")
    })
}

/// `coordinate -> sensitivity` read directly from the vault records (global +
/// projects). **Read-only** — unlike a redb index rebuild, this never writes to
/// the vault or takes the index write lock; it reads the same metadata the redb
/// index caches (the index is maintained by the write paths / `rebuild_from`,
/// not by this query).
fn sensitivity_inventory(ctx: &Ctx) -> Result<std::collections::BTreeMap<String, Sensitivity>> {
    let key = ctx.master_key()?;
    let mut map = std::collections::BTreeMap::new();
    collect_sensitivities(&ctx.registry.global_dir(), key.expose(), &mut map)?;
    for name in ctx.registry.list_projects().map_err(|e| anyhow!("{e}"))? {
        collect_sensitivities(&ctx.registry.project_dir(&name), key.expose(), &mut map)?;
    }
    Ok(map)
}

fn collect_sensitivities(
    dir: &Path,
    key: &[u8; kovra_core::KEY_LEN],
    map: &mut std::collections::BTreeMap<String, Sensitivity>,
) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for (_, record) in store::load_all(dir, key)
        .map_err(|e| anyhow!("{e}"))?
        .records
    {
        map.insert(record.canonical_path(), record.sensitivity());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovra_core::MockConfirmer;

    fn temp_ctx() -> (Ctx, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let registry = Registry::open(dir.path()).unwrap();
        let ctx = Ctx {
            root: dir.path().to_path_buf(),
            registry,
            clock: kovra_core::SystemClock,
        };
        (ctx, dir)
    }

    fn row(origin: &str, coordinate: &str, sensitivity: &str, fp: &str) -> Row {
        let (env, rest) = coordinate.split_once('/').unwrap_or(("", coordinate));
        let comp = rest.split_once('/').map(|(c, _)| c).unwrap_or("");
        Row {
            origin: origin.to_string(),
            coordinate: coordinate.to_string(),
            environment: env.to_string(),
            component: comp.to_string(),
            sensitivity: sensitivity.to_string(),
            mode: "literal".to_string(),
            fingerprint: fp.to_string(),
        }
    }

    // The inventory table renders every row (header + each coordinate) and is not
    // truncated when an origin is wider than the others — the regression that the
    // old fixed-width formatter hit (a long `project:…` pushed columns out of line).
    #[test]
    fn list_table_renders_all_rows_and_header() {
        let rows = vec![
            row("global", "ops/ai/anthropic-api-key", "low", "a720da3b"),
            row(
                "project:einvoice-generator",
                "prod/factura-facil/password",
                "high",
                "8f22982c",
            ),
        ];
        let out = render_list_table(&rows, &std::collections::BTreeSet::new());
        for needle in [
            "ORIGIN",
            "COORDINATE",
            "FINGERPRINT",
            "project:einvoice-generator",
            "ops/ai/anthropic-api-key",
            "prod/factura-facil/password",
        ] {
            assert!(out.contains(needle), "table missing {needle:?}:\n{out}");
        }
    }

    // A project coordinate that also exists in the global vault is flagged in the
    // fingerprint column (§9.3), and only then.
    #[test]
    fn list_table_marks_shadowed_coordinate() {
        let coord = "dev/backend/database-url";
        let rows = vec![
            row("global", coord, "low", "aaaaaaaa"),
            row("project:synaptyc-app", coord, "injectonly", "bbbbbbbb"),
        ];
        let mut shadowed = std::collections::BTreeSet::new();
        shadowed.insert(coord.to_string());
        let out = render_list_table(&rows, &shadowed);
        assert!(
            out.contains("*shadows global"),
            "expected shadow mark:\n{out}"
        );
        // Exactly one row carries the marker (the project row, not the global one).
        assert_eq!(out.matches("*shadows global").count(), 1);
    }

    // KOV-33 (I3/I5) — a CLI sensitivity downgrade confirms an *action*, so its
    // request offers the device-password fallback ("Use Password"), aligning with
    // the Web UI downgrade gate (KOV-30). The secret broker stays biometric-only.
    #[test]
    fn downgrade_request_allows_password() {
        let req =
            downgrade_confirm_request("dev/app/token", Sensitivity::High, Sensitivity::Low, "dev");
        assert!(req.allow_password, "downgrade must offer Use Password");
        // It is still a secret-scoped request (not a generic action) carrying the
        // resolved command for the I16 authoritative headline.
        assert!(req.action.is_none());
        assert_eq!(req.sensitivity, Sensitivity::High);
        assert!(
            req.resolved_command
                .as_deref()
                .is_some_and(|c| c.contains("--sensitivity low")),
            "command should describe the downgrade: {:?}",
            req.resolved_command
        );
    }

    // KOV-30 (I3) — opening the admin UI is an attended action: the gate proceeds
    // only on an approved confirmation.
    #[test]
    fn ui_launch_gate_approved_is_ok() {
        let (ctx, _d) = temp_ctx();
        let broker = MockConfirmer::always(ConfirmOutcome::Approved);
        assert!(run_ui_launch_gate(&ctx, &broker).is_ok());
    }

    // KOV-30 (I3) — a denied or timed-out confirmation refuses to start the UI
    // (fails safe, §8).
    #[test]
    fn ui_launch_gate_denied_or_timeout_errs() {
        let (ctx, _d) = temp_ctx();
        assert!(run_ui_launch_gate(&ctx, &MockConfirmer::always(ConfirmOutcome::Denied)).is_err());
        assert!(
            run_ui_launch_gate(&ctx, &MockConfirmer::always(ConfirmOutcome::TimedOut)).is_err()
        );
    }

    // KOV-30 — `--no-confirm` (KOVRA_UI_NO_CONFIRM) bypasses the gate entirely.
    #[test]
    fn ui_launch_no_confirm_bypasses() {
        let (ctx, _d) = temp_ctx();
        assert!(confirm_ui_launch(&ctx, true).is_ok());
    }

    // KOV-49 (DQ-13, I6) — the `docker run` argv never carries the master key
    // *value*: the key is staged as a tmpfs secret file and mounted, and only the
    // in-container *path* to that file is passed via `-e`. Also locks the
    // pull-only published image tag (no `docker build`, no `:local`).
    #[test]
    fn docker_run_args_never_carry_key_value() {
        // A representative staged-key hex value (as `stage_secret_dir` would write
        // to the mounted file). It must NOT leak into argv anywhere.
        let key_hex = "deadbeefcafef00d0011223344556677";
        let args = docker_run_args(
            "kovra-ui-8731",
            "127.0.0.1:8731:8731",
            "type=bind,src=/Users/x/.vaults,dst=/vaults",
            "type=bind,src=/tmp/kovra-ui-secret-abcd,dst=/run/secrets,ro",
            8731,
            900,
            "00112233445566778899aabbccddeeff",
        );
        // I6: the key value appears in no argument.
        assert!(
            args.iter().all(|a| !a.contains(key_hex)),
            "master key value leaked into docker argv: {args:?}"
        );
        // The secret reaches the container only as a file path, never a value.
        assert!(
            args.iter()
                .any(|a| a == "KOVRA_MASTER_KEY_FILE=/run/secrets/kovra_master_key"),
            "expected the tmpfs secret file path env: {args:?}"
        );
        assert!(
            !args.iter().any(|a| a.starts_with("KOVRA_MASTER_KEY=")),
            "the key must never be passed as an env value: {args:?}"
        );
        // Decision #3 (pull-only): the published, version-pinned GHCR image is the
        // last arg; the old local-build tag is gone.
        assert_eq!(args.last().map(String::as_str), Some(UI_IMAGE_TAG));
        assert!(
            UI_IMAGE_TAG.starts_with("ghcr.io/kaeus-inc/kovra-ui:"),
            "image must be the published GHCR tag, got {UI_IMAGE_TAG}"
        );
        assert!(
            !args.iter().any(|a| a.contains("kovra-ui:local")),
            "the local-build tag must be gone: {args:?}"
        );
    }
}
