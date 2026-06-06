//! The agent session: a registry root, the master key, and a fixed
//! [`AgentScope`]. All metadata reads route through [`kovra_core::policy::decide`]
//! with `Surface::Mcp` / `Origin::Agent`, so scope is enforced first (I13) and
//! no value ever leaves through a metadata call.
//!
//! This module is pure Rust (no pyo3) so the policy routing is unit-tested
//! without a Python interpreter. The pyo3 `KovraSession` in `lib.rs` is a thin
//! wrapper that marshals these results into Python objects.

use std::env;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use kovra_core::{
    AccessRequest, AgentScope, Argon2Keyring, AuditAction, AuditEvent, AuditSink, Clock,
    Coordinate, Decision, EnvRefs, EnvSegment, FileAuditSink, FileConfirmer, Keyring, MasterKey,
    MockKeyring, Operation, Origin, OsKeyring, Registry, Resolution, SchemeRouter, SecretProvider,
    SecretRecord, SecretValue, Sensitivity, Source, Surface, SystemClock, SystemEnvSource,
    VaultOrigin, birth_sensitivity, decide, fingerprint, is_downgrade, seal, store,
};
use kovra_providers_aws::{AwsProvider, SystemAwsRunner};
use kovra_providers_azure::{AzureProvider, SystemAzRunner};
use kovra_wrapper::{Allowlist, ProcessRunner, SystemRunner, Wrapper, WrapperError};

use crate::errors::FfiError;

/// How long an injection confirmation may wait before failing safe to denial
/// (§8) — matches the CLI default.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(120);
const ALLOWLIST_FILE: &str = "allowlist";

/// Override for the registry root (mirrors the CLI; spec §10.2).
const VAULT_DIR_ENV: &str = "KOVRA_VAULT_DIR";
/// When set, use the Argon2 passphrase backend instead of the OS keyring.
const PASSPHRASE_ENV: &str = "KOVRA_PASSPHRASE";
const SALT_FILE: &str = "kdf.salt";

/// A flattened, value-free view of a secret record — what the agent metadata
/// surface returns. Never carries plaintext (I11/I12); the fingerprint is the
/// truncated BLAKE3 marker, only useful for "did I update the right value?".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordView {
    pub coordinate: String,
    pub environment: String,
    pub component: String,
    pub key: String,
    pub sensitivity: String,
    pub mode: String,
    pub fingerprint: String,
    pub revealable: bool,
    pub origin: String,
    pub reference: Option<String>,
}

/// The result of an `inject_run`: the child's exit status and its (sanitized,
/// §5.1) output. Vault-backed values injected into the child are masked here.
#[derive(Debug, Clone)]
pub struct InjectOutput {
    pub status: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// An agent session bound to a registry root and a fixed scope.
pub struct Session {
    root: PathBuf,
    registry: Registry,
    scope: AgentScope,
    master: MasterKey,
    clock: SystemClock,
}

impl Session {
    /// Construct from an already-derived master key (the unit-test entry point —
    /// no keyring, no env). `root` must contain (or will get) `global/`.
    pub fn with_master(
        root: PathBuf,
        scope: AgentScope,
        master: MasterKey,
    ) -> Result<Self, FfiError> {
        let registry = Registry::open(&root)?;
        Ok(Self {
            root,
            registry,
            scope,
            master,
            clock: SystemClock,
        })
    }

    /// Resolve root + keyring backend from explicit args, falling back to env
    /// (`KOVRA_VAULT_DIR` / `KOVRA_PASSPHRASE`) exactly like the CLI context.
    pub fn open(
        vault_dir: Option<PathBuf>,
        scope: AgentScope,
        passphrase: Option<String>,
    ) -> Result<Self, FfiError> {
        let root = match vault_dir.or_else(|| env::var_os(VAULT_DIR_ENV).map(PathBuf::from)) {
            Some(p) => p,
            None => Registry::default_root()?,
        };
        let passphrase = passphrase.or_else(|| env::var(PASSPHRASE_ENV).ok());
        let keyring: Box<dyn Keyring> = match passphrase {
            Some(pass) => {
                let salt = std::fs::read(root.join(SALT_FILE)).map_err(|_| {
                    FfiError::Config(format!(
                        "reading {SALT_FILE} from the vault root (run `kovra init` first)"
                    ))
                })?;
                Box::new(Argon2Keyring::new(pass.into_bytes(), salt)?)
            }
            None => Box::new(OsKeyring::new()),
        };
        let master = keyring
            .get_master_key()
            .map_err(|_| FfiError::Config("obtaining the master key (run `kovra init`?)".into()))?;
        Self::with_master(root, scope, master)
    }

    /// Whether the coordinate (under `project`) is addressable for `operation`
    /// in this session — the I13 gate, evaluated *before* any vault read.
    ///
    /// Sensitivity/revealable are irrelevant for `Metadata` (they only gate
    /// reveal/inject), so a neutral request suffices here.
    fn addressable(&self, coord: &Coordinate, project: Option<&str>, operation: Operation) -> bool {
        let req = AccessRequest {
            coordinate: coord,
            project,
            sensitivity: Sensitivity::Low,
            revealable: false,
            operation,
            surface: Surface::Mcp,
            origin: Origin::Agent,
        };
        decide(&req, &self.scope) == Decision::Allow
    }

    /// List every record addressable for metadata in this session. Out-of-scope
    /// coordinates are simply absent (I13) — never surfaced and then filtered by
    /// the caller.
    pub fn list_visible(&self) -> Result<Vec<RecordView>, FfiError> {
        let key = self.master.expose();
        let mut views = Vec::new();

        // Global vault (project = None).
        for (_, record) in store::load_all(&self.registry.global_dir(), key)?.records {
            if let Some(coord) = coord_of(&record)
                && self.addressable(&coord, None, Operation::Metadata)
            {
                views.push(view_of(&record, VaultOrigin::Global));
            }
        }

        // Project vaults (project = Some(name)).
        for name in self.registry.list_projects()? {
            let dir = self.registry.project_dir(&name);
            for (_, record) in store::load_all(&dir, key)?.records {
                if let Some(coord) = coord_of(&record)
                    && self.addressable(&coord, Some(&name), Operation::Metadata)
                {
                    views.push(view_of(&record, VaultOrigin::Project(name.clone())));
                }
            }
        }
        Ok(views)
    }

    /// Metadata for one coordinate (diagnose). Scope is gated first (I13): an
    /// out-of-scope or absent coordinate both raise `NotFound`.
    pub fn status_of(
        &self,
        coordinate: &str,
        project: Option<&str>,
    ) -> Result<RecordView, FfiError> {
        let coord = parse_concrete(coordinate)?;
        if !self.addressable(&coord, project, Operation::Metadata) {
            return Err(FfiError::NotFound); // I13: indistinguishable from absent
        }
        match self
            .registry
            .resolve_with_key(&coord, project, self.master.expose())?
        {
            Resolution::Found { record, origin } => Ok(view_of(&record, origin)),
            Resolution::NotFound => Err(FfiError::NotFound),
        }
    }

    /// The truncated fingerprint of a coordinate's value, or `NotFound`. For a
    /// reference (no stored value) the fingerprint is the pointer marker.
    pub fn fingerprint_of(
        &self,
        coordinate: &str,
        project: Option<&str>,
    ) -> Result<String, FfiError> {
        Ok(self.status_of(coordinate, project)?.fingerprint)
    }

    /// Reveal a value *into* the agent's context — the guarded path (I11/I14).
    ///
    /// Scope is gated first (I13): a coordinate not addressable for `Reveal` in
    /// this session is `NotFound`, never leaking its existence. For an
    /// addressable secret, [`decide`] over the record's own sensitivity and
    /// `revealable` flag is authoritative: MCP reveals **only** a `revealable`,
    /// non-`prod`, non-`high` literal (I11); `prod` is always denied (I14), as
    /// are `high` and `inject-only`. A denial is audited (supervision, §11).
    pub fn reveal(&self, coordinate: &str, project: Option<&str>) -> Result<Vec<u8>, FfiError> {
        let coord = parse_concrete(coordinate)?;
        // I13 pre-gate: scope only — do not even resolve an out-of-scope coord,
        // and never reveal that it exists.
        if !self.scope.addresses(&coord, project) || !self.scope.permits(Operation::Reveal) {
            return Err(FfiError::NotFound);
        }
        let record = match self
            .registry
            .resolve_with_key(&coord, project, self.master.expose())?
        {
            Resolution::Found { record, .. } => record,
            Resolution::NotFound => return Err(FfiError::NotFound),
        };
        // A reference holds no value (I8) — there is nothing to reveal here. A
        // keypair's private half is NEVER returned to the model (I11/I14): it is
        // a private-key op (used only *through* sign/decrypt/ssh-add), so reveal
        // over MCP is refused regardless of the `revealable` flag.
        let value = match &record {
            SecretRecord::Literal { value, .. } => value.expose().to_vec(),
            SecretRecord::Reference { .. } => {
                return Err(FfiError::Denied(
                    "reference value is materialized at run time, not revealable over MCP".into(),
                ));
            }
            SecretRecord::Keypair { .. } => {
                return Err(FfiError::Denied(
                    "a keypair's private key is never revealed (I11/I14); use it through sign/decrypt/ssh-add via the CLI".into(),
                ));
            }
            SecretRecord::Totp { .. } => {
                return Err(FfiError::Denied(
                    "a TOTP seed is never revealed (I11/I14); derive a code on demand with `kovra code` via the CLI".into(),
                ));
            }
        };
        // The record's own flags drive the decision — never caller intent (I11).
        let req = AccessRequest {
            coordinate: &coord,
            project,
            sensitivity: record.sensitivity(),
            revealable: record.revealable(),
            operation: Operation::Reveal,
            surface: Surface::Mcp,
            origin: Origin::Agent,
        };
        let canonical = coord.canonical_path()?;
        let env = env_of(&coord);
        match decide(&req, &self.scope) {
            Decision::Allow => {
                self.audit(AuditAction::Reveal, "revealed", &canonical, &env);
                Ok(value)
            }
            Decision::Deny(reason) => {
                self.audit(AuditAction::Deny, "denied", &canonical, &env);
                Err(FfiError::Denied(format!("{reason:?}")))
            }
            // Caught by the pre-gate already; kept exhaustive.
            Decision::Unaddressable => Err(FfiError::NotFound),
            // MCP reveal never reaches an interactive confirmation.
            Decision::RequireConfirmation => Err(FfiError::Denied(
                "reveal requires attended confirmation (not available over MCP)".into(),
            )),
        }
    }

    /// Resolve an `.env.refs` and run `program args...` with the values injected
    /// into the child's environment (never argv/disk, I7). High/prod injection
    /// requires the executor to be on the allowlist (I15) **and** an attended
    /// confirmation via the cross-process broker (I3/I16) — exactly the CLI +
    /// `kovra approve` path, with `Origin::Agent`. The agent never sees a value;
    /// it only drives the run, and vault values are masked in the output (§5.1).
    ///
    /// `client_identity` is the **trusted, observed** caller identity for the
    /// I16 prompt (§8.3): the MCP server passes the agent/client/session name it
    /// authenticated (e.g. `"Claude Code (session abc123)"`) through this trusted
    /// PyO3 boundary, and it is rendered as the requesting process on the
    /// confirmation dialog. It is NOT the spoofable requester free-text
    /// (`requester_description` stays fenced) and never carries a value (I7/I12).
    /// `None` simply omits the line.
    pub fn inject_run(
        &self,
        refs_content: &str,
        env: &str,
        program: &str,
        args: &[String],
        project: Option<&str>,
        client_identity: Option<&str>,
    ) -> Result<InjectOutput, FfiError> {
        let runner = SystemRunner;
        let confirmer = FileConfirmer::under_root(&self.root);
        let audit = FileAuditSink::under_root(&self.root);
        let allowlist = load_allowlist(&self.root);
        // L6: dispatch references by scheme — Azure Key Vault via the real `az`
        // CLI (ambient identity, §6.2). A materialized reference still flows
        // through the normal policy path: it is injected into the child env only,
        // never returned to the model (I11/I14).
        let provider = build_router();
        self.inject_run_with(
            refs_content,
            env,
            program,
            args,
            project,
            client_identity,
            &allowlist,
            &runner,
            &confirmer,
            &audit,
            &provider,
            CONFIRM_TIMEOUT,
        )
    }

    /// Testable core of [`inject_run`]: the runner, confirmer, audit sink, and
    /// allowlist are injected so the I7/I15/I16 path can be exercised with mocks
    /// (no real child, no real broker). The scope gate (I13) and `Origin::Agent`
    /// wiring live here; everything else is the Wrapper's job (L5).
    #[allow(clippy::too_many_arguments)]
    fn inject_run_with(
        &self,
        refs_content: &str,
        env: &str,
        program: &str,
        args: &[String],
        project: Option<&str>,
        client_identity: Option<&str>,
        allowlist: &Allowlist,
        runner: &dyn ProcessRunner,
        confirmer: &dyn kovra_core::Confirmer,
        audit: &dyn AuditSink,
        provider: &dyn SecretProvider,
        timeout: Duration,
    ) -> Result<InjectOutput, FfiError> {
        // The session must be granted the inject operation at all (I13).
        if !self.scope.permits(Operation::Inject) {
            return Err(FfiError::NotFound);
        }
        let refs = EnvRefs::parse(refs_content)?;
        let effective_project = project.or(refs.project.as_deref());

        // I13 — every referenced vault coordinate must be addressable in scope,
        // gated *before* the wrapper resolves or launches anything. An
        // out-of-scope reference is `NotFound`: the run never starts and the
        // coordinate's existence is not revealed.
        for (_, source) in &refs.vars {
            if let Source::Uri { uri, .. } = source {
                let coord =
                    Coordinate::from_str(uri).map_err(|e| FfiError::Config(e.to_string()))?;
                let concrete = match &coord.environment {
                    EnvSegment::Placeholder => coord.with_env(env),
                    EnvSegment::Literal(_) => coord,
                };
                if !self.scope.addresses(&concrete, effective_project) {
                    return Err(FfiError::NotFound);
                }
            }
        }

        // Feed the wrapper the session's master key via an in-memory keyring.
        // References are materialized through the injected `provider` (the L6
        // scheme router) — never returned to the model, only injected (I11/I14).
        let keyring = MockKeyring::with_key(*self.master.expose());
        let env_source = SystemEnvSource;
        let wrapper = Wrapper {
            registry: &self.registry,
            keyring: &keyring,
            env_source: &env_source,
            provider,
            confirmer,
            audit,
            clock: &self.clock,
            allowlist,
            runner,
            confirm_timeout: timeout,
            sanitize_output: true,
            // I16 (§8.3): the requesting process is the MCP client identity the
            // server authenticated and threaded through this trusted PyO3
            // boundary — NOT the observed OS parent (which here is just the MCP
            // host), and NOT untrusted requester text.
            requesting_process: client_identity.map(str::to_owned),
        };
        let program_path = PathBuf::from(program);
        match wrapper.run(
            &refs,
            env,
            effective_project,
            &program_path,
            args,
            Origin::Agent,
        ) {
            Ok(out) => Ok(InjectOutput {
                status: out.status,
                stdout: out.stdout,
                stderr: out.stderr,
            }),
            Err(e) => Err(map_wrapper_err(e)),
        }
    }

    // ───────────────────────────── writes ─────────────────────────────
    //
    // Writes are contained by **addressability** (the env/project filter, I13):
    // a session may only mutate coordinates it can address. The operation axis
    // (metadata/inject/reveal) governs value *flow*, not mutation, so it is not
    // consulted here. Every write is `Origin::Agent` and audited (I12); no write
    // returns a value (I6) — `generate`'s value is born server-side and only its
    // metadata comes back.

    /// Create or update a literal value (the agent provides the value as a tool
    /// argument — never argv, I6). New secrets are born per I5 (`prod` ⇒ `high`);
    /// updates preserve sensitivity/revealable/description/created.
    pub fn set(
        &self,
        coordinate: &str,
        value: &str,
        project: Option<&str>,
    ) -> Result<RecordView, FfiError> {
        let coord = parse_concrete(coordinate)?;
        self.require_addressable(&coord, project)?;
        let env = env_of(&coord);
        let dir = self.vault_dir(project);
        let key = self.master.expose();
        let now = self.clock.now_rfc3339();

        let (sensitivity, revealable, description, created, action) =
            match store::read_record(&dir, &coord, key)? {
                // A keypair is not a plain value — its key material is created
                // via the CLI (`keygen` / `add --public-key`), never overwritten
                // by `set`, which would silently change the modality.
                Some(SecretRecord::Keypair { .. }) => {
                    return Err(FfiError::Config(format!(
                        "`{coordinate}` is a keypair; it cannot be overwritten with `set`"
                    )));
                }
                // A TOTP enrollment is not a plain value — re-enroll via the CLI
                // (`kovra add --totp`), never overwrite with `set`.
                Some(SecretRecord::Totp { .. }) => {
                    return Err(FfiError::Config(format!(
                        "`{coordinate}` is a TOTP enrollment; it cannot be overwritten with `set`"
                    )));
                }
                Some(existing) => {
                    let (s, r, d, c) = preserved(&existing);
                    (s, r, d, c, AuditAction::Edit)
                }
                None => (
                    birth_sensitivity(&env, Sensitivity::Medium), // I5
                    false,
                    None,
                    now.clone(),
                    AuditAction::Create,
                ),
            };
        let record = SecretRecord::Literal {
            value: SecretValue::from(value.to_string()),
            sensitivity,
            revealable,
            environment: env.clone(),
            component: coord.component.clone(),
            key: coord.key.clone(),
            description,
            created,
            updated: now,
        };
        store::write_record(&dir, &coord, &seal(&record, key)?)?;
        let canonical = coord.canonical_path()?;
        let result = if matches!(action, AuditAction::Create) {
            "created"
        } else {
            "value-updated"
        };
        self.audit(action, result, &canonical, &env);
        Ok(view_of(&record, origin_for(project)))
    }

    /// Generate a random value server-side, store it, and return **only its
    /// metadata** — the value never crosses back to the model (I6, AC3). Born
    /// per I5. Errors if the coordinate already exists.
    pub fn generate(
        &self,
        coordinate: &str,
        length: usize,
        sensitivity: Option<&str>,
        description: Option<String>,
        project: Option<&str>,
    ) -> Result<RecordView, FfiError> {
        let coord = parse_concrete(coordinate)?;
        self.require_addressable(&coord, project)?;
        if length == 0 {
            return Err(FfiError::Config("length must be at least 1".into()));
        }
        let env = env_of(&coord);
        let dir = self.vault_dir(project);
        let key = self.master.expose();
        if store::read_record(&dir, &coord, key)?.is_some() {
            return Err(FfiError::Config(format!("`{coordinate}` already exists")));
        }
        let chosen = match sensitivity {
            Some(s) => parse_sensitivity(s)?,
            None => Sensitivity::Medium,
        };
        let born = birth_sensitivity(&env, chosen);

        use rand::Rng;
        use rand::distributions::Alphanumeric;
        let generated: String = rand::rngs::OsRng
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect();
        let now = self.clock.now_rfc3339();
        let record = SecretRecord::Literal {
            value: SecretValue::from(generated),
            sensitivity: born,
            revealable: false,
            environment: env.clone(),
            component: coord.component.clone(),
            key: coord.key.clone(),
            description,
            created: now.clone(),
            updated: now,
        };
        store::write_record(&dir, &coord, &seal(&record, key)?)?;
        let canonical = coord.canonical_path()?;
        self.audit(AuditAction::Create, "generated", &canonical, &env);
        Ok(view_of(&record, origin_for(project))) // metadata only — never the value
    }

    /// Delete a secret. Out-of-scope or absent → `NotFound` (I13).
    pub fn delete(&self, coordinate: &str, project: Option<&str>) -> Result<(), FfiError> {
        let coord = parse_concrete(coordinate)?;
        self.require_addressable(&coord, project)?;
        let dir = self.vault_dir(project);
        if store::read_record(&dir, &coord, self.master.expose())?.is_none() {
            return Err(FfiError::NotFound);
        }
        store::delete_record(&dir, &coord)?;
        let canonical = coord.canonical_path()?;
        self.audit(AuditAction::Delete, "deleted", &canonical, &env_of(&coord));
        Ok(())
    }

    /// Edit metadata (sensitivity / description / revealable / reference). A
    /// sensitivity *downgrade* is a deliberate, separately audited act (I5).
    pub fn edit_metadata(
        &self,
        coordinate: &str,
        sensitivity: Option<&str>,
        description: Option<String>,
        revealable: Option<bool>,
        reference: Option<String>,
        project: Option<&str>,
    ) -> Result<RecordView, FfiError> {
        let coord = parse_concrete(coordinate)?;
        self.require_addressable(&coord, project)?;
        let dir = self.vault_dir(project);
        let key = self.master.expose();
        let existing = store::read_record(&dir, &coord, key)?.ok_or(FfiError::NotFound)?;
        let env = env_of(&coord);
        let new_sensitivity = match sensitivity {
            Some(s) => Some(parse_sensitivity(s)?),
            None => None,
        };
        let lowered = matches!(new_sensitivity, Some(s) if is_downgrade(existing.sensitivity(), s));
        let now = self.clock.now_rfc3339();
        let updated = apply_edits(
            existing,
            new_sensitivity,
            description,
            reference,
            revealable,
            &env,
            now,
        )?;
        store::write_record(&dir, &coord, &seal(&updated, key)?)?;
        let canonical = coord.canonical_path()?;
        if lowered {
            self.audit(
                AuditAction::SensitivityDowngrade,
                "downgraded",
                &canonical,
                &env,
            );
        }
        self.audit(AuditAction::Edit, "metadata-updated", &canonical, &env);
        Ok(view_of(&updated, origin_for(project)))
    }

    /// The target vault directory: a named project vault, else the global vault.
    fn vault_dir(&self, project: Option<&str>) -> PathBuf {
        match project {
            Some(p) => self.registry.project_dir(p),
            None => self.registry.global_dir(),
        }
    }

    /// Containment gate for writes (I13): the coordinate must be addressable in
    /// this session's scope. Out-of-scope → `NotFound`, indistinguishable from
    /// absent — a write can never reveal the existence of an out-of-scope coord.
    fn require_addressable(
        &self,
        coord: &Coordinate,
        project: Option<&str>,
    ) -> Result<(), FfiError> {
        if self.scope.addresses(coord, project) {
            Ok(())
        } else {
            Err(FfiError::NotFound)
        }
    }

    /// Append an `Origin::Agent` audit record (I12 — action/coordinate/result,
    /// never a value).
    fn audit(&self, action: AuditAction, result: &str, canonical: &str, env: &str) {
        let sink = FileAuditSink::under_root(&self.root);
        let _ = sink.record(
            &AuditEvent::new(&self.clock, action, result)
                .at(canonical, env)
                .by(Origin::Agent),
        );
    }
}

/// Apply metadata edits to a record (mirrors the CLI's `apply_edits`, with the
/// `revealable` knob). Editing the pointer of a literal (or vice versa) is
/// rejected — the modality is fixed.
#[allow(clippy::too_many_arguments)]
fn apply_edits(
    existing: SecretRecord,
    new_sensitivity: Option<Sensitivity>,
    new_description: Option<String>,
    new_reference: Option<String>,
    new_revealable: Option<bool>,
    env: &str,
    now: String,
) -> Result<SecretRecord, FfiError> {
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
                return Err(FfiError::Config(
                    "`reference` edits a reference secret; this is a literal".into(),
                ));
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
            if new_reference.is_some() {
                return Err(FfiError::Config(
                    "`reference` edits a reference secret; this is a keypair".into(),
                ));
            }
            // The key material is immutable through edit; only metadata changes.
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
            if new_reference.is_some() {
                return Err(FfiError::Config(
                    "`reference` edits a reference secret; this is a TOTP enrollment".into(),
                ));
            }
            // The seed/params are immutable through edit; only metadata changes.
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

/// Preserve the metadata of an existing record across a value `set`.
fn preserved(rec: &SecretRecord) -> (Sensitivity, bool, Option<String>, String) {
    match rec {
        SecretRecord::Literal {
            sensitivity,
            revealable,
            description,
            created,
            ..
        }
        | SecretRecord::Reference {
            sensitivity,
            revealable,
            description,
            created,
            ..
        }
        | SecretRecord::Keypair {
            sensitivity,
            revealable,
            description,
            created,
            ..
        }
        | SecretRecord::Totp {
            sensitivity,
            revealable,
            description,
            created,
            ..
        } => (
            *sensitivity,
            *revealable,
            description.clone(),
            created.clone(),
        ),
    }
}

/// The literal environment of a concrete coordinate.
fn env_of(coord: &Coordinate) -> String {
    match &coord.environment {
        EnvSegment::Literal(e) => e.clone(),
        EnvSegment::Placeholder => unreachable!("parse_concrete rejects placeholders"),
    }
}

/// The vault origin a write targets (for the returned [`RecordView`]).
fn origin_for(project: Option<&str>) -> VaultOrigin {
    match project {
        Some(p) => VaultOrigin::Project(p.to_string()),
        None => VaultOrigin::Global,
    }
}

/// Load the executor allowlist from `<root>/allowlist` (one path per line, `#`
/// comments). The agent cannot extend it — only a human edits this file (I15).
fn load_allowlist(root: &Path) -> Allowlist {
    let mut allow = Allowlist::empty();
    if let Ok(content) = std::fs::read_to_string(root.join(ALLOWLIST_FILE)) {
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                allow.allow(PathBuf::from(trimmed));
            }
        }
    }
    allow
}

/// Build the L6 provider router (mirrors the CLI's wiring point): the Azure Key
/// Vault provider over the real `az` CLI and the AWS Secrets Manager provider over
/// the real `aws` CLI, dispatched by URI scheme. `core` stays free of any provider
/// crate (§6.1); an unknown scheme falls through to a clear "unsupported scheme"
/// error. Adding another provider is one `.with(...)` here.
fn build_router() -> SchemeRouter {
    SchemeRouter::new()
        .with(Box::new(AzureProvider::new(SystemAzRunner)))
        .with(Box::new(AwsProvider::new(SystemAwsRunner)))
}

/// Map a wrapper error to the binding error. The injection-gate refusals
/// (allowlist / denied / timed-out) are `Denied`; anything else is a config /
/// runtime problem.
fn map_wrapper_err(e: WrapperError) -> FfiError {
    match e {
        WrapperError::NotAllowlisted { .. }
        | WrapperError::ConfirmationDenied
        | WrapperError::ConfirmationTimedOut => FfiError::Denied(e.to_string()),
        other => FfiError::Config(other.to_string()),
    }
}

/// Parse a sensitivity name (`low|medium|high|inject-only`, case-insensitive).
fn parse_sensitivity(s: &str) -> Result<Sensitivity, FfiError> {
    match s.to_ascii_lowercase().replace('_', "-").as_str() {
        "low" => Ok(Sensitivity::Low),
        "medium" => Ok(Sensitivity::Medium),
        "high" => Ok(Sensitivity::High),
        "inject-only" | "injectonly" => Ok(Sensitivity::InjectOnly),
        other => Err(FfiError::Config(format!(
            "unknown sensitivity `{other}` (expected low|medium|high|inject-only)"
        ))),
    }
}

/// Parse a concrete coordinate (`secret:env/component/key`); reject `${ENV}`.
fn parse_concrete(s: &str) -> Result<Coordinate, FfiError> {
    let coord = Coordinate::from_str(s).map_err(|e| FfiError::Config(e.to_string()))?;
    coord.canonical_path().map_err(|e| {
        FfiError::Config(format!("{e} (a coordinate must be concrete, not ${{ENV}})"))
    })?;
    Ok(coord)
}

/// Reconstruct a concrete coordinate from a stored record's segments.
fn coord_of(record: &SecretRecord) -> Option<Coordinate> {
    let (env, comp, key) = match record {
        SecretRecord::Literal {
            environment,
            component,
            key,
            ..
        }
        | SecretRecord::Reference {
            environment,
            component,
            key,
            ..
        }
        | SecretRecord::Keypair {
            environment,
            component,
            key,
            ..
        }
        | SecretRecord::Totp {
            environment,
            component,
            key,
            ..
        } => (environment, component, key),
    };
    Coordinate::from_str(&format!("secret:{env}/{comp}/{key}")).ok()
}

/// Flatten a record into a value-free [`RecordView`]. For a keypair the
/// fingerprint is of the **public** key (never the private half, I12); the mode
/// distinguishes a full keypair from a public-only entry. The private key never
/// enters a view (there is no field for it).
fn view_of(record: &SecretRecord, origin: VaultOrigin) -> RecordView {
    let origin = match origin {
        VaultOrigin::Global => "global".to_string(),
        VaultOrigin::Project(name) => format!("project:{name}"),
    };
    let (mode, print, reference) = match record {
        SecretRecord::Literal { value, .. } => {
            ("literal".to_string(), fingerprint(value.expose()), None)
        }
        SecretRecord::Reference { reference, .. } => (
            "reference".to_string(),
            format!("→ {reference}"),
            Some(reference.clone()),
        ),
        SecretRecord::Keypair {
            algorithm,
            private,
            public,
            ..
        } => {
            let mode = if private.is_some() {
                format!("keypair:{}", algorithm.as_str())
            } else {
                format!("pubkey:{}", algorithm.as_str())
            };
            (mode, fingerprint(public.as_bytes()), None)
        }
        SecretRecord::Totp {
            algorithm,
            digits,
            period,
            ..
        } => {
            // The fingerprint is of the non-secret params only — never the seed
            // (I12). The mode carries the algorithm so a view distinguishes
            // enrollments without ever touching the seed.
            let mode = format!("totp:{}", algorithm.as_str().to_lowercase());
            (
                mode,
                fingerprint(format!("totp:{}:{digits}:{period}", algorithm.as_str()).as_bytes()),
                None,
            )
        }
    };
    let (env, comp, key) = match record {
        SecretRecord::Literal {
            environment,
            component,
            key,
            ..
        }
        | SecretRecord::Reference {
            environment,
            component,
            key,
            ..
        }
        | SecretRecord::Keypair {
            environment,
            component,
            key,
            ..
        }
        | SecretRecord::Totp {
            environment,
            component,
            key,
            ..
        } => (environment.clone(), component.clone(), key.clone()),
    };
    RecordView {
        coordinate: format!("{env}/{comp}/{key}"),
        environment: env,
        component: comp,
        key,
        sensitivity: format!("{:?}", record.sensitivity()).to_lowercase(),
        mode,
        fingerprint: print,
        revealable: record.revealable(),
        origin,
        reference,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovra_core::{Filter, KEY_LEN, SecretValue, seal};
    use std::collections::BTreeSet;

    const KEY: [u8; KEY_LEN] = [7u8; KEY_LEN];

    fn literal(
        env: &str,
        comp: &str,
        key: &str,
        sens: Sensitivity,
        revealable: bool,
    ) -> SecretRecord {
        SecretRecord::Literal {
            value: SecretValue::from(format!("val-{env}-{comp}-{key}")),
            sensitivity: sens,
            revealable,
            environment: env.to_string(),
            component: comp.to_string(),
            key: key.to_string(),
            description: None,
            created: "2026-05-30T00:00:00Z".to_string(),
            updated: "2026-05-30T00:00:00Z".to_string(),
        }
    }

    fn write(dir: &std::path::Path, record: &SecretRecord) {
        let coord = coord_of(record).unwrap();
        store::write_record(dir, &coord, &seal(record, &KEY).unwrap()).unwrap();
    }

    /// Build a session over a temp vault with the given scope, seeded with a
    /// dev/medium (revealable), a test/medium, and a prod/high secret.
    fn seeded_session(scope: AgentScope) -> (tempfile::TempDir, Session) {
        let tmp = tempfile::tempdir().unwrap();
        let registry = Registry::open(tmp.path()).unwrap();
        let global = registry.global_dir();
        write(
            &global,
            &literal("dev", "app", "key", Sensitivity::Medium, true),
        );
        write(
            &global,
            &literal("test", "app", "token", Sensitivity::Medium, false),
        );
        write(
            &global,
            &literal("prod", "db", "password", Sensitivity::High, false),
        );
        let session =
            Session::with_master(tmp.path().to_path_buf(), scope, MasterKey::new(KEY)).unwrap();
        (tmp, session)
    }

    fn metadata_scope(envs: Option<Vec<&str>>) -> AgentScope {
        let mut operations = BTreeSet::new();
        operations.insert(Operation::Metadata);
        AgentScope {
            operations,
            projects: Filter::Any,
            environments: match envs {
                None => Filter::Any,
                Some(list) => Filter::only(list),
            },
        }
    }

    // I13 — `list` surfaces only in-scope coordinates; prod is *absent* under a
    // dev/test-only scope, not present-but-denied.
    #[test]
    fn i13_list_omits_out_of_scope_coordinates() {
        let (_tmp, session) = seeded_session(metadata_scope(Some(vec!["dev", "test"])));
        let coords: BTreeSet<String> = session
            .list_visible()
            .unwrap()
            .into_iter()
            .map(|v| v.coordinate)
            .collect();
        assert!(coords.contains("dev/app/key"));
        assert!(coords.contains("test/app/token"));
        assert!(
            !coords.contains("prod/db/password"),
            "prod is out of scope and must not appear (I13)"
        );
    }

    // I13 — `status` of an out-of-scope coordinate is indistinguishable from an
    // absent one: both `NotFound`.
    #[test]
    fn i13_status_out_of_scope_is_not_found_like_absent() {
        let (_tmp, session) = seeded_session(metadata_scope(Some(vec!["dev"])));
        // out of scope (prod excluded)
        assert!(matches!(
            session.status_of("secret:prod/db/password", None),
            Err(FfiError::NotFound)
        ));
        // genuinely absent (in-scope env, no such record) — same error
        assert!(matches!(
            session.status_of("secret:dev/nope/missing", None),
            Err(FfiError::NotFound)
        ));
    }

    // A metadata read returns the record's flags (sensitivity, revealable) and a
    // fingerprint — never the value.
    #[test]
    fn status_returns_value_free_metadata() {
        let (_tmp, session) = seeded_session(metadata_scope(None));
        let view = session.status_of("secret:dev/app/key", None).unwrap();
        assert_eq!(view.sensitivity, "medium");
        assert!(view.revealable);
        assert_eq!(view.mode, "literal");
        assert!(!view.fingerprint.is_empty());
        // the value must not leak into any metadata field
        let blob = format!("{view:?}");
        assert!(!blob.contains("val-dev-app-key"));
    }

    // The metadata operation must be granted: a session without it addresses
    // nothing for status (I13 — operation axis).
    #[test]
    fn i13_metadata_operation_must_be_granted() {
        let scope = AgentScope {
            operations: BTreeSet::new(), // no operations granted
            projects: Filter::Any,
            environments: Filter::Any,
        };
        let (_tmp, session) = seeded_session(scope);
        assert!(session.list_visible().unwrap().is_empty());
        assert!(matches!(
            session.status_of("secret:dev/app/key", None),
            Err(FfiError::NotFound)
        ));
    }

    /// A scope that can write anywhere (every env/project addressable). Writes
    /// are gated on addressability, not on the operation axis, so `metadata` is
    /// enough to grant the metadata read used by the assertions.
    fn write_scope() -> AgentScope {
        let mut operations = BTreeSet::new();
        operations.insert(Operation::Metadata);
        AgentScope {
            operations,
            projects: Filter::Any,
            environments: Filter::Any,
        }
    }

    // I5 — a `prod` secret is born `high`, even when the caller asks for less.
    #[test]
    fn i5_prod_set_and_generate_are_born_high() {
        let (_tmp, session) = seeded_session(write_scope());
        let set = session.set("secret:prod/new/secret", "v", None).unwrap();
        assert_eq!(set.sensitivity, "high", "prod set must be born high (I5)");
        let generated = session
            .generate("secret:prod/new/genned", 16, Some("low"), None, None)
            .unwrap();
        assert_eq!(
            generated.sensitivity, "high",
            "prod generate must be born high even when low is requested (I5)"
        );
    }

    // I5 — lowering a secret's sensitivity is a deliberate, separately audited
    // act (`SensitivityDowngrade`).
    #[test]
    fn i5_metadata_downgrade_is_audited() {
        let (tmp, session) = seeded_session(write_scope());
        session
            .edit_metadata(
                "secret:prod/db/password",
                Some("medium"),
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let log = std::fs::read_to_string(tmp.path().join("audit.log")).unwrap();
        assert!(
            log.contains("downgraded"),
            "a sensitivity downgrade must be audited (I5): {log}"
        );
    }

    // I6 — the value crosses inward as an argument but never crosses back out:
    // not through the write's return, not through a later read.
    #[test]
    fn i6_set_value_never_returns_through_metadata() {
        let (_tmp, session) = seeded_session(write_scope());
        let secret = "S3cr3t-Do-Not-Echo";
        let written = session.set("secret:dev/app/fresh", secret, None).unwrap();
        assert!(!format!("{written:?}").contains(secret));
        let read = session.status_of("secret:dev/app/fresh", None).unwrap();
        assert!(!format!("{read:?}").contains(secret));
        // list never carries values either
        let listed = session.list_visible().unwrap();
        assert!(!format!("{listed:?}").contains(secret));
    }

    // I6/AC3 — a generated value is born server-side and is never returned; only
    // its metadata (a fingerprint, not the value) comes back.
    #[test]
    fn i6_generate_returns_no_value() {
        let (_tmp, session) = seeded_session(write_scope());
        let view = session
            .generate("secret:dev/app/genned", 24, None, None, None)
            .unwrap();
        assert_eq!(view.mode, "literal");
        assert!(!view.fingerprint.is_empty());
        // The view exposes a fingerprint and flags only — there is no value field
        // to leak (structural guarantee), and the fingerprint is not the value.
        assert_ne!(view.fingerprint.len(), 24);
    }

    // I12 — writes are audited with action/coordinate/origin, and the value is
    // never written to the audit log.
    #[test]
    fn i12_writes_audited_without_value() {
        let (tmp, session) = seeded_session(write_scope());
        let secret = "p@ssw0rd-not-in-log";
        session.set("secret:dev/app/k", secret, None).unwrap();
        let log = std::fs::read_to_string(tmp.path().join("audit.log")).unwrap();
        assert!(
            !log.contains(secret),
            "the value must never be audited (I12)"
        );
        assert!(log.contains("dev/app/k"), "the coordinate is audited");
        assert!(log.contains("agent"), "the agent origin is recorded");
        assert!(log.contains("created"));
    }

    // I7 (write path) — the plaintext value is never written to disk; the vault
    // record is AEAD-sealed (metadata + value together).
    #[test]
    fn i7_set_value_not_on_disk_in_plaintext() {
        let (tmp, session) = seeded_session(write_scope());
        let secret = "plaintext-must-not-hit-disk";
        session.set("secret:dev/app/sealed", secret, None).unwrap();
        for entry in walk(tmp.path()) {
            if let Ok(bytes) = std::fs::read(&entry) {
                assert!(
                    !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
                    "plaintext value found on disk at {} (I7)",
                    entry.display()
                );
            }
        }
    }

    // Out-of-scope writes are refused as `NotFound` (I13) — a write can't even
    // confirm the coordinate's existence.
    #[test]
    fn i13_write_out_of_scope_is_not_found() {
        let (_tmp, session) = seeded_session(metadata_scope(Some(vec!["dev"])));
        assert!(matches!(
            session.set("secret:prod/db/password", "x", None),
            Err(FfiError::NotFound)
        ));
        assert!(matches!(
            session.delete("secret:prod/db/password", None),
            Err(FfiError::NotFound)
        ));
    }

    /// Seed a vault for the reveal tests and return a session whose scope grants
    /// metadata + reveal over every environment. Records:
    /// - `dev/app/show` medium, **revealable** → the only allowed reveal
    /// - `dev/app/locked` medium, not revealable
    /// - `dev/app/high` high, revealable
    /// - `dev/app/inj` inject-only, revealable
    /// - `prod/db/pw` medium, revealable (deliberately downgraded — still denied)
    fn seeded_for_reveal() -> (tempfile::TempDir, Session) {
        let tmp = tempfile::tempdir().unwrap();
        let registry = Registry::open(tmp.path()).unwrap();
        let g = registry.global_dir();
        write(
            &g,
            &literal("dev", "app", "show", Sensitivity::Medium, true),
        );
        write(
            &g,
            &literal("dev", "app", "locked", Sensitivity::Medium, false),
        );
        write(&g, &literal("dev", "app", "high", Sensitivity::High, true));
        write(
            &g,
            &literal("dev", "app", "inj", Sensitivity::InjectOnly, true),
        );
        write(&g, &literal("prod", "db", "pw", Sensitivity::Medium, true));
        let mut operations = BTreeSet::new();
        operations.insert(Operation::Metadata);
        operations.insert(Operation::Reveal);
        let scope = AgentScope {
            operations,
            projects: Filter::Any,
            environments: Filter::Any,
        };
        let session =
            Session::with_master(tmp.path().to_path_buf(), scope, MasterKey::new(KEY)).unwrap();
        (tmp, session)
    }

    // I11 — MCP reveals only a revealable, non-prod, non-high literal.
    #[test]
    fn i11_reveal_allows_only_revealable_nonprod_nonhigh() {
        let (_tmp, session) = seeded_for_reveal();
        // the one allowed reveal returns the exact bytes
        let value = session.reveal("secret:dev/app/show", None).unwrap();
        assert_eq!(value, b"val-dev-app-show");
    }

    #[test]
    fn i11_reveal_denies_nonrevealable_high_and_inject_only() {
        let (_tmp, session) = seeded_for_reveal();
        for coord in [
            "secret:dev/app/locked", // not revealable
            "secret:dev/app/high",   // high
            "secret:dev/app/inj",    // inject-only
        ] {
            assert!(
                matches!(session.reveal(coord, None), Err(FfiError::Denied(_))),
                "{coord} must be denied over MCP (I11)"
            );
        }
    }

    // I14 — prod plaintext is never returned to an agent, even when the secret
    // has been downgraded to medium and marked revealable.
    #[test]
    fn i14_reveal_prod_is_always_denied() {
        let (_tmp, session) = seeded_for_reveal();
        assert!(matches!(
            session.reveal("secret:prod/db/pw", None),
            Err(FfiError::Denied(_))
        ));
    }

    // I13 — a reveal of an out-of-scope coordinate, or without the reveal
    // operation granted, is `NotFound` (not `Denied`): existence is not leaked.
    #[test]
    fn i13_reveal_out_of_scope_or_ungranted_is_not_found() {
        // env out of scope
        let (_t1, dev_only) = {
            let tmp = tempfile::tempdir().unwrap();
            let registry = Registry::open(tmp.path()).unwrap();
            write(
                &registry.global_dir(),
                &literal("prod", "db", "pw", Sensitivity::Medium, true),
            );
            let mut ops = BTreeSet::new();
            ops.insert(Operation::Reveal);
            let scope = AgentScope {
                operations: ops,
                projects: Filter::Any,
                environments: Filter::only(["dev"]),
            };
            let s =
                Session::with_master(tmp.path().to_path_buf(), scope, MasterKey::new(KEY)).unwrap();
            (tmp, s)
        };
        assert!(matches!(
            dev_only.reveal("secret:prod/db/pw", None),
            Err(FfiError::NotFound)
        ));

        // reveal operation not granted (metadata-only scope) → NotFound
        let (_tmp, meta_only) = seeded_session(metadata_scope(None));
        assert!(matches!(
            meta_only.reveal("secret:dev/app/key", None),
            Err(FfiError::NotFound)
        ));
    }

    // I11/I14 — a keypair's private half is NEVER revealed over MCP, regardless
    // of the `revealable` flag: it is a private-key op, used only through
    // sign/decrypt/ssh-add, never returned into the model's context.
    #[test]
    fn i11_keypair_private_half_never_revealed_over_mcp() {
        let tmp = tempfile::tempdir().unwrap();
        let registry = Registry::open(tmp.path()).unwrap();
        // A keypair marked revealable=true (a deliberate attempt to coax it out)
        // in a non-prod, low env — still must be refused for the private half.
        let kp = SecretRecord::Keypair {
            algorithm: kovra_core::KeyAlgorithm::Ed25519,
            private: Some(SecretValue::from("PRIVATE-KEY-MATERIAL")),
            public: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test".to_string(),
            sensitivity: Sensitivity::Low,
            revealable: true,
            environment: "dev".to_string(),
            component: "ssh".to_string(),
            key: "deploy".to_string(),
            description: None,
            created: "2026-06-01T00:00:00Z".to_string(),
            updated: "2026-06-01T00:00:00Z".to_string(),
        };
        let coord = coord_of(&kp).unwrap();
        store::write_record(&registry.global_dir(), &coord, &seal(&kp, &KEY).unwrap()).unwrap();
        let mut operations = BTreeSet::new();
        operations.insert(Operation::Metadata);
        operations.insert(Operation::Reveal);
        let scope = AgentScope {
            operations,
            projects: Filter::Any,
            environments: Filter::Any,
        };
        let session =
            Session::with_master(tmp.path().to_path_buf(), scope, MasterKey::new(KEY)).unwrap();
        let res = session.reveal("secret:dev/ssh/deploy", None);
        assert!(
            matches!(res, Err(FfiError::Denied(_))),
            "a keypair's private key must never be revealed over MCP (I11/I14): {res:?}"
        );
        // and the metadata view exposes the public key + a public-key fingerprint,
        // never the private material (I12).
        let view = session.status_of("secret:dev/ssh/deploy", None).unwrap();
        assert!(view.mode.starts_with("keypair:"));
        assert!(!format!("{view:?}").contains("PRIVATE-KEY-MATERIAL"));
    }

    // I11/I14 — a TOTP seed is NEVER revealed over MCP, regardless of the
    // `revealable` flag: it is custodied like a private key, the code is produced
    // on demand via the CLI, and the seed never crosses into the model's context.
    #[test]
    fn i11_totp_seed_never_revealed_over_mcp() {
        let tmp = tempfile::tempdir().unwrap();
        let registry = Registry::open(tmp.path()).unwrap();
        // A TOTP enrollment marked revealable=true (a deliberate coax attempt) in
        // a non-prod, low env — still must be refused for the seed.
        let totp = SecretRecord::Totp {
            seed: SecretValue::from("TOTP-SEED-MATERIAL"),
            algorithm: kovra_core::TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            sensitivity: Sensitivity::Low,
            revealable: true,
            environment: "dev".to_string(),
            component: "auth".to_string(),
            key: "mfa".to_string(),
            description: None,
            created: "2026-06-01T00:00:00Z".to_string(),
            updated: "2026-06-01T00:00:00Z".to_string(),
        };
        let coord = coord_of(&totp).unwrap();
        store::write_record(&registry.global_dir(), &coord, &seal(&totp, &KEY).unwrap()).unwrap();
        let mut operations = BTreeSet::new();
        operations.insert(Operation::Metadata);
        operations.insert(Operation::Reveal);
        let scope = AgentScope {
            operations,
            projects: Filter::Any,
            environments: Filter::Any,
        };
        let session =
            Session::with_master(tmp.path().to_path_buf(), scope, MasterKey::new(KEY)).unwrap();
        let res = session.reveal("secret:dev/auth/mfa", None);
        assert!(
            matches!(res, Err(FfiError::Denied(_))),
            "a TOTP seed must never be revealed over MCP (I11/I14): {res:?}"
        );
        // the metadata view exposes the params fingerprint, never the seed (I12)
        let view = session.status_of("secret:dev/auth/mfa", None).unwrap();
        assert!(view.mode.starts_with("totp:"));
        assert!(!format!("{view:?}").contains("TOTP-SEED-MATERIAL"));
    }

    // A TOTP enrollment cannot be overwritten via `set` (the modality is fixed).
    #[test]
    fn totp_set_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let registry = Registry::open(tmp.path()).unwrap();
        let totp = SecretRecord::Totp {
            seed: SecretValue::from("SEED"),
            algorithm: kovra_core::TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            sensitivity: Sensitivity::Medium,
            revealable: false,
            environment: "dev".to_string(),
            component: "auth".to_string(),
            key: "mfa".to_string(),
            description: None,
            created: "2026-06-01T00:00:00Z".to_string(),
            updated: "2026-06-01T00:00:00Z".to_string(),
        };
        let coord = coord_of(&totp).unwrap();
        store::write_record(&registry.global_dir(), &coord, &seal(&totp, &KEY).unwrap()).unwrap();
        let session =
            Session::with_master(tmp.path().to_path_buf(), write_scope(), MasterKey::new(KEY))
                .unwrap();
        assert!(matches!(
            session.set("secret:dev/auth/mfa", "x", None),
            Err(FfiError::Config(_))
        ));
    }

    // A keypair cannot be overwritten via `set` (the modality is fixed).
    #[test]
    fn keypair_set_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let registry = Registry::open(tmp.path()).unwrap();
        let kp = SecretRecord::Keypair {
            algorithm: kovra_core::KeyAlgorithm::Ed25519,
            private: Some(SecretValue::from("PRIV")),
            public: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test".to_string(),
            sensitivity: Sensitivity::Medium,
            revealable: false,
            environment: "dev".to_string(),
            component: "ssh".to_string(),
            key: "deploy".to_string(),
            description: None,
            created: "2026-06-01T00:00:00Z".to_string(),
            updated: "2026-06-01T00:00:00Z".to_string(),
        };
        let coord = coord_of(&kp).unwrap();
        store::write_record(&registry.global_dir(), &coord, &seal(&kp, &KEY).unwrap()).unwrap();
        let session =
            Session::with_master(tmp.path().to_path_buf(), write_scope(), MasterKey::new(KEY))
                .unwrap();
        assert!(matches!(
            session.set("secret:dev/ssh/deploy", "x", None),
            Err(FfiError::Config(_))
        ));
    }

    // A denied reveal is audited (supervision) and never logs the value (I12).
    #[test]
    fn reveal_denial_is_audited_without_value() {
        let (tmp, session) = seeded_for_reveal();
        let _ = session.reveal("secret:dev/app/locked", None);
        let log = std::fs::read_to_string(tmp.path().join("audit.log")).unwrap();
        assert!(log.contains("denied"));
        assert!(!log.contains("val-dev-app-locked"));
    }

    // ───────────────────────── inject_run (I7/I15/I16) ─────────────────────────

    use kovra_core::{
        ConfirmOutcome, ConfirmRequest, MockAuditSink, MockConfirmer, UnsupportedProvider,
    };
    use kovra_providers_azure::{AzureProvider, MockAzRunner};
    use kovra_wrapper::{MockRunner, Output};
    use std::sync::Mutex;

    /// A confirmer that records the request it was asked to confirm, so a test
    /// can assert the prompt is core-authoritative (I16).
    struct RecordingConfirmer {
        command: Mutex<Option<String>>,
        origin: Mutex<Option<Origin>>,
        requesting_process: Mutex<Option<String>>,
        outcome: ConfirmOutcome,
    }
    impl RecordingConfirmer {
        fn new(outcome: ConfirmOutcome) -> Self {
            Self {
                command: Mutex::new(None),
                origin: Mutex::new(None),
                requesting_process: Mutex::new(None),
                outcome,
            }
        }
    }
    impl kovra_core::Confirmer for RecordingConfirmer {
        fn confirm(&self, req: &ConfirmRequest, _timeout: Duration) -> ConfirmOutcome {
            *self.command.lock().unwrap() = req.resolved_command.clone();
            *self.origin.lock().unwrap() = Some(req.origin);
            *self.requesting_process.lock().unwrap() = req.requesting_process.clone();
            self.outcome
        }
    }

    /// A session that can inject over every env, seeded with one high and one low
    /// secret. Returns the temp dir, the session, and the master key bytes.
    fn inject_session() -> (tempfile::TempDir, Session) {
        let tmp = tempfile::tempdir().unwrap();
        let registry = Registry::open(tmp.path()).unwrap();
        let g = registry.global_dir();
        write(&g, &literal("dev", "app", "high", Sensitivity::High, false));
        write(&g, &literal("dev", "app", "low", Sensitivity::Low, false));
        let mut ops = BTreeSet::new();
        ops.insert(Operation::Inject);
        // Metadata is granted so the I8 assertion can confirm — via `status_of`
        // — that the stored record stayed a pointer after the run. The value is
        // never returned through metadata (it carries no value, §5.1).
        ops.insert(Operation::Metadata);
        let scope = AgentScope {
            operations: ops,
            projects: Filter::Any,
            environments: Filter::Any,
        };
        let session =
            Session::with_master(tmp.path().to_path_buf(), scope, MasterKey::new(KEY)).unwrap();
        (tmp, session)
    }

    // I15 — a high secret may only be injected into an allowlisted executable;
    // a non-allowlisted program is refused before the child ever launches.
    #[test]
    fn i15_high_inject_requires_allowlisted_executor() {
        let (_tmp, session) = inject_session();
        let runner = MockRunner::ok();
        let audit = MockAuditSink::new();
        let empty = Allowlist::empty(); // nothing allowlisted
        let res = session.inject_run_with(
            "TOKEN=secret:dev/app/high",
            "dev",
            "/usr/bin/deploy",
            &[],
            None,
            None,
            &empty,
            &runner,
            &MockConfirmer::always(ConfirmOutcome::Approved),
            &audit,
            &UnsupportedProvider,
            Duration::from_secs(1),
        );
        assert!(matches!(res, Err(FfiError::Denied(_))), "I15: {res:?}");
        assert!(!runner.was_invoked(), "the child must not launch (I15)");
    }

    // I15/I7 — an allowlisted high injection, once approved, launches the child
    // with the value in its environment (in-memory, never argv/disk).
    #[test]
    fn i15_allowlisted_high_inject_reaches_child_env() {
        let (_tmp, session) = inject_session();
        let runner = MockRunner::ok();
        let audit = MockAuditSink::new();
        let mut allow = Allowlist::empty();
        allow.allow(PathBuf::from("/usr/bin/deploy"));
        session
            .inject_run_with(
                "TOKEN=secret:dev/app/high",
                "dev",
                "/usr/bin/deploy",
                &[],
                None,
                None,
                &allow,
                &runner,
                &MockConfirmer::always(ConfirmOutcome::Approved),
                &audit,
                &UnsupportedProvider,
                Duration::from_secs(1),
            )
            .unwrap();
        let run = runner.invocations().into_iter().next().unwrap();
        assert_eq!(
            run.env_value("TOKEN"),
            Some("val-dev-app-high"),
            "the value must reach the child env (I7 — in-memory, not argv)"
        );
    }

    // I16 — the confirmation prompt is authoritative from the core: it shows the
    // exact resolved argv, built by the wrapper, with Origin::Agent. The MCP
    // client identity, threaded through the trusted PyO3 boundary, becomes the
    // requesting-process fact on the prompt (§8.3) — never spoofable requester
    // text.
    #[test]
    fn i16_confirm_prompt_is_core_built_and_agent_origin() {
        let (_tmp, session) = inject_session();
        let runner = MockRunner::ok();
        let audit = MockAuditSink::new();
        let mut allow = Allowlist::empty();
        allow.allow(PathBuf::from("/usr/bin/deploy"));
        let confirmer = RecordingConfirmer::new(ConfirmOutcome::Approved);
        session
            .inject_run_with(
                "TOKEN=secret:dev/app/high",
                "dev",
                "/usr/bin/deploy",
                &["--now".to_string()],
                None,
                Some("Claude Code (session abc123)"),
                &allow,
                &runner,
                &confirmer,
                &audit,
                &UnsupportedProvider,
                Duration::from_secs(1),
            )
            .unwrap();
        let cmd = confirmer.command.lock().unwrap().clone().unwrap();
        assert!(
            cmd.contains("/usr/bin/deploy"),
            "prompt shows the argv: {cmd}"
        );
        assert!(cmd.contains("--now"), "prompt shows the args: {cmd}");
        assert_eq!(
            *confirmer.origin.lock().unwrap(),
            Some(Origin::Agent),
            "the run is agent-initiated (I16/§8.3)"
        );
        assert_eq!(
            confirmer.requesting_process.lock().unwrap().as_deref(),
            Some("Claude Code (session abc123)"),
            "the MCP client identity threads through as the requesting process (I16/§8.3)"
        );
    }

    // A denied confirmation refuses the injection (the child never launches).
    #[test]
    fn high_inject_denied_does_not_launch() {
        let (_tmp, session) = inject_session();
        let runner = MockRunner::ok();
        let audit = MockAuditSink::new();
        let mut allow = Allowlist::empty();
        allow.allow(PathBuf::from("/usr/bin/deploy"));
        let res = session.inject_run_with(
            "TOKEN=secret:dev/app/high",
            "dev",
            "/usr/bin/deploy",
            &[],
            None,
            None,
            &allow,
            &runner,
            &MockConfirmer::always(ConfirmOutcome::Denied),
            &audit,
            &UnsupportedProvider,
            Duration::from_secs(1),
        );
        assert!(matches!(res, Err(FfiError::Denied(_))));
        assert!(!runner.was_invoked());
    }

    // A low/dev injection is not gated — it runs with no allowlist and no
    // confirmation, and the vault value is masked in the returned output (§5.1).
    #[test]
    fn low_inject_runs_ungated_and_masks_output() {
        let (_tmp, session) = inject_session();
        // the child echoes the secret value on stdout; the wrapper must mask it
        let runner = MockRunner::new(Output {
            status: Some(0),
            stdout: b"got val-dev-app-low here".to_vec(),
            stderr: Vec::new(),
        });
        let audit = MockAuditSink::new();
        let out = session
            .inject_run_with(
                "TOKEN=secret:dev/app/low",
                "dev",
                "/usr/bin/echo",
                &[],
                None,
                None,
                &Allowlist::empty(), // not needed for low/dev
                &runner,
                &MockConfirmer::always(ConfirmOutcome::Denied), // ignored: low isn't gated
                &audit,
                &UnsupportedProvider,
                Duration::from_secs(1),
            )
            .unwrap();
        assert!(runner.was_invoked());
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            !stdout.contains("val-dev-app-low"),
            "vault value must be masked in output (§5.1): {stdout}"
        );
    }

    /// Seed a session with a `high` Azure **reference** secret (`prod`-ish high
    /// sensitivity) addressable for inject over every env. The reference points
    /// at `azure-kv://corp-kv/db-url`; the value lives only in (mock) Azure (I8).
    fn reference_inject_session() -> (tempfile::TempDir, Session) {
        let tmp = tempfile::tempdir().unwrap();
        let registry = Registry::open(tmp.path()).unwrap();
        let reference = SecretRecord::Reference {
            reference: "azure-kv://corp-kv/db-url".to_string(),
            sensitivity: Sensitivity::High,
            revealable: false,
            environment: "dev".to_string(),
            component: "db".to_string(),
            key: "url".to_string(),
            description: None,
            created: "2026-06-01T00:00:00Z".to_string(),
            updated: "2026-06-01T00:00:00Z".to_string(),
        };
        let coord = coord_of(&reference).unwrap();
        store::write_record(
            &registry.global_dir(),
            &coord,
            &seal(&reference, &KEY).unwrap(),
        )
        .unwrap();
        let mut ops = BTreeSet::new();
        ops.insert(Operation::Inject);
        // Metadata too, so the I8 assertion below can read the record back and
        // confirm it stayed a pointer (the value was never stored).
        ops.insert(Operation::Metadata);
        let scope = AgentScope {
            operations: ops,
            projects: Filter::Any,
            environments: Filter::Any,
        };
        let session =
            Session::with_master(tmp.path().to_path_buf(), scope, MasterKey::new(KEY)).unwrap();
        (tmp, session)
    }

    // I8 + I11/I14 — a `high` Azure reference is materialized at run time (mock
    // `az`) and INJECTED into the child env (allowlisted + approved), but the
    // materialized value is NEVER returned to the model: the stored record stays
    // a pointer (I8), and the returned `InjectOutput` carries no value (I11/I14,
    // same masking as any reference). The provider is the L6 Azure impl over a
    // mock `az` runner — no real CLI, no network.
    #[test]
    fn i8_i11_i14_high_azure_reference_injects_but_never_returns_value() {
        let secret_value = "postgres://prod-host/db-AZURE-SECRET";
        let (tmp, session) = reference_inject_session();
        // the child echoes the injected value on stdout; the wrapper must mask it
        let runner = MockRunner::new(Output {
            status: Some(0),
            stdout: format!("connecting to {secret_value} now").into_bytes(),
            stderr: Vec::new(),
        });
        let audit = MockAuditSink::new();
        let mut allow = Allowlist::empty();
        allow.allow(PathBuf::from("/usr/bin/deploy"));
        // L6 Azure provider over a scripted `az` returning the secret value.
        let provider = AzureProvider::new(MockAzRunner::ok(secret_value));
        let out = session
            .inject_run_with(
                "DB_URL=secret:dev/db/url",
                "dev",
                "/usr/bin/deploy",
                &[],
                None,
                None,
                &allow,
                &runner,
                &MockConfirmer::always(ConfirmOutcome::Approved),
                &audit,
                &provider,
                Duration::from_secs(1),
            )
            .unwrap();

        // The value reached the child env (in-memory; the run actually happened).
        assert!(runner.was_invoked());
        let run = runner.invocations().into_iter().next().unwrap();
        assert_eq!(run.env_value("DB_URL"), Some(secret_value));

        // …but the value is NEVER returned to the model: the InjectOutput the
        // agent receives is masked (§5.1) — neither stdout nor stderr carries it.
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stdout.contains(secret_value) && !stderr.contains(secret_value),
            "a materialized azure reference must not be returned to the model (I11/I14): {stdout}"
        );

        // I8 — the stored record is still a pointer; the value was never stored.
        let view = session.status_of("secret:dev/db/url", None).unwrap();
        assert_eq!(view.mode, "reference");
        assert_eq!(view.reference.as_deref(), Some("azure-kv://corp-kv/db-url"));
        for entry in walk(tmp.path()) {
            if let Ok(bytes) = std::fs::read(&entry) {
                assert!(
                    !bytes
                        .windows(secret_value.len())
                        .any(|w| w == secret_value.as_bytes()),
                    "the materialized value must never be stored on disk (I8): {}",
                    entry.display()
                );
            }
        }

        // I12 — the provider invocation is audited with the coordinate + scheme,
        // and the materialized value is never in the audit log.
        let events = audit.events();
        let inv = events
            .iter()
            .find(|e| e.action == AuditAction::ProviderInvocation)
            .expect("a ProviderInvocation event must be emitted (I12)");
        assert_eq!(inv.coordinate.as_deref(), Some("dev/db/url"));
        assert_eq!(inv.result, "scheme:azure-kv");
        let log = format!("{events:?}");
        assert!(
            !log.contains(secret_value),
            "the materialized value must never be audited (I12)"
        );
    }

    // I13 — injecting a reference outside the session's scope is `NotFound`, and
    // the run never starts.
    #[test]
    fn i13_inject_out_of_scope_is_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let registry = Registry::open(tmp.path()).unwrap();
        write(
            &registry.global_dir(),
            &literal("prod", "db", "pw", Sensitivity::High, false),
        );
        let mut ops = BTreeSet::new();
        ops.insert(Operation::Inject);
        let scope = AgentScope {
            operations: ops,
            projects: Filter::Any,
            environments: Filter::only(["dev"]), // prod out of scope
        };
        let session =
            Session::with_master(tmp.path().to_path_buf(), scope, MasterKey::new(KEY)).unwrap();
        let runner = MockRunner::ok();
        let res = session.inject_run_with(
            "PW=secret:prod/db/pw",
            "prod",
            "/usr/bin/deploy",
            &[],
            None,
            None,
            &Allowlist::empty(),
            &runner,
            &MockConfirmer::always(ConfirmOutcome::Approved),
            &MockAuditSink::new(),
            &UnsupportedProvider,
            Duration::from_secs(1),
        );
        assert!(matches!(res, Err(FfiError::NotFound)));
        assert!(!runner.was_invoked());
    }

    // The inject operation must be granted at all (I13 — operation axis).
    #[test]
    fn i13_inject_requires_operation_granted() {
        let (_tmp, session) = seeded_session(metadata_scope(None)); // no Inject op
        let runner = MockRunner::ok();
        let res = session.inject_run_with(
            "TOKEN=secret:dev/app/key",
            "dev",
            "/usr/bin/echo",
            &[],
            None,
            None,
            &Allowlist::empty(),
            &runner,
            &MockConfirmer::always(ConfirmOutcome::Approved),
            &MockAuditSink::new(),
            &UnsupportedProvider,
            Duration::from_secs(1),
        );
        assert!(matches!(res, Err(FfiError::NotFound)));
        assert!(!runner.was_invoked());
    }

    /// Recursively collect every file path under `dir`.
    fn walk(dir: &std::path::Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    out.extend(walk(&p));
                } else {
                    out.push(p);
                }
            }
        }
        out
    }
}
