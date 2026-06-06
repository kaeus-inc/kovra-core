//! `kovra-webui` — the on-demand, loopback administration Web UI (L10, KOV-22;
//! spec §9.3, §12; invariants I1/I2/I10).
//!
//! A richer admin surface than the CLI, brought up on demand by `kovra ui`: an
//! [`axum`] server bound to `127.0.0.1` only (I10), behind an ephemeral
//! per-launch session token and an `Origin`/`Host` check (anti
//! DNS-rebinding/CSRF even on loopback). It does CRUD + generate plus
//! **sensitivity-governed visualization**:
//!
//! - `low`/`medium` → the value is revealed **on demand** (fetched per click,
//!   never preloaded into the listing, §9.3).
//! - `high` → masked + truncated fingerprint; the UI defers an actual reveal to
//!   the CLI (the trusted, biometric channel). The browser never sees it (I1).
//! - `inject-only` → existence/metadata only (I2).
//! - `reference` → the pointer URI is shown/edited, **never** a value (it has
//!   none); at most a resolution status. Keypair private halves and TOTP seeds
//!   are likewise never rendered.
//!
//! The reveal gate is **not re-derived here** — every reveal runs through
//! [`kovra_core::decide`] with [`Surface::WebUi`], so the I1/I2 boundary lives in
//! the core and the UI is a thin adapter (spec §2/§15). Nothing in this crate is
//! `[host]`: the router is exercised by `[mock]` endpoint tests; only the real
//! TCP bind + browser-open + Docker packaging (L11) are validated on hardware.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use kovra_core::{
    AccessRequest, AgentScope, AuditAction, AuditEvent, AuditSink, Clock, ConfirmOutcome,
    ConfirmRequest, Confirmer, Coordinate, Decision, FileAuditSink, MasterKey, Operation, Origin,
    Registry, Resolution, SecretRecord, SecretValue, Sensitivity, Surface, SystemClock,
    birth_sensitivity, decide, delete_requires_confirmation, downgrade_requires_confirmation,
    fingerprint, is_downgrade, store,
};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};
use std::str::FromStr;

mod assets;

/// HTTP header carrying the ephemeral per-launch session token.
pub const SESSION_HEADER: &str = "x-kovra-session";

/// Default loopback port for `kovra ui`.
pub const DEFAULT_PORT: u16 = 8731;

/// Shared application state. Cheap to clone (an `Arc`); holds the registry root,
/// the resolved master key (zeroized on drop via [`MasterKey`]), the ephemeral
/// session token, and the last-activity instant for the idle watchdog.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    root: PathBuf,
    master: MasterKey,
    session_token: String,
    last_activity: Mutex<Instant>,
    /// Broker for the **per-action** attended confirmation of destructive UI
    /// operations (sensitivity downgrade, delete — KOV-30). Supplied by the
    /// launcher: Touch ID on `[host]` macOS, the file broker (`kovra approve`)
    /// otherwise / in the container. The same authoritative `Confirmer` the CLI
    /// uses (I3/I5/I16), never re-derived here.
    confirmer: Arc<dyn Confirmer + Send + Sync>,
}

impl AppState {
    /// Build state for a registry `root`, a resolved `master` key, and the
    /// attended-confirmation `confirmer`, minting a fresh random session token
    /// (128 bits of hex). The token dies with the process — it is never
    /// persisted.
    pub fn new(
        root: PathBuf,
        master: MasterKey,
        confirmer: Arc<dyn Confirmer + Send + Sync>,
    ) -> Self {
        let mut buf = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        let session_token = buf.iter().map(|b| format!("{b:02x}")).collect();
        Self::new_with_session(root, master, session_token, confirmer)
    }

    /// Like [`AppState::new`] but with a caller-supplied session token. Used by
    /// the L11 container entrypoint so the host orchestrator (`kovra ui
    /// --docker`) — which generated the token and built the browser URL — and
    /// the in-container server agree on it.
    pub fn new_with_session(
        root: PathBuf,
        master: MasterKey,
        session_token: String,
        confirmer: Arc<dyn Confirmer + Send + Sync>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                root,
                master,
                session_token,
                last_activity: Mutex::new(Instant::now()),
                confirmer,
            }),
        }
    }

    /// The ephemeral session token (embedded into the page URL by `kovra ui`).
    pub fn session_token(&self) -> &str {
        &self.inner.session_token
    }

    /// A clone of the per-action confirmation broker (cheap — an `Arc`).
    fn confirmer(&self) -> Arc<dyn Confirmer + Send + Sync> {
        Arc::clone(&self.inner.confirmer)
    }

    fn registry(&self) -> Result<Registry, AppError> {
        Registry::open(&self.inner.root).map_err(|e| AppError::internal(e.to_string()))
    }

    fn key(&self) -> &[u8; kovra_core::KEY_LEN] {
        self.inner.master.expose()
    }

    fn audit(&self, action: AuditAction, result: &str, canonical: &str, env: &str) {
        let clock = SystemClock;
        let _ = FileAuditSink::under_root(&self.inner.root).record(
            &AuditEvent::new(&clock, action, result)
                .at(canonical, env)
                .by(Origin::Human),
        );
    }

    fn touch(&self) {
        if let Ok(mut t) = self.inner.last_activity.lock() {
            *t = Instant::now();
        }
    }

    fn idle_for(&self) -> Duration {
        self.inner
            .last_activity
            .lock()
            .map(|t| t.elapsed())
            .unwrap_or_default()
    }
}

/// A handler error rendered as an HTTP status + JSON body (never a value).
#[derive(Debug)]
struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
    fn bad(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

/// Build the router for `state`. The `/api/*` routes sit behind the ephemeral
/// session-token check; every route (incl. `/`) is behind the `Origin`/`Host`
/// loopback guard. This is the unit exercised by the endpoint tests.
pub fn build_app(state: AppState) -> Router {
    let api = Router::new()
        .route("/secrets", get(list_secrets))
        .route("/reveal", get(reveal_secret))
        .route(
            "/secret",
            post(create_secret)
                .put(update_value)
                .patch(edit_metadata)
                .delete(delete_secret),
        )
        .route("/generate", post(generate_secret))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_session,
        ));

    Router::new()
        .route("/", get(index))
        // Static front-end assets (vendored Tabulator + first-party app shell).
        // Carry no secrets, so they sit outside the `/api` session layer but
        // inside the loopback guard below (KOV-29).
        .merge(assets::routes())
        .nest("/api", api)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            loopback_guard,
        ))
        .with_state(state)
}

// ───────────────────────────── middleware ─────────────────────────────

/// I10 / anti-DNS-rebinding: accept only loopback `Host` and same-origin
/// `Origin`. Runs for every route (including `/`). Also refreshes the
/// idle-watchdog clock.
async fn loopback_guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if let Some(host) = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        && !is_loopback_host(host)
    {
        return AppError::new(StatusCode::FORBIDDEN, "non-loopback Host rejected (I10)")
            .into_response();
    }
    // If an Origin is present (a browser fetch), it must itself be loopback.
    if let Some(origin) = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|h| h.to_str().ok())
        && !is_loopback_origin(origin)
    {
        return AppError::new(StatusCode::FORBIDDEN, "cross-origin request rejected")
            .into_response();
    }
    state.touch();
    next.run(req).await
}

/// Require the ephemeral session token on `/api/*`. The browser shell receives
/// it from the launch URL and echoes it in [`SESSION_HEADER`].
async fn require_session(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let presented = req
        .headers()
        .get(SESSION_HEADER)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    // Constant-ish comparison is unnecessary here (loopback, ephemeral token),
    // but we still avoid leaking which half mismatched.
    if presented.is_empty() || presented != state.session_token() {
        return AppError::new(StatusCode::UNAUTHORIZED, "missing or invalid session token")
            .into_response();
    }
    next.run(req).await
}

fn is_loopback_host(host: &str) -> bool {
    // Strip the optional port; accept the loopback names only.
    let h = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    h == "127.0.0.1" || h == "localhost" || h == "[::1]" || h == "::1"
}

fn is_loopback_origin(origin: &str) -> bool {
    let rest = match origin.strip_prefix("http://") {
        Some(r) => r,
        None => match origin.strip_prefix("https://") {
            Some(r) => r,
            None => return false,
        },
    };
    is_loopback_host(rest)
}

// ───────────────────────────── handlers ─────────────────────────────

#[derive(Deserialize, Default)]
struct ScopeQuery {
    project: Option<String>,
}

#[derive(Deserialize)]
struct CoordQuery {
    coord: String,
    project: Option<String>,
}

/// `GET /` — the minimal admin shell. Serves no secret; the listing and any
/// reveal are fetched over `/api/*` on demand with the session token.
async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

/// `GET /api/secrets` — metadata-only inventory (never a value, §9.3). Lists the
/// global vault plus every project (or one project), marking shadowing and
/// reference pointers.
async fn list_secrets(
    State(state): State<AppState>,
    Query(q): Query<ScopeQuery>,
) -> Result<Json<Value>, AppError> {
    let registry = state.registry()?;
    let mut rows: Vec<Value> = Vec::new();
    let mut global_coords: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    let mut collect = |dir: PathBuf, origin: String| -> Result<(), AppError> {
        let outcome =
            store::load_all(&dir, state.key()).map_err(|e| AppError::internal(e.to_string()))?;
        for (_, record) in outcome.records {
            if origin == "global" {
                global_coords.insert(record.canonical_path());
            }
            rows.push(row_for(&record, &origin));
        }
        Ok(())
    };

    match q.project.as_deref() {
        Some(p) => collect(registry.project_dir(p), format!("project:{p}"))?,
        None => {
            collect(registry.global_dir(), "global".to_string())?;
            for name in registry
                .list_projects()
                .map_err(|e| AppError::internal(e.to_string()))?
            {
                collect(registry.project_dir(&name), format!("project:{name}"))?;
            }
        }
    }

    // Mark project rows that shadow a homonymous global coordinate (§9.3).
    for row in &mut rows {
        let is_project = row
            .get("origin")
            .and_then(|o| o.as_str())
            .is_some_and(|o| o.starts_with("project:"));
        let coord = row.get("coordinate").and_then(|c| c.as_str()).unwrap_or("");
        if is_project && global_coords.contains(coord) {
            row["shadows_global"] = json!(true);
        }
    }

    Ok(Json(json!({ "secrets": rows })))
}

/// One inventory row — metadata only (I1/I12). Literals carry a truncated
/// fingerprint; references carry the pointer; keypair/totp carry their
/// non-secret descriptors. **No value, private key, or seed is ever included.**
fn row_for(record: &SecretRecord, origin: &str) -> Value {
    let base = json!({
        "origin": origin,
        "coordinate": record.canonical_path(),
        "environment": record.environment(),
        "component": record.component(),
        "key": record.key(),
        "sensitivity": sensitivity_str(record.sensitivity()),
        "revealable": record.revealable(),
        "shadows_global": false,
    });
    let mut v = base;
    match record {
        SecretRecord::Literal { value, .. } => {
            v["mode"] = json!("literal");
            v["fingerprint"] = json!(fingerprint(value.expose()));
        }
        SecretRecord::Reference { reference, .. } => {
            v["mode"] = json!("reference");
            v["pointer"] = json!(reference);
        }
        SecretRecord::Keypair {
            algorithm,
            private,
            public,
            ..
        } => {
            v["mode"] = json!(if private.is_some() {
                "keypair"
            } else {
                "public-only"
            });
            v["algorithm"] = json!(algorithm.as_str());
            v["public"] = json!(public); // public key is not a secret
            v["fingerprint"] = json!(fingerprint(public.as_bytes()));
        }
        SecretRecord::Totp {
            algorithm,
            digits,
            period,
            ..
        } => {
            v["mode"] = json!("totp");
            v["algorithm"] = json!(algorithm.as_str());
            v["digits"] = json!(digits);
            v["period"] = json!(period);
        }
    }
    v
}

/// `GET /api/reveal?coord=&project=` — reveal a value **on demand**, governed by
/// sensitivity through [`decide`] (I1/I2). Only `low`/`medium` literals return a
/// value; `high` returns masked + fingerprint; `inject-only` returns metadata
/// only; references/keypairs/totp never return their secret material.
async fn reveal_secret(
    State(state): State<AppState>,
    Query(q): Query<CoordQuery>,
) -> Result<Json<Value>, AppError> {
    let coord = parse_coord(&q.coord)?;
    let registry = state.registry()?;
    let record = match registry
        .resolve_with_key(&coord, q.project.as_deref(), state.key())
        .map_err(|e| AppError::internal(e.to_string()))?
    {
        Resolution::Found { record, origin } => {
            let _ = origin; // origin is surfaced by the listing, not the reveal
            record
        }
        Resolution::NotFound => {
            return Err(AppError::not_found(format!("no secret at `{}`", q.coord)));
        }
    };
    let canonical = record.canonical_path();
    let env = record.environment().to_string();
    let sensitivity = record.sensitivity();

    // Non-literal modalities never expose their secret material in the browser.
    match &record {
        SecretRecord::Reference { reference, .. } => {
            return Ok(Json(json!({
                "coordinate": canonical,
                "kind": "reference",
                "pointer": reference,
                "status": "unverified",
                "note": "value not stored; materialized at run time by the provider (I8)"
            })));
        }
        SecretRecord::Keypair {
            algorithm,
            private,
            public,
            ..
        } => {
            return Ok(Json(json!({
                "coordinate": canonical,
                "kind": if private.is_some() { "keypair" } else { "public-only" },
                "algorithm": algorithm.as_str(),
                "public": public,
                "note": "private half is custodied; use the CLI (sign/decrypt/ssh-add)"
            })));
        }
        SecretRecord::Totp {
            algorithm,
            digits,
            period,
            ..
        } => {
            return Ok(Json(json!({
                "coordinate": canonical,
                "kind": "totp",
                "algorithm": algorithm.as_str(),
                "digits": digits,
                "period": period,
                "note": "seed is custodied; derive a code with the CLI (`kovra code`)"
            })));
        }
        SecretRecord::Literal { .. } => {}
    }

    let SecretRecord::Literal {
        value, revealable, ..
    } = &record
    else {
        unreachable!("non-literal handled above");
    };

    let request = AccessRequest {
        coordinate: &coord,
        project: q.project.as_deref(),
        sensitivity,
        revealable: *revealable,
        operation: Operation::Reveal,
        surface: Surface::WebUi,
        origin: Origin::Human,
    };
    match decide(&request, &AgentScope::full()) {
        Decision::Allow => {
            // low/medium: the only path that returns a literal value, and only on
            // this explicit per-coordinate fetch (never in the listing).
            let value_str = String::from_utf8_lossy(value.expose()).into_owned();
            state.audit(AuditAction::Reveal, "revealed", &canonical, &env);
            Ok(Json(json!({
                "coordinate": canonical,
                "kind": "literal",
                "sensitivity": sensitivity_str(sensitivity),
                "value": value_str
            })))
        }
        Decision::Deny(reason) => {
            // high → masked + fingerprint (defer to CLI); inject-only → metadata
            // only. The value never leaves the core (I1/I2).
            use kovra_core::DenyReason;
            let body = match reason {
                DenyReason::WebUiCriticalMasked => json!({
                    "coordinate": canonical,
                    "kind": "literal",
                    "sensitivity": sensitivity_str(sensitivity),
                    "masked": true,
                    "fingerprint": fingerprint(value.expose()),
                    "note": "high — masked in the browser (I1); reveal via the CLI's biometric channel"
                }),
                DenyReason::InjectOnlyNeverRevealed => json!({
                    "coordinate": canonical,
                    "kind": "literal",
                    "sensitivity": sensitivity_str(sensitivity),
                    "inject_only": true,
                    "note": "inject-only — never revealed on any surface (I2)"
                }),
                other => json!({
                    "coordinate": canonical,
                    "kind": "literal",
                    "masked": true,
                    "note": format!("not revealable here: {other:?}")
                }),
            };
            state.audit(AuditAction::Reveal, "masked", &canonical, &env);
            Ok(Json(body))
        }
        Decision::Unaddressable => Err(AppError::not_found("not addressable")),
        Decision::RequireConfirmation => {
            // The Web UI never prompts for confirmation; it masks instead (the
            // CLI is the confirmation channel). Treat as masked.
            Ok(Json(json!({
                "coordinate": canonical,
                "kind": "literal",
                "masked": true,
                "fingerprint": fingerprint(value.expose()),
                "note": "requires confirmation — reveal via the CLI"
            })))
        }
    }
}

#[derive(Deserialize)]
struct CreateBody {
    coord: String,
    project: Option<String>,
    value: Option<String>,
    reference: Option<String>,
    sensitivity: Option<String>,
    description: Option<String>,
    #[serde(default)]
    revealable: bool,
}

/// `POST /api/secret` — create a literal or reference secret. Values arrive in
/// the request body over loopback (never argv); prod is born `high` (I5).
async fn create_secret(
    State(state): State<AppState>,
    Json(body): Json<CreateBody>,
) -> Result<Json<Value>, AppError> {
    let coord = parse_coord(&body.coord)?;
    let (env, component, key) = segments(&coord);
    let registry = state.registry()?;
    let dir = vault_dir(&registry, body.project.as_deref());

    if store::read_record(&dir, &coord, state.key())
        .map_err(|e| AppError::internal(e.to_string()))?
        .is_some()
    {
        return Err(AppError::bad(format!("`{}` already exists", body.coord)));
    }
    let chosen = parse_sensitivity(body.sensitivity.as_deref())?.unwrap_or(Sensitivity::Medium);
    let born = birth_sensitivity(&env, chosen);
    let now = SystemClock.now_rfc3339();
    let record = match (&body.reference, &body.value) {
        (Some(reference), _) => SecretRecord::Reference {
            reference: reference.clone(),
            sensitivity: born,
            revealable: body.revealable,
            environment: env.clone(),
            component,
            key,
            description: body.description.clone(),
            created: now.clone(),
            updated: now,
        },
        (None, Some(value)) => SecretRecord::Literal {
            value: SecretValue::from(value.as_str()),
            sensitivity: born,
            revealable: body.revealable,
            environment: env.clone(),
            component,
            key,
            description: body.description.clone(),
            created: now.clone(),
            updated: now,
        },
        (None, None) => return Err(AppError::bad("provide `value` or `reference`")),
    };
    write(&dir, &coord, &record, state.key())?;
    state.audit(
        AuditAction::Create,
        "created",
        &record.canonical_path(),
        &env,
    );
    Ok(Json(
        json!({ "created": record.canonical_path(), "sensitivity": sensitivity_str(born) }),
    ))
}

#[derive(Deserialize)]
struct UpdateBody {
    coord: String,
    project: Option<String>,
    value: String,
}

/// `PUT /api/secret` — replace a literal's value (metadata preserved). Refuses
/// to overwrite a keypair/totp/reference (those are not plain values).
async fn update_value(
    State(state): State<AppState>,
    Json(body): Json<UpdateBody>,
) -> Result<Json<Value>, AppError> {
    let coord = parse_coord(&body.coord)?;
    let registry = state.registry()?;
    let dir = vault_dir(&registry, body.project.as_deref());
    let existing = store::read_record(&dir, &coord, state.key())
        .map_err(|e| AppError::internal(e.to_string()))?
        .ok_or_else(|| AppError::not_found(format!("`{}` not found", body.coord)))?;
    let now = SystemClock.now_rfc3339();
    let record = match existing {
        SecretRecord::Literal {
            sensitivity,
            revealable,
            environment,
            component,
            key,
            description,
            created,
            ..
        } => SecretRecord::Literal {
            value: SecretValue::from(body.value.as_str()),
            sensitivity,
            revealable,
            environment,
            component,
            key,
            description,
            created,
            updated: now,
        },
        _ => return Err(AppError::bad("only a literal's value can be updated here")),
    };
    write(&dir, &coord, &record, state.key())?;
    state.audit(
        AuditAction::Edit,
        "value-updated",
        &record.canonical_path(),
        record.environment(),
    );
    Ok(Json(json!({ "updated": record.canonical_path() })))
}

#[derive(Deserialize)]
struct EditBody {
    coord: String,
    project: Option<String>,
    sensitivity: Option<String>,
    description: Option<String>,
    reference: Option<String>,
    revealable: Option<bool>,
}

/// `PATCH /api/secret` — edit metadata (sensitivity / description / reference
/// pointer / revealable). Lowering sensitivity is an audited downgrade (I5).
async fn edit_metadata(
    State(state): State<AppState>,
    Json(body): Json<EditBody>,
) -> Result<Json<Value>, AppError> {
    let coord = parse_coord(&body.coord)?;
    let registry = state.registry()?;
    let dir = vault_dir(&registry, body.project.as_deref());
    let existing = store::read_record(&dir, &coord, state.key())
        .map_err(|e| AppError::internal(e.to_string()))?
        .ok_or_else(|| AppError::not_found(format!("`{}` not found", body.coord)))?;
    let new_sensitivity = parse_sensitivity(body.sensitivity.as_deref())?;
    let env = existing.environment().to_string();
    let lowered = matches!(new_sensitivity, Some(s) if is_downgrade(existing.sensitivity(), s));

    // KOV-30 — lowering a CRITICAL secret's sensitivity from the UI is an
    // attended action (I5 + I16), gated through the same broker the CLI uses
    // (commands.rs::edit). The downgrade is applied only on an approved
    // confirmation; deny/timeout leave the record untouched.
    if let Some(new) = new_sensitivity
        && downgrade_requires_confirmation(existing.sensitivity(), new)
    {
        let canonical = existing.canonical_path();
        let req = ui_action_request(
            &existing,
            format!(
                "edit {canonical} --sensitivity {} (downgrade, web ui)",
                sensitivity_str(new)
            ),
        );
        match confirm_action(state.confirmer(), req).await {
            ConfirmOutcome::Approved => {
                state.audit(AuditAction::Approve, "approved-downgrade", &canonical, &env);
            }
            ConfirmOutcome::Denied => {
                state.audit(AuditAction::Deny, "denied-downgrade", &canonical, &env);
                return Err(AppError::new(
                    StatusCode::FORBIDDEN,
                    "denied — sensitivity not lowered",
                ));
            }
            ConfirmOutcome::TimedOut => {
                state.audit(AuditAction::Timeout, "timeout-downgrade", &canonical, &env);
                return Err(AppError::new(
                    StatusCode::REQUEST_TIMEOUT,
                    "timed out — sensitivity not lowered",
                ));
            }
        }
    }

    let now = SystemClock.now_rfc3339();
    let updated = apply_edit(
        existing,
        new_sensitivity,
        body.description.clone(),
        body.reference.clone(),
        body.revealable,
        now,
    )?;
    write(&dir, &coord, &updated, state.key())?;
    if lowered {
        state.audit(
            AuditAction::SensitivityDowngrade,
            "downgraded",
            &updated.canonical_path(),
            &env,
        );
    }
    state.audit(
        AuditAction::Edit,
        "metadata-updated",
        &updated.canonical_path(),
        &env,
    );
    Ok(Json(json!({ "edited": updated.canonical_path() })))
}

/// `DELETE /api/secret?coord=&project=`.
async fn delete_secret(
    State(state): State<AppState>,
    Query(q): Query<CoordQuery>,
) -> Result<Json<Value>, AppError> {
    let coord = parse_coord(&q.coord)?;
    let registry = state.registry()?;
    let dir = vault_dir(&registry, q.project.as_deref());
    let existing = store::read_record(&dir, &coord, state.key())
        .map_err(|e| AppError::internal(e.to_string()))?
        .ok_or_else(|| AppError::not_found(format!("`{}` not found", q.coord)))?;
    let canonical = existing.canonical_path();
    let env = existing.environment().to_string();

    // KOV-30 — deleting a CRITICAL secret (high / inject-only) from the UI is an
    // attended action, gated through the same broker the rest of kovra uses
    // (Touch ID / `kovra approve`, I16). Non-critical secrets (low / medium) are
    // viewable on demand without biometrics, so their deletion is NOT broker-
    // gated here — the browser guards it with a type-the-name confirmation modal
    // (client-side friction against accidents, matching the reveal tier). The
    // record is removed only on an approved confirmation when gating applies.
    if delete_requires_confirmation(existing.sensitivity()) {
        let req = ui_action_request(&existing, format!("delete {canonical} (web ui)"));
        match confirm_action(state.confirmer(), req).await {
            ConfirmOutcome::Approved => {
                state.audit(AuditAction::Approve, "approved-delete", &canonical, &env);
            }
            ConfirmOutcome::Denied => {
                state.audit(AuditAction::Deny, "denied-delete", &canonical, &env);
                return Err(AppError::new(StatusCode::FORBIDDEN, "denied — not deleted"));
            }
            ConfirmOutcome::TimedOut => {
                state.audit(AuditAction::Timeout, "timeout-delete", &canonical, &env);
                return Err(AppError::new(
                    StatusCode::REQUEST_TIMEOUT,
                    "timed out — not deleted",
                ));
            }
        }
    }

    store::delete_record(&dir, &coord).map_err(|e| AppError::internal(e.to_string()))?;
    state.audit(AuditAction::Delete, "deleted", &canonical, &env);
    Ok(Json(json!({ "deleted": canonical })))
}

#[derive(Deserialize)]
struct GenerateBody {
    coord: String,
    project: Option<String>,
    length: Option<usize>,
    sensitivity: Option<String>,
    description: Option<String>,
}

/// `POST /api/generate` — generate a random value server-side, store it, and
/// **never return it** (the value is born in the core, §9.2).
async fn generate_secret(
    State(state): State<AppState>,
    Json(body): Json<GenerateBody>,
) -> Result<Json<Value>, AppError> {
    let coord = parse_coord(&body.coord)?;
    let (env, component, key) = segments(&coord);
    let registry = state.registry()?;
    let dir = vault_dir(&registry, body.project.as_deref());
    if store::read_record(&dir, &coord, state.key())
        .map_err(|e| AppError::internal(e.to_string()))?
        .is_some()
    {
        return Err(AppError::bad(format!("`{}` already exists", body.coord)));
    }
    let length = body.length.unwrap_or(32);
    if length == 0 {
        return Err(AppError::bad("length must be at least 1"));
    }
    use rand::Rng;
    use rand::distributions::Alphanumeric;
    let generated: String = rand::rngs::OsRng
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();
    let chosen = parse_sensitivity(body.sensitivity.as_deref())?.unwrap_or(Sensitivity::Medium);
    let born = birth_sensitivity(&env, chosen);
    let now = SystemClock.now_rfc3339();
    let record = SecretRecord::Literal {
        value: SecretValue::from(generated),
        sensitivity: born,
        revealable: false,
        environment: env.clone(),
        component,
        key,
        description: body.description.clone(),
        created: now.clone(),
        updated: now,
    };
    write(&dir, &coord, &record, state.key())?;
    state.audit(
        AuditAction::Create,
        "generated",
        &record.canonical_path(),
        &env,
    );
    Ok(Json(json!({
        "generated": record.canonical_path(),
        "length": length,
        "sensitivity": sensitivity_str(born),
        "note": "value stored, never returned"
    })))
}

// ───────────────────────────── helpers ─────────────────────────────

/// How long a destructive-action confirmation waits for an attended decision
/// before failing safe to denial — mirrors the CLI's `CONFIRM_TIMEOUT` (§8).
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(120);

/// Run a (blocking) broker confirmation off the async reactor. `Confirmer::confirm`
/// polls a file / blocks on a condvar, so it must not run on a Tokio worker
/// thread. A join error fails safe to denial (§8). The `ConfirmRequest` is built
/// by the core from the **stored record** (I16), never from the request body.
async fn confirm_action(
    confirmer: Arc<dyn Confirmer + Send + Sync>,
    req: ConfirmRequest,
) -> ConfirmOutcome {
    tokio::task::spawn_blocking(move || confirmer.confirm(&req, CONFIRM_TIMEOUT))
        .await
        .unwrap_or(ConfirmOutcome::Denied)
}

/// Build the authoritative `ConfirmRequest` for a destructive UI action against a
/// stored `record`. All fields are core-observed facts (coordinate / sensitivity
/// / environment from the record; the surface identity is server-authored), so
/// the prompt can never be steered by untrusted request input (I16).
fn ui_action_request(record: &SecretRecord, command: String) -> ConfirmRequest {
    ConfirmRequest::new(
        record.canonical_path(),
        record.sensitivity(),
        record.environment().to_string(),
        Origin::Human,
    )
    .with_command(command)
    // Trusted, server-authored surface identity (never the browser/requester).
    .with_requesting_process("kovra ui (web admin)")
    // KOV-30 — these are administrative *actions* (delete / downgrade), not
    // delivery of the secret value, so the native Touch ID prompt always offers
    // the device-password fallback ("Use Password"). The secret broker (high
    // reveal/inject) stays biometrics-only via `ConfirmRequest::new` (§8/I3).
    .with_allow_password(true)
}

fn parse_coord(s: &str) -> Result<Coordinate, AppError> {
    let with_scheme = if s.starts_with("secret:") {
        s.to_string()
    } else {
        format!("secret:{s}")
    };
    let coord = Coordinate::from_str(&with_scheme).map_err(|e| AppError::bad(e.to_string()))?;
    // A web coordinate must be concrete (no `${ENV}` placeholder).
    coord
        .canonical_path()
        .map_err(|e| AppError::bad(format!("{e} (coordinate must be concrete)")))?;
    Ok(coord)
}

fn segments(coord: &Coordinate) -> (String, String, String) {
    use kovra_core::EnvSegment;
    let env = match &coord.environment {
        EnvSegment::Literal(e) => e.clone(),
        EnvSegment::Placeholder => unreachable!("parse_coord rejects placeholders"),
    };
    (env, coord.component.clone(), coord.key.clone())
}

fn vault_dir(registry: &Registry, project: Option<&str>) -> PathBuf {
    match project {
        Some(p) => registry.project_dir(p),
        None => registry.global_dir(),
    }
}

fn write(
    dir: &std::path::Path,
    coord: &Coordinate,
    record: &SecretRecord,
    key: &[u8; kovra_core::KEY_LEN],
) -> Result<(), AppError> {
    let sealed = kovra_core::seal(record, key).map_err(|e| AppError::internal(e.to_string()))?;
    store::write_record(dir, coord, &sealed).map_err(|e| AppError::internal(e.to_string()))
}

fn sensitivity_str(s: Sensitivity) -> &'static str {
    match s {
        Sensitivity::Low => "low",
        Sensitivity::Medium => "medium",
        Sensitivity::High => "high",
        Sensitivity::InjectOnly => "inject-only",
    }
}

fn parse_sensitivity(s: Option<&str>) -> Result<Option<Sensitivity>, AppError> {
    match s {
        None => Ok(None),
        Some(v) => match v.to_ascii_lowercase().replace('_', "-").as_str() {
            "low" => Ok(Some(Sensitivity::Low)),
            "medium" => Ok(Some(Sensitivity::Medium)),
            "high" => Ok(Some(Sensitivity::High)),
            "inject-only" => Ok(Some(Sensitivity::InjectOnly)),
            other => Err(AppError::bad(format!("unknown sensitivity `{other}`"))),
        },
    }
}

fn apply_edit(
    existing: SecretRecord,
    new_sensitivity: Option<Sensitivity>,
    new_description: Option<String>,
    new_reference: Option<String>,
    new_revealable: Option<bool>,
    now: String,
) -> Result<SecretRecord, AppError> {
    match existing {
        SecretRecord::Literal {
            value,
            sensitivity,
            revealable,
            environment,
            component,
            key,
            description,
            created,
            ..
        } => {
            if new_reference.is_some() {
                return Err(AppError::bad(
                    "`reference` edits a reference secret; this is a literal",
                ));
            }
            Ok(SecretRecord::Literal {
                value,
                sensitivity: new_sensitivity.unwrap_or(sensitivity),
                revealable: new_revealable.unwrap_or(revealable),
                environment,
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
            environment,
            component,
            key,
            description,
            created,
            ..
        } => Ok(SecretRecord::Reference {
            reference: new_reference.unwrap_or(reference),
            sensitivity: new_sensitivity.unwrap_or(sensitivity),
            revealable: new_revealable.unwrap_or(revealable),
            environment,
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
            environment,
            component,
            key,
            description,
            created,
            ..
        } => {
            if new_reference.is_some() {
                return Err(AppError::bad(
                    "`reference` edits a reference secret; this is a keypair",
                ));
            }
            Ok(SecretRecord::Keypair {
                algorithm,
                private,
                public,
                sensitivity: new_sensitivity.unwrap_or(sensitivity),
                revealable: new_revealable.unwrap_or(revealable),
                environment,
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
            environment,
            component,
            key,
            description,
            created,
            ..
        } => {
            if new_reference.is_some() {
                return Err(AppError::bad(
                    "`reference` edits a reference secret; this is a TOTP enrollment",
                ));
            }
            Ok(SecretRecord::Totp {
                seed,
                algorithm,
                digits,
                period,
                sensitivity: new_sensitivity.unwrap_or(sensitivity),
                revealable: new_revealable.unwrap_or(revealable),
                environment,
                component,
                key,
                description: new_description.or(description),
                created,
                updated: now,
            })
        }
    }
}

// ───────────────────────────── serve (host) ─────────────────────────────

/// Run the server on an already-bound loopback `listener` until Ctrl-C or
/// `idle` of inactivity. `[host]`: the real bind + browser-open are validated on
/// hardware; the router itself is covered by the `[mock]` endpoint tests.
pub async fn serve(
    listener: tokio::net::TcpListener,
    state: AppState,
    idle: Duration,
) -> std::io::Result<()> {
    let app = build_app(state.clone());
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(state, idle))
        .await
}

/// Resolve when either Ctrl-C arrives or the server has been idle for `idle`.
async fn shutdown_signal(state: AppState, idle: Duration) {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let idle_watchdog = async {
        let tick = Duration::from_secs(5).min(idle);
        loop {
            tokio::time::sleep(tick).await;
            if state.idle_for() >= idle {
                break;
            }
        }
    };
    tokio::select! {
        _ = ctrl_c => {}
        _ = idle_watchdog => {}
    }
}

/// The default loopback bind address for `kovra ui`.
pub fn default_addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Parse a master key supplied as a file's bytes (L11 Docker entrypoint, I9).
///
/// Accepts either exactly [`kovra_core::KEY_LEN`] raw bytes, or a hex string of
/// `2 * KEY_LEN` characters (with optional surrounding whitespace/newline — the
/// common shape of a Docker secret file). Never logs the bytes. The key arrives
/// from a Docker secret in `tmpfs` at runtime, never from an image layer (I9).
pub fn parse_master_key(raw: &[u8]) -> Result<MasterKey, String> {
    // Raw binary key: exact length.
    if raw.len() == kovra_core::KEY_LEN {
        let mut key = [0u8; kovra_core::KEY_LEN];
        key.copy_from_slice(raw);
        return Ok(MasterKey::new(key));
    }
    // Otherwise treat it as hex text (trimmed).
    let text = std::str::from_utf8(raw)
        .map_err(|_| "master key file is neither raw bytes nor UTF-8 hex".to_string())?
        .trim();
    if text.len() != kovra_core::KEY_LEN * 2 {
        return Err(format!(
            "master key must be {} raw bytes or {} hex chars (got {} chars)",
            kovra_core::KEY_LEN,
            kovra_core::KEY_LEN * 2,
            text.len()
        ));
    }
    let mut key = [0u8; kovra_core::KEY_LEN];
    for (i, pair) in text.as_bytes().chunks(2).enumerate() {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| "master key hex is invalid".to_string())?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| "master key hex is invalid".to_string())?;
        key[i] = (hi * 16 + lo) as u8;
    }
    Ok(MasterKey::new(key))
}

/// The admin shell. Carries no secret and no inline script — it loads the
/// vendored Tabulator grid and the first-party `app.js`/`app.css` from the
/// embedded `/assets/*` routes, which then drive the governed `/api` (KOV-29).
/// The ephemeral session token rides in the page URL (`?session=`) and is read
/// by `app.js`; `high`/`inject-only` values are never delivered here (I1/I2).
const INDEX_HTML: &str = r##"<!doctype html>
<html lang="en" data-theme="dark"><head>
<meta charset="utf-8"><title>kovra — local admin</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="/assets/kovra-icon.png">
<link rel="stylesheet" href="/assets/tabulator/tabulator.min.css">
<link rel="stylesheet" href="/assets/app.css">
</head><body>
<div class="app">
  <aside class="side">
    <div class="brand">
      <div class="logo"><img src="/assets/kovra-icon.png" alt="kovra"></div>
      <div><div class="name">ko<span class="v">v</span>ra</div><div class="tag">local secrets</div></div>
    </div>
    <nav class="nav">
      <a class="on" href="#"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z"/></svg>Secrets</a>
    </nav>
    <div class="spacer"></div>
    <div class="vault"><span class="dot"></span><div><div class="who">local vault</div><div class="sub">loopback only</div></div></div>
  </aside>
  <div class="main">
    <div class="top">
      <div class="search">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3-3"/></svg>
        <input id="search" type="search" placeholder="Search secrets, coordinates, projects…" autocomplete="off" spellcheck="false">
      </div>
      <span class="looppill"><span class="d"></span>loopback</span>
      <button class="iconbtn" id="refresh" title="Refresh">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2v6h-6M3 12a9 9 0 0 1 15-6.7L21 8M3 22v-6h6M21 12a9 9 0 0 1-15 6.7L3 16"/></svg>
      </button>
      <button class="iconbtn" id="theme" title="Toggle theme">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/></svg>
      </button>
    </div>
    <div class="content">
      <div class="head">
        <div><h1>Secrets</h1><div class="sub"><span id="status">loading…</span> · governed by sensitivity · loopback only</div></div>
        <div class="right">
          <div class="seg">
            <button id="view-table" class="on"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 5h18M3 12h18M3 19h18"/></svg>Table</button>
            <button id="view-tree"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M5 4v16M5 8h6M11 8v8M11 12h6"/></svg>Tree</button>
            <button id="view-projects"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/></svg>Projects</button>
          </div>
          <button class="btn primary" id="new"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>New secret</button>
        </div>
      </div>
      <div class="stats">
        <div class="stat"><div class="n" id="stat-total">—</div><div class="l"><span class="d" style="background:var(--accent)"></span>total secrets</div></div>
        <div class="stat"><div class="n" id="stat-high">—</div><div class="l"><span class="d" style="background:var(--high)"></span>high / critical</div></div>
        <div class="stat"><div class="n" id="stat-inject">—</div><div class="l"><span class="d" style="background:var(--inj)"></span>inject-only</div></div>
        <div class="stat"><div class="n" id="stat-ref">—</div><div class="l"><span class="d" style="background:var(--med)"></span>references</div></div>
      </div>
      <div class="project-bar" id="project-bar" hidden></div>
      <div class="card"><div id="grid"></div></div>
    </div>
  </div>
</div>

<div class="scrim" id="scrim"></div>
<aside class="drawer" id="drawer">
  <div class="dh"><h3 id="reveal-title">…</h3><button class="iconbtn" id="reveal-close" title="Close"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6 6 18"/></svg></button></div>
  <div class="db" id="reveal-body"></div>
</aside>

<dialog id="form">
  <form id="form-el">
    <div class="mh"><h3 id="form-title">…</h3><button type="button" id="form-cancel" class="iconbtn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6 6 18"/></svg></button></div>
    <div class="mb" id="form-body"></div>
    <div class="mf">
      <button type="button" id="form-cancel-2" class="btn">Cancel</button>
      <button type="submit" id="form-submit" class="btn primary">Save</button>
    </div>
  </form>
</dialog>
<div id="toasts" aria-live="polite"></div>
<script src="/assets/tabulator/tabulator.min.js"></script>
<script src="/assets/app.js"></script>
</body></html>"##;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use kovra_core::MockConfirmer;
    use tower::ServiceExt; // oneshot

    const KEY: [u8; kovra_core::KEY_LEN] = [0x33; kovra_core::KEY_LEN];

    /// State whose per-action broker (KOV-30) always returns `outcome` — lets a
    /// test assert both the gated (denied/timeout) and the ungated (approved)
    /// paths deterministically, without touching biometrics.
    fn state_with_confirmer(outcome: ConfirmOutcome) -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        // The registry layout is created on open.
        Registry::open(dir.path()).unwrap();
        let state = AppState::new(
            dir.path().to_path_buf(),
            MasterKey::new(KEY),
            Arc::new(MockConfirmer::always(outcome)),
        );
        (state, dir)
    }

    /// Default test state: confirmations auto-approve, so the pre-existing
    /// non-gating tests (reveal/list/create/generate/crud) behave as before.
    fn temp_state() -> (AppState, tempfile::TempDir) {
        state_with_confirmer(ConfirmOutcome::Approved)
    }

    fn put_record(state: &AppState, record: &SecretRecord) {
        let registry = state.registry().unwrap();
        let coord = Coordinate::from_str(&format!("secret:{}", record.canonical_path())).unwrap();
        write(&registry.global_dir(), &coord, record, state.key()).unwrap();
    }

    fn read_back(state: &AppState, coord: &str) -> Option<SecretRecord> {
        let c = Coordinate::from_str(&format!("secret:{coord}")).unwrap();
        store::read_record(&state.registry().unwrap().global_dir(), &c, state.key()).unwrap()
    }

    fn api_patch(body: &str, session: &str) -> Request<Body> {
        Request::builder()
            .method("PATCH")
            .uri("/api/secret")
            .header(header::HOST, "127.0.0.1:8731")
            .header(SESSION_HEADER, session)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn api_delete(coord: &str, session: &str) -> Request<Body> {
        Request::builder()
            .method("DELETE")
            .uri(format!("/api/secret?coord={coord}"))
            .header(header::HOST, "127.0.0.1:8731")
            .header(SESSION_HEADER, session)
            .body(Body::empty())
            .unwrap()
    }

    fn literal(env: &str, key: &str, value: &str, sens: Sensitivity) -> SecretRecord {
        SecretRecord::Literal {
            value: SecretValue::from(value),
            sensitivity: sens,
            revealable: false,
            environment: env.to_string(),
            component: "app".to_string(),
            key: key.to_string(),
            description: None,
            created: "2026-06-01T00:00:00Z".to_string(),
            updated: "2026-06-01T00:00:00Z".to_string(),
        }
    }

    async fn body_json(resp: Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    }

    fn api_get(uri: &str, session: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::HOST, "127.0.0.1:8731")
            .header(SESSION_HEADER, session)
            .body(Body::empty())
            .unwrap()
    }

    // A low/medium literal value is revealed on the explicit fetch.
    #[tokio::test]
    async fn medium_literal_reveals_value() {
        let (state, _d) = temp_state();
        put_record(
            &state,
            &literal("dev", "url", "postgres://x", Sensitivity::Medium),
        );
        let app = build_app(state.clone());
        let resp = app
            .oneshot(api_get(
                "/api/reveal?coord=dev/app/url",
                state.session_token(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp).await;
        assert_eq!(j["value"], "postgres://x");
    }

    // I1 — a high literal is never returned as a value; masked + fingerprint only.
    #[tokio::test]
    async fn high_literal_is_masked_never_value() {
        let (state, _d) = temp_state();
        put_record(
            &state,
            &literal("dev", "key", "TOP-SECRET-HIGH", Sensitivity::High),
        );
        let app = build_app(state.clone());
        let resp = app
            .oneshot(api_get(
                "/api/reveal?coord=dev/app/key",
                state.session_token(),
            ))
            .await
            .unwrap();
        let j = body_json(resp).await;
        assert_eq!(j["masked"], json!(true));
        assert!(j.get("value").is_none(), "high must not return a value");
        assert!(j["fingerprint"].is_string());
        // Defensive: the plaintext appears nowhere in the response.
        assert!(
            !serde_json::to_string(&j)
                .unwrap()
                .contains("TOP-SECRET-HIGH")
        );
    }

    // I2 — an inject-only literal returns metadata only, never the value.
    #[tokio::test]
    async fn inject_only_returns_metadata_only() {
        let (state, _d) = temp_state();
        put_record(
            &state,
            &literal("dev", "tok", "INJECT-ONLY-VAL", Sensitivity::InjectOnly),
        );
        let app = build_app(state.clone());
        let resp = app
            .oneshot(api_get(
                "/api/reveal?coord=dev/app/tok",
                state.session_token(),
            ))
            .await
            .unwrap();
        let j = body_json(resp).await;
        assert_eq!(j["inject_only"], json!(true));
        assert!(j.get("value").is_none());
        assert!(
            !serde_json::to_string(&j)
                .unwrap()
                .contains("INJECT-ONLY-VAL")
        );
    }

    // A reference reveals only the pointer, never a value (I8 at the surface).
    #[tokio::test]
    async fn reference_reveals_pointer_only() {
        let (state, _d) = temp_state();
        put_record(
            &state,
            &SecretRecord::Reference {
                reference: "azure-kv://corp-kv/api".to_string(),
                sensitivity: Sensitivity::High,
                revealable: false,
                environment: "dev".to_string(),
                component: "app".to_string(),
                key: "api".to_string(),
                description: None,
                created: "2026-06-01T00:00:00Z".to_string(),
                updated: "2026-06-01T00:00:00Z".to_string(),
            },
        );
        let app = build_app(state.clone());
        let resp = app
            .oneshot(api_get(
                "/api/reveal?coord=dev/app/api",
                state.session_token(),
            ))
            .await
            .unwrap();
        let j = body_json(resp).await;
        assert_eq!(j["kind"], "reference");
        assert_eq!(j["pointer"], "azure-kv://corp-kv/api");
        assert!(j.get("value").is_none());
    }

    // The inventory lists metadata and never a value.
    #[tokio::test]
    async fn listing_is_metadata_only() {
        let (state, _d) = temp_state();
        put_record(
            &state,
            &literal("dev", "url", "secret-listing-value", Sensitivity::Medium),
        );
        let app = build_app(state.clone());
        let resp = app
            .oneshot(api_get("/api/secrets", state.session_token()))
            .await
            .unwrap();
        let j = body_json(resp).await;
        let txt = serde_json::to_string(&j).unwrap();
        assert!(txt.contains("dev/app/url"));
        assert!(
            !txt.contains("secret-listing-value"),
            "listing must not carry values"
        );
    }

    // The session token is required on /api.
    #[tokio::test]
    async fn api_requires_session_token() {
        let (state, _d) = temp_state();
        let app = build_app(state.clone());
        let resp = app
            .oneshot(api_get("/api/secrets", "wrong-token"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // I10 — a non-loopback Host is rejected (anti DNS-rebinding).
    #[tokio::test]
    async fn non_loopback_host_is_rejected() {
        let (state, _d) = temp_state();
        let app = build_app(state.clone());
        let req = Request::builder()
            .method("GET")
            .uri("/api/secrets")
            .header(header::HOST, "evil.example.com")
            .header(SESSION_HEADER, state.session_token())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // A cross-origin request is rejected even with a valid session + loopback Host.
    #[tokio::test]
    async fn cross_origin_is_rejected() {
        let (state, _d) = temp_state();
        let app = build_app(state.clone());
        let req = Request::builder()
            .method("GET")
            .uri("/api/secrets")
            .header(header::HOST, "127.0.0.1:8731")
            .header(header::ORIGIN, "http://evil.example.com")
            .header(SESSION_HEADER, state.session_token())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // CRUD round-trip: create → reveal → delete.
    #[tokio::test]
    async fn crud_round_trip() {
        let (state, _d) = temp_state();
        let app = build_app(state.clone());
        // create
        let body = json!({"coord":"dev/app/new","value":"v1","sensitivity":"medium"}).to_string();
        let req = Request::builder()
            .method("POST")
            .uri("/api/secret")
            .header(header::HOST, "127.0.0.1:8731")
            .header(SESSION_HEADER, state.session_token())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "create failed");
        // reveal
        let resp = build_app(state.clone())
            .oneshot(api_get(
                "/api/reveal?coord=dev/app/new",
                state.session_token(),
            ))
            .await
            .unwrap();
        assert_eq!(body_json(resp).await["value"], "v1");
        // delete
        let req = Request::builder()
            .method("DELETE")
            .uri("/api/secret?coord=dev/app/new")
            .header(header::HOST, "127.0.0.1:8731")
            .header(SESSION_HEADER, state.session_token())
            .body(Body::empty())
            .unwrap();
        let resp = build_app(state.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // KOV-30 (I5/I16) — lowering a CRITICAL secret from the UI is gated: a denied
    // confirmation is refused (403) and the record keeps its sensitivity.
    #[tokio::test]
    async fn downgrade_of_high_denied_leaves_record_unchanged() {
        let (state, _d) = state_with_confirmer(ConfirmOutcome::Denied);
        put_record(&state, &literal("dev", "key", "v", Sensitivity::High));
        let body = json!({"coord":"dev/app/key","sensitivity":"low"}).to_string();
        let resp = build_app(state.clone())
            .oneshot(api_patch(&body, state.session_token()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            read_back(&state, "dev/app/key").unwrap().sensitivity(),
            Sensitivity::High,
            "denied downgrade must not lower sensitivity"
        );
    }

    // KOV-30 — an approved confirmation applies the critical downgrade.
    #[tokio::test]
    async fn downgrade_of_high_approved_lowers_sensitivity() {
        let (state, _d) = state_with_confirmer(ConfirmOutcome::Approved);
        put_record(&state, &literal("dev", "key", "v", Sensitivity::High));
        let body = json!({"coord":"dev/app/key","sensitivity":"low"}).to_string();
        let resp = build_app(state.clone())
            .oneshot(api_patch(&body, state.session_token()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            read_back(&state, "dev/app/key").unwrap().sensitivity(),
            Sensitivity::Low
        );
    }

    // KOV-30 — a NON-critical downgrade (medium→low) is not gated; it applies
    // even with a denying broker (downgrade_requires_confirmation = high|inject).
    #[tokio::test]
    async fn noncritical_downgrade_is_not_gated() {
        let (state, _d) = state_with_confirmer(ConfirmOutcome::Denied);
        put_record(&state, &literal("dev", "url", "v", Sensitivity::Medium));
        let body = json!({"coord":"dev/app/url","sensitivity":"low"}).to_string();
        let resp = build_app(state.clone())
            .oneshot(api_patch(&body, state.session_token()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            read_back(&state, "dev/app/url").unwrap().sensitivity(),
            Sensitivity::Low
        );
    }

    // KOV-30 — deleting a CRITICAL secret is broker-gated: a denied confirmation
    // keeps the record (403).
    #[tokio::test]
    async fn delete_of_high_denied_keeps_record() {
        let (state, _d) = state_with_confirmer(ConfirmOutcome::Denied);
        put_record(&state, &literal("dev", "key", "v", Sensitivity::High));
        let resp = build_app(state.clone())
            .oneshot(api_delete("dev/app/key", state.session_token()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(
            read_back(&state, "dev/app/key").is_some(),
            "denied delete of a critical secret must keep the record"
        );
    }

    // KOV-30 — deleting a NON-critical secret is NOT broker-gated: it succeeds
    // even with a denying broker (the browser guards it with a type-the-name
    // modal instead, not the broker). The reveal tier and the delete tier match.
    #[tokio::test]
    async fn delete_of_low_is_not_broker_gated() {
        let (state, _d) = state_with_confirmer(ConfirmOutcome::Denied);
        put_record(&state, &literal("dev", "url", "v", Sensitivity::Low));
        let resp = build_app(state.clone())
            .oneshot(api_delete("dev/app/url", state.session_token()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            read_back(&state, "dev/app/url").is_none(),
            "non-critical delete must not consult the broker"
        );
    }

    // L11 (I9): the master key parses from a Docker-secret file as raw bytes or
    // hex; a wrong length is rejected. (The container reads this from tmpfs.)
    #[test]
    fn master_key_parses_raw_and_hex() {
        let raw = [0x33u8; kovra_core::KEY_LEN];
        let from_raw = parse_master_key(&raw).unwrap();
        assert_eq!(from_raw.expose(), &raw);

        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let from_hex = parse_master_key(hex.as_bytes()).unwrap();
        assert_eq!(from_hex.expose(), &raw);

        // Trailing newline (typical secret file) is tolerated.
        let from_hex_nl = parse_master_key(format!("{hex}\n").as_bytes()).unwrap();
        assert_eq!(from_hex_nl.expose(), &raw);

        // Wrong length and non-hex are rejected.
        assert!(parse_master_key(b"too-short").is_err());
        assert!(parse_master_key(&[0u8; kovra_core::KEY_LEN - 1]).is_err());
        let bad_hex = "z".repeat(kovra_core::KEY_LEN * 2);
        assert!(parse_master_key(bad_hex.as_bytes()).is_err());
    }

    // generate stores a value and never returns it; prod is born high (I5).
    #[tokio::test]
    async fn generate_never_returns_value_and_prod_is_high() {
        let (state, _d) = temp_state();
        let body = json!({"coord":"prod/app/gen","length":24}).to_string();
        let req = Request::builder()
            .method("POST")
            .uri("/api/generate")
            .header(header::HOST, "127.0.0.1:8731")
            .header(SESSION_HEADER, state.session_token())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = build_app(state.clone()).oneshot(req).await.unwrap();
        let j = body_json(resp).await;
        assert_eq!(j["sensitivity"], "high", "prod born high (I5)");
        assert!(j.get("value").is_none(), "generate never returns the value");
        // And the stored prod value is masked on reveal (I1).
        let resp = build_app(state.clone())
            .oneshot(api_get(
                "/api/reveal?coord=prod/app/gen",
                state.session_token(),
            ))
            .await
            .unwrap();
        assert_eq!(body_json(resp).await["masked"], json!(true));
    }

    // ── KOV-29: embedded asset routes + new shell ──────────────────────────

    async fn body_text(resp: Response) -> (StatusCode, String, String) {
        let status = resp.status();
        let ctype = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, ctype, String::from_utf8_lossy(&bytes).into_owned())
    }

    fn get_loopback(uri: &str, host: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::HOST, host)
            .body(Body::empty())
            .unwrap()
    }

    // The shell loads the vendored grid + first-party app from `/assets/*` and
    // carries no inline application logic (the old inline reveal script is gone).
    #[tokio::test]
    async fn index_shell_references_assets_and_has_no_inline_logic() {
        let (state, _d) = temp_state();
        let resp = build_app(state.clone())
            .oneshot(get_loopback("/", "127.0.0.1:8731"))
            .await
            .unwrap();
        let (status, _ct, html) = body_text(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains(r#"src="/assets/tabulator/tabulator.min.js""#));
        assert!(html.contains(r#"src="/assets/app.js""#));
        assert!(html.contains(r#"<div id="grid">"#));
        // No inline app logic in the shell — it must live in the embedded app.js.
        assert!(
            !html.contains("fetch('/api/secrets'") && !html.contains("/api/reveal?"),
            "shell must not embed inline API logic"
        );
    }

    // Each embedded asset is served with the right content type and real content.
    #[tokio::test]
    async fn embedded_assets_are_served_with_types() {
        let (state, _d) = temp_state();
        let cases = [
            (
                "/assets/tabulator/tabulator.min.js",
                "javascript",
                "Tabulator",
            ),
            (
                "/assets/tabulator/tabulator.min.css",
                "text/css",
                ".tabulator",
            ),
            ("/assets/app.js", "javascript", "kovra Web UI v2"),
            ("/assets/app.css", "text/css", "kovra Web UI v2"),
        ];
        for (uri, want_ct, want_body) in cases {
            let resp = build_app(state.clone())
                .oneshot(get_loopback(uri, "127.0.0.1:8731"))
                .await
                .unwrap();
            let (status, ct, body) = body_text(resp).await;
            assert_eq!(status, StatusCode::OK, "{uri}");
            assert!(ct.contains(want_ct), "{uri} content-type was `{ct}`");
            assert!(body.contains(want_body), "{uri} body missing `{want_body}`");
        }
    }

    // The brand icon + vendored fonts are served as binary assets with the
    // right content type and a non-empty body (KOV-29).
    #[tokio::test]
    async fn embedded_brand_binary_assets_are_served() {
        let (state, _d) = temp_state();
        let cases = [
            ("/assets/kovra-icon.png", "image/png"),
            ("/assets/fonts/sora-latin-600-normal.woff2", "font/woff2"),
            ("/assets/fonts/inter-latin-400-normal.woff2", "font/woff2"),
            ("/assets/fonts/inter-latin-500-normal.woff2", "font/woff2"),
            ("/assets/fonts/inter-latin-600-normal.woff2", "font/woff2"),
        ];
        for (uri, want_ct) in cases {
            let resp = build_app(state.clone())
                .oneshot(get_loopback(uri, "127.0.0.1:8731"))
                .await
                .unwrap();
            let status = resp.status();
            let ct = resp
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(status, StatusCode::OK, "{uri}");
            assert_eq!(ct, want_ct, "{uri} content-type");
            assert!(!bytes.is_empty(), "{uri} body is empty");
        }
    }

    // The shell wires the brand chrome the client depends on: the icon (logo +
    // favicon), the theme toggle, the reveal drawer, and the stats strip.
    #[tokio::test]
    async fn index_shell_has_brand_chrome() {
        let (state, _d) = temp_state();
        let resp = build_app(state.clone())
            .oneshot(get_loopback("/", "127.0.0.1:8731"))
            .await
            .unwrap();
        let (status, _ct, html) = body_text(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains(r#"href="/assets/kovra-icon.png""#));
        assert!(html.contains(r#"id="theme""#));
        assert!(html.contains(r#"id="drawer""#));
        assert!(html.contains(r#"id="stat-total""#));
        // The three grid views, incl. the Projects toggle (KOV-32).
        assert!(html.contains(r#"id="view-table""#));
        assert!(html.contains(r#"id="view-tree""#));
        assert!(html.contains(r#"id="view-projects""#));
    }

    // Assets carry no secrets, so they need no session token (a `<script src>`
    // load cannot attach one) — but they are still loopback-guarded (I10).
    #[tokio::test]
    async fn assets_need_no_session_but_are_loopback_guarded() {
        let (state, _d) = temp_state();
        // No session header → still served.
        let resp = build_app(state.clone())
            .oneshot(get_loopback("/assets/app.js", "127.0.0.1:8731"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // Non-loopback Host → rejected, like every route.
        let resp = build_app(state.clone())
            .oneshot(get_loopback("/assets/app.js", "evil.example.com"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // Contract the new client depends on: the inventory is metadata-only — it
    // carries the coordinate/sensitivity/mode/fingerprint but never a value.
    #[tokio::test]
    async fn api_secrets_contract_is_metadata_only() {
        let (state, _d) = temp_state();
        put_record(
            &state,
            &literal(
                "dev",
                "url",
                "should-not-appear-in-listing",
                Sensitivity::Medium,
            ),
        );
        let resp = build_app(state.clone())
            .oneshot(api_get("/api/secrets", state.session_token()))
            .await
            .unwrap();
        let j = body_json(resp).await;
        let row = &j["secrets"][0];
        for k in ["coordinate", "sensitivity", "mode", "fingerprint"] {
            assert!(row.get(k).is_some(), "row missing `{k}`");
        }
        assert!(
            row.get("value").is_none(),
            "listing must never carry a value"
        );
        let txt = serde_json::to_string(&j).unwrap();
        assert!(!txt.contains("should-not-appear-in-listing"));
    }
}
