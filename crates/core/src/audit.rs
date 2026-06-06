//! The audit log (spec §11; invariant I12).
//!
//! Append-only record of every security-relevant action — access/delivery,
//! reveal, injection, approve/deny/timeout, sensitivity downgrade, unattended
//! delivery, provider invocation, create/edit/delete, and agent-scope grants
//! and out-of-scope attempts. It **never** records a value, and any recorded
//! fingerprint is the truncated one (§10.4, I12). It is detection, not
//! prevention — the supervision that makes granting the agent autonomy
//! comfortable.
//!
//! L3 backs it with a JSON-lines file at `~/.vaults/audit.log` (the §11
//! literal). L12 (`kovra audit`, KOV-20) adds the queryable view: [`read_log`] +
//! [`query_log`] + [`render_log`], annotated with sensitivity from the redb
//! metadata index (ADR-0001, a rebuildable cache). The view is value-free —
//! coordinates, truncated fingerprints, sensitivity, timestamps, and origin
//! only (I11/I12).

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::clock::Clock;
use crate::confirm::{ConfirmOutcome, Untrusted};
use crate::error::CoreError;
use crate::scope::Origin;
use crate::store;

/// The kind of action recorded (§11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditAction {
    /// Access / delivery of a value through an operation.
    Access,
    /// Plaintext revealed (into a context).
    Reveal,
    /// Value injected into a child process.
    Inject,
    /// A confirmation was approved.
    Approve,
    /// A confirmation was denied.
    Deny,
    /// A confirmation timed out (treated as denial).
    Timeout,
    /// A secret's sensitivity was lowered (I5 deliberate, audited downgrade).
    SensitivityDowngrade,
    /// An unattended (token) delivery occurred.
    UnattendedDelivery,
    /// An encrypted package was sealed (L7, §7) — records the env/component
    /// scope + entry count, never a value (I12).
    Package,
    /// An external provider was invoked to materialize a reference.
    ProviderInvocation,
    /// A secret was created.
    Create,
    /// A secret was edited.
    Edit,
    /// A secret was deleted.
    Delete,
    /// An agent scope was granted.
    ScopeGrant,
    /// An out-of-scope coordinate was attempted (I13).
    OutOfScopeAttempt,
}

/// One append-only audit entry. **No field ever holds a value** (I12); any
/// fingerprint is the truncated form (§10.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// RFC-3339 UTC timestamp.
    pub ts: String,
    /// What happened.
    pub action: AuditAction,
    /// The coordinate acted on (an address, never a value).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coordinate: Option<String>,
    /// Environment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// Outcome / result text (e.g. `allowed`, `denied:McpCriticalForbidden`).
    pub result: String,
    /// Who initiated it (`agent` / `human`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// Truncated fingerprint (§10.4); never the full hash, never the value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Requester-supplied note, segregated as untrusted (mirrors I16).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester_note: Option<String>,
}

impl AuditEvent {
    /// Start an event stamped `now` by the clock.
    pub fn new(clock: &dyn Clock, action: AuditAction, result: impl Into<String>) -> Self {
        Self {
            ts: clock.now_rfc3339(),
            action,
            coordinate: None,
            environment: None,
            result: result.into(),
            origin: None,
            fingerprint: None,
            requester_note: None,
        }
    }

    /// Record which coordinate (address) and environment the event concerns.
    pub fn at(mut self, coordinate: impl Into<String>, environment: impl Into<String>) -> Self {
        self.coordinate = Some(coordinate.into());
        self.environment = Some(environment.into());
        self
    }

    /// Record the initiating origin.
    pub fn by(mut self, origin: Origin) -> Self {
        self.origin = Some(origin.as_str().to_string());
        self
    }

    /// Record a **truncated** fingerprint (callers must pass the truncated form
    /// from [`crate::fingerprint`], never a full hash or a value).
    pub fn with_fingerprint(mut self, truncated: impl Into<String>) -> Self {
        self.fingerprint = Some(truncated.into());
        self
    }

    /// Attach a requester note, stored as the (untrusted) text.
    pub fn with_note(mut self, note: &Untrusted) -> Self {
        self.requester_note = Some(note.0.clone());
        self
    }
}

/// A confirmation outcome rendered as an audit result string.
pub fn outcome_result(outcome: ConfirmOutcome) -> &'static str {
    match outcome {
        ConfirmOutcome::Approved => "approved",
        ConfirmOutcome::Denied => "denied",
        ConfirmOutcome::TimedOut => "timeout",
    }
}

/// Where audit events go. The store/policy depend on this trait, so they are
/// testable with [`MockAuditSink`]; production uses [`FileAuditSink`].
pub trait AuditSink {
    /// Append an event. Append-only — never updates or deletes.
    fn record(&self, event: &AuditEvent) -> Result<(), CoreError>;
}

/// Append-only JSON-lines sink at a file path (default `~/.vaults/audit.log`).
pub struct FileAuditSink {
    path: PathBuf,
}

impl FileAuditSink {
    /// A sink writing to `path`. The parent directory is created `0700` and the
    /// log file `0600` on first write.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The conventional audit log path under a registry root: `<root>/audit.log`.
    pub fn under_root(root: &Path) -> Self {
        Self::new(root.join("audit.log"))
    }
}

impl AuditSink for FileAuditSink {
    fn record(&self, event: &AuditEvent) -> Result<(), CoreError> {
        if let Some(parent) = self.path.parent() {
            store::ensure_dir(parent)?;
        }
        let existed = self.path.exists();
        let mut line =
            serde_json::to_string(event).map_err(|e| CoreError::Serialization(e.to_string()))?;
        line.push('\n');

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| CoreError::Audit(format!("open audit log: {e}")))?;
        if !existed {
            store::restrict(&self.path, 0o600)?;
        }
        file.write_all(line.as_bytes())
            .map_err(|e| CoreError::Audit(format!("append audit log: {e}")))?;
        file.sync_all()
            .map_err(|e| CoreError::Audit(format!("fsync audit log: {e}")))?;
        Ok(())
    }
}

/// The conventional audit-log filename under a registry root.
pub const AUDIT_LOG: &str = "audit.log";

/// Read an append-only audit log (JSON lines) into events, in file
/// (chronological) order. **Tolerant**: a malformed or partial trailing line is
/// skipped rather than failing the whole read (mirrors the store's tolerant
/// loader). A missing log is an empty history, not an error.
pub fn read_log(path: &Path) -> Result<Vec<AuditEvent>, CoreError> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(CoreError::Audit(format!("read audit log: {e}"))),
    };
    Ok(content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<AuditEvent>(l).ok())
        .collect())
}

/// A filter over audit events for `kovra audit` (L12). All set conditions AND
/// together; a `None` field is unconstrained. Time bounds compare RFC-3339
/// strings, which sort chronologically for the UTC `Z` timestamps the sink
/// writes.
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    /// Exact coordinate (`env/component/key`).
    pub coordinate: Option<String>,
    /// Environment segment.
    pub environment: Option<String>,
    /// Component segment (the middle of the coordinate).
    pub component: Option<String>,
    /// Only events at/after this RFC-3339 instant (inclusive).
    pub since: Option<String>,
    /// Only events at/before this RFC-3339 instant (inclusive).
    pub until: Option<String>,
    /// Only this action kind.
    pub action: Option<AuditAction>,
}

impl AuditQuery {
    /// Whether `ev` satisfies every set constraint.
    pub fn matches(&self, ev: &AuditEvent) -> bool {
        if let Some(c) = &self.coordinate
            && ev.coordinate.as_deref() != Some(c.as_str())
        {
            return false;
        }
        if let Some(e) = &self.environment
            && ev.environment.as_deref() != Some(e.as_str())
        {
            return false;
        }
        if let Some(comp) = &self.component {
            let got = ev.coordinate.as_deref().and_then(|c| c.split('/').nth(1));
            if got != Some(comp.as_str()) {
                return false;
            }
        }
        if let Some(s) = &self.since
            && ev.ts.as_str() < s.as_str()
        {
            return false;
        }
        if let Some(u) = &self.until
            && ev.ts.as_str() > u.as_str()
        {
            return false;
        }
        if let Some(a) = &self.action
            && ev.action != *a
        {
            return false;
        }
        true
    }
}

/// Filter `events` by `query`, preserving chronological order.
pub fn query_log(events: Vec<AuditEvent>, query: &AuditQuery) -> Vec<AuditEvent> {
    events.into_iter().filter(|e| query.matches(e)).collect()
}

/// Render events as value-free rows: timestamp, action, coordinate, sensitivity
/// (from the redb metadata index — see [`crate::Index`]), origin, **truncated**
/// fingerprint, and result. The [`AuditEvent`] type holds neither a value nor a
/// full fingerprint (I12), and `sensitivity_by_coord` is metadata only, so the
/// render path cannot leak a value or a full hash (I11/I12).
pub fn render_log(
    events: &[AuditEvent],
    sensitivity_by_coord: &std::collections::BTreeMap<String, crate::sensitivity::Sensitivity>,
) -> String {
    let mut out = String::new();
    out.push_str(
        "TIMESTAMP             ACTION                COORDINATE                 SENS    ORIGIN  FPR       RESULT\n",
    );
    for ev in events {
        let coord = ev.coordinate.as_deref().unwrap_or("-");
        let sens = ev
            .coordinate
            .as_deref()
            .and_then(|c| sensitivity_by_coord.get(c))
            .map(|s| format!("{s:?}").to_lowercase())
            .unwrap_or_else(|| "-".to_string());
        let origin = ev.origin.as_deref().unwrap_or("-");
        let fpr = ev.fingerprint.as_deref().unwrap_or("-");
        out.push_str(&format!(
            "{:<21} {:<21} {:<26} {:<7} {:<7} {:<9} {}\n",
            ev.ts,
            action_label(ev.action),
            coord,
            sens,
            origin,
            fpr,
            ev.result
        ));
    }
    out
}

/// The kebab-case label for an action (e.g. `provider-invocation`). Mirrors the
/// `#[serde(rename_all = "kebab-case")]` on-disk spelling without allocating or
/// invoking the serializer per row.
fn action_label(action: AuditAction) -> &'static str {
    match action {
        AuditAction::Access => "access",
        AuditAction::Reveal => "reveal",
        AuditAction::Inject => "inject",
        AuditAction::Approve => "approve",
        AuditAction::Deny => "deny",
        AuditAction::Timeout => "timeout",
        AuditAction::SensitivityDowngrade => "sensitivity-downgrade",
        AuditAction::UnattendedDelivery => "unattended-delivery",
        AuditAction::Package => "package",
        AuditAction::ProviderInvocation => "provider-invocation",
        AuditAction::Create => "create",
        AuditAction::Edit => "edit",
        AuditAction::Delete => "delete",
        AuditAction::ScopeGrant => "scope-grant",
        AuditAction::OutOfScopeAttempt => "out-of-scope-attempt",
    }
}

/// In-memory sink for tests.
#[derive(Default)]
pub struct MockAuditSink {
    events: Mutex<Vec<AuditEvent>>,
}

impl MockAuditSink {
    /// A new, empty in-memory sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// A snapshot of recorded events.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().expect("audit mutex poisoned").clone()
    }
}

impl AuditSink for MockAuditSink {
    fn record(&self, event: &AuditEvent) -> Result<(), CoreError> {
        self.events
            .lock()
            .expect("audit mutex poisoned")
            .push(event.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::MockClock;
    use crate::fingerprint::fingerprint;

    #[test]
    fn mock_sink_records_events_in_order() {
        let clock = MockClock::default();
        let sink = MockAuditSink::new();
        sink.record(&AuditEvent::new(&clock, AuditAction::Create, "ok"))
            .unwrap();
        sink.record(&AuditEvent::new(
            &clock,
            AuditAction::OutOfScopeAttempt,
            "blocked",
        ))
        .unwrap();
        let evs = sink.events();
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].action, AuditAction::Create);
        assert_eq!(evs[1].action, AuditAction::OutOfScopeAttempt);
    }

    #[test]
    fn event_serialization_holds_no_value_only_truncated_fingerprint() {
        let clock = MockClock::default();
        let value = "super-secret";
        let ev = AuditEvent::new(&clock, AuditAction::Reveal, "allowed")
            .at("prod/db/password", "prod")
            .by(Origin::Human)
            .with_fingerprint(fingerprint(value.as_bytes()));
        let json = serde_json::to_string(&ev).unwrap();
        assert!(
            !json.contains(value),
            "audit event must not contain the value"
        );
        // fingerprint present and truncated (8 hex chars), never the full hash
        assert!(json.contains(&fingerprint(value.as_bytes())));
        let full = blake3::hash(value.as_bytes()).to_hex().to_string();
        assert!(!json.contains(&full));
        // timestamp from the (mock) clock
        assert!(ev.ts.ends_with('Z'));
    }

    #[test]
    fn file_sink_appends_jsonl_and_is_0600() {
        let dir = tempfile::tempdir().unwrap();
        let clock = MockClock::default();
        let sink = FileAuditSink::under_root(dir.path());
        sink.record(&AuditEvent::new(&clock, AuditAction::Create, "ok"))
            .unwrap();
        sink.record(&AuditEvent::new(&clock, AuditAction::Delete, "ok"))
            .unwrap();

        let path = dir.path().join("audit.log");
        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "one JSON object per line, appended");
        // each line is valid JSON
        for line in &lines {
            let _: AuditEvent = serde_json::from_str(line).unwrap();
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    // ── KOV-20: read / query / render the audit view ──

    fn write_log(dir: &std::path::Path, events: &[AuditEvent]) {
        let sink = FileAuditSink::under_root(dir);
        for ev in events {
            sink.record(ev).unwrap();
        }
    }

    fn ev(ts: &str, action: AuditAction, coord: &str, env: &str) -> AuditEvent {
        AuditEvent {
            ts: ts.to_string(),
            action,
            coordinate: Some(coord.to_string()),
            environment: Some(env.to_string()),
            result: "ok".to_string(),
            origin: Some("human".to_string()),
            fingerprint: None,
            requester_note: None,
        }
    }

    #[test]
    fn read_log_is_tolerant_and_chronological() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_LOG);
        // valid lines + a garbage line in the middle (must be skipped).
        let good1 = serde_json::to_string(&ev(
            "2026-06-01T00:00:00Z",
            AuditAction::Create,
            "dev/db/password",
            "dev",
        ))
        .unwrap();
        let good2 = serde_json::to_string(&ev(
            "2026-06-01T00:00:01Z",
            AuditAction::Inject,
            "dev/db/password",
            "dev",
        ))
        .unwrap();
        std::fs::write(&path, format!("{good1}\n{{not json}}\n{good2}\n")).unwrap();

        let events = read_log(&path).unwrap();
        assert_eq!(events.len(), 2, "the malformed line is skipped");
        assert_eq!(events[0].action, AuditAction::Create);
        assert_eq!(events[1].action, AuditAction::Inject);
    }

    #[test]
    fn missing_log_is_empty_history() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_log(&dir.path().join("nope.log")).unwrap().is_empty());
    }

    #[test]
    fn query_filters_by_coordinate_component_env_time_and_action() {
        let dir = tempfile::tempdir().unwrap();
        write_log(
            dir.path(),
            &[
                ev(
                    "2026-06-01T00:00:00Z",
                    AuditAction::Create,
                    "dev/db/password",
                    "dev",
                ),
                ev(
                    "2026-06-01T00:00:05Z",
                    AuditAction::Inject,
                    "dev/db/password",
                    "dev",
                ),
                ev(
                    "2026-06-02T00:00:00Z",
                    AuditAction::Reveal,
                    "prod/api/key",
                    "prod",
                ),
            ],
        );
        let all = read_log(&dir.path().join(AUDIT_LOG)).unwrap();

        let by_env = query_log(
            all.clone(),
            &AuditQuery {
                environment: Some("prod".into()),
                ..Default::default()
            },
        );
        assert_eq!(by_env.len(), 1);
        assert_eq!(by_env[0].action, AuditAction::Reveal);

        let by_component = query_log(
            all.clone(),
            &AuditQuery {
                component: Some("db".into()),
                ..Default::default()
            },
        );
        assert_eq!(by_component.len(), 2);

        let by_action = query_log(
            all.clone(),
            &AuditQuery {
                action: Some(AuditAction::Inject),
                ..Default::default()
            },
        );
        assert_eq!(by_action.len(), 1);

        let by_window = query_log(
            all,
            &AuditQuery {
                since: Some("2026-06-01T00:00:03Z".into()),
                until: Some("2026-06-01T23:59:59Z".into()),
                ..Default::default()
            },
        );
        assert_eq!(by_window.len(), 1, "only the 00:00:05 inject is in window");
        assert_eq!(by_window[0].action, AuditAction::Inject);
    }

    #[test]
    fn render_is_value_free_and_only_truncated_fingerprint() {
        use crate::sensitivity::Sensitivity;
        let value = b"super-secret-value";
        let event = AuditEvent {
            ts: "2026-06-01T00:00:00Z".to_string(),
            action: AuditAction::Reveal,
            coordinate: Some("prod/db/password".to_string()),
            environment: Some("prod".to_string()),
            result: "allowed".to_string(),
            origin: Some("human".to_string()),
            fingerprint: Some(fingerprint(value)),
            requester_note: None,
        };
        let mut sens = std::collections::BTreeMap::new();
        sens.insert("prod/db/password".to_string(), Sensitivity::High);

        let table = render_log(&[event], &sens);
        // coordinate, sensitivity, origin, truncated fingerprint all present
        assert!(table.contains("prod/db/password"));
        assert!(table.contains("high"));
        assert!(table.contains(&fingerprint(value)));
        // anti-leak: never the value, never the FULL fingerprint hash (I11/I12)
        assert!(!table.contains("super-secret-value"));
        let full = blake3::hash(value).to_hex().to_string();
        assert!(
            !table.contains(&full),
            "render must not emit a full fingerprint"
        );
    }
}
