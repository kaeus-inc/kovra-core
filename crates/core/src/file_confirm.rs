//! File-backed confirmation broker (spec §8) — the cross-process half of the
//! attended-approval flow.
//!
//! [`crate::CliApproveConfirmer`] resolves a request only within the **same**
//! process. The CLI needs `kovra approve <id>` (one process) to release a
//! `kovra run` / `kovra show` blocked in **another** process. This broker makes
//! the pending request and its decision durable files under
//! `<root>/pending/`, so the approval channel lives entirely outside the
//! requesting process — a hijacked agent cannot self-approve (§8).
//!
//! - `confirm` writes `pending/<id>.json` (the authoritative [`ConfirmRequest`])
//!   and **blocks**, polling for `pending/<id>.decision` until it appears or the
//!   timeout elapses (timeout ⇒ deny, §8).
//! - `approve` / `deny` (called by `kovra approve` in another process) write the
//!   decision file.
//! - `list_pending` enumerates the open requests for `kovra approve --list`.
//!
//! Files are `0600` under a `0700` dir; writes are atomic (temp → rename). No
//! value is ever written — only the authoritative address/metadata (I12).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::confirm::{ConfirmOutcome, ConfirmRequest, Confirmer};
use crate::error::CoreError;
use crate::store;

/// The conventional pending-requests subdirectory under the registry root.
pub const PENDING_DIR: &str = "pending";

const REQUEST_EXT: &str = "json";
const DECISION_EXT: &str = "decision";
const APPROVED: &str = "approved";
const DENIED: &str = "denied";

/// A pending request as persisted for `kovra approve --list`: the authoritative
/// [`ConfirmRequest`] plus its id and creation time. Carries no value (I12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRequest {
    /// The operator-typable request id (`<unix>-<pid>-<n>`).
    pub id: String,
    /// Seconds since the Unix epoch when the request was created.
    pub created_unix: u64,
    /// The authoritative prompt (command, coordinate, sensitivity, env, origin).
    pub request: ConfirmRequest,
}

/// A cross-process [`Confirmer`] backed by files under `<root>/pending/`.
pub struct FileConfirmer {
    dir: PathBuf,
    poll: Duration,
    counter: AtomicU64,
}

impl FileConfirmer {
    /// A broker writing under `dir` (the pending directory itself).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            poll: Duration::from_millis(250),
            counter: AtomicU64::new(0),
        }
    }

    /// A broker rooted at a registry root: `<root>/pending/`.
    pub fn under_root(root: &Path) -> Self {
        Self::new(root.join(PENDING_DIR))
    }

    /// Override the poll interval (tests use a short one).
    pub fn with_poll(mut self, poll: Duration) -> Self {
        self.poll = poll;
        self
    }

    fn request_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.{REQUEST_EXT}"))
    }

    fn decision_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.{DECISION_EXT}"))
    }

    fn next_id(&self) -> String {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        format!("{secs}-{}-{n}", std::process::id())
    }

    /// Enumerate the open pending requests, sorted by id.
    pub fn list_pending(&self) -> Result<Vec<PendingRequest>, CoreError> {
        let mut out = Vec::new();
        if !self.dir.exists() {
            return Ok(out);
        }
        let entries =
            fs::read_dir(&self.dir).map_err(|e| CoreError::Io(format!("read pending dir: {e}")))?;
        for entry in entries {
            let path = entry
                .map_err(|e| CoreError::Io(format!("pending entry: {e}")))?
                .path();
            if path.extension().and_then(|e| e.to_str()) != Some(REQUEST_EXT) {
                continue;
            }
            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(_) => continue, // racing cleanup — skip
            };
            if let Ok(pending) = serde_json::from_slice::<PendingRequest>(&bytes) {
                out.push(pending);
            }
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    /// Approve a pending request from another process. Returns `false` if no such
    /// request is open.
    pub fn approve(&self, id: &str) -> Result<bool, CoreError> {
        self.decide(id, true)
    }

    /// Deny a pending request from another process.
    pub fn deny(&self, id: &str) -> Result<bool, CoreError> {
        self.decide(id, false)
    }

    fn decide(&self, id: &str, approved: bool) -> Result<bool, CoreError> {
        if !self.request_path(id).exists() {
            return Ok(false);
        }
        let body = if approved { APPROVED } else { DENIED };
        atomic_write(&self.decision_path(id), body.as_bytes())?;
        Ok(true)
    }

    fn cleanup(&self, id: &str) {
        let _ = fs::remove_file(self.request_path(id));
        let _ = fs::remove_file(self.decision_path(id));
    }
}

impl Confirmer for FileConfirmer {
    fn confirm(&self, req: &ConfirmRequest, timeout: Duration) -> ConfirmOutcome {
        // Best-effort to publish the request; on any IO failure, fail safe (deny).
        let id = self.next_id();
        let created_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let pending = PendingRequest {
            id: id.clone(),
            created_unix,
            request: req.clone(),
        };
        if store::ensure_dir(&self.dir).is_err() {
            return ConfirmOutcome::Denied;
        }
        let Ok(bytes) = serde_json::to_vec(&pending) else {
            return ConfirmOutcome::Denied;
        };
        if atomic_write(&self.request_path(&id), &bytes).is_err() {
            return ConfirmOutcome::Denied;
        }

        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(body) = fs::read_to_string(self.decision_path(&id)) {
                let outcome = if body.trim() == APPROVED {
                    ConfirmOutcome::Approved
                } else {
                    ConfirmOutcome::Denied
                };
                self.cleanup(&id);
                return outcome;
            }
            if Instant::now() >= deadline {
                self.cleanup(&id);
                return ConfirmOutcome::TimedOut; // §8: caller treats as denial
            }
            thread::sleep(
                self.poll
                    .min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }
}

/// Write `bytes` to `path` atomically (temp → rename), `0600` on Unix. Reuses
/// `store::restrict` — the single owner of kovra's on-disk permission policy.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), CoreError> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|e| CoreError::Io(format!("write pending: {e}")))?;
    store::restrict(&tmp, 0o600)?;
    fs::rename(&tmp, path).map_err(|e| CoreError::Io(format!("rename pending: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::Origin;
    use crate::sensitivity::Sensitivity;

    fn req() -> ConfirmRequest {
        ConfirmRequest::new("prod/db/password", Sensitivity::High, "prod", Origin::Human)
            .with_command("/usr/bin/deploy --env prod")
    }

    fn broker(dir: &Path) -> FileConfirmer {
        FileConfirmer::new(dir.join(PENDING_DIR)).with_poll(Duration::from_millis(10))
    }

    #[test]
    fn approve_from_another_broker_yields_approved() {
        let tmp = tempfile::tempdir().unwrap();
        let runner = broker(tmp.path());
        let approver = broker(tmp.path()); // a second "process" over the same dir

        let handle = std::thread::spawn(move || {
            loop {
                let pending = approver.list_pending().unwrap();
                if let Some(p) = pending.first() {
                    assert!(approver.approve(&p.id).unwrap());
                    break;
                }
                std::thread::yield_now();
            }
        });
        let outcome = runner.confirm(&req(), Duration::from_secs(5));
        handle.join().unwrap();
        assert_eq!(outcome, ConfirmOutcome::Approved);
        // request + decision cleaned up
        assert!(runner.list_pending().unwrap().is_empty());
    }

    #[test]
    fn deny_from_another_broker_yields_denied() {
        let tmp = tempfile::tempdir().unwrap();
        let runner = broker(tmp.path());
        let approver = broker(tmp.path());

        let handle = std::thread::spawn(move || {
            loop {
                if let Some(p) = approver.list_pending().unwrap().first() {
                    assert!(approver.deny(&p.id).unwrap());
                    break;
                }
                std::thread::yield_now();
            }
        });
        let outcome = runner.confirm(&req(), Duration::from_secs(5));
        handle.join().unwrap();
        assert_eq!(outcome, ConfirmOutcome::Denied);
    }

    #[test]
    fn timeout_fails_safe_and_cleans_up() {
        let tmp = tempfile::tempdir().unwrap();
        let runner = broker(tmp.path());
        let outcome = runner.confirm(&req(), Duration::from_millis(30));
        assert_eq!(outcome, ConfirmOutcome::TimedOut);
        assert!(!outcome.is_approved());
        assert!(runner.list_pending().unwrap().is_empty());
    }

    #[test]
    fn list_pending_surfaces_the_authoritative_request() {
        let tmp = tempfile::tempdir().unwrap();
        let runner = broker(tmp.path());
        let lister = broker(tmp.path());

        let handle = std::thread::spawn(move || {
            loop {
                let pending = lister.list_pending().unwrap();
                if let Some(p) = pending.first() {
                    assert_eq!(p.request.coordinate, "prod/db/password");
                    assert_eq!(
                        p.request.resolved_command.as_deref(),
                        Some("/usr/bin/deploy --env prod")
                    );
                    assert_eq!(p.request.sensitivity, Sensitivity::High);
                    lister.approve(&p.id).unwrap();
                    break;
                }
                std::thread::yield_now();
            }
        });
        let outcome = runner.confirm(&req(), Duration::from_secs(5));
        handle.join().unwrap();
        assert_eq!(outcome, ConfirmOutcome::Approved);
    }

    #[test]
    fn approve_unknown_id_is_false() {
        let tmp = tempfile::tempdir().unwrap();
        let runner = broker(tmp.path());
        assert!(!runner.approve("no-such-id").unwrap());
    }
}
