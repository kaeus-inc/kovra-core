//! The executor allowlist (spec §5.1, invariant I15).
//!
//! Injecting a `high`/`prod` secret into a child process is only a containment
//! boundary if the executable is **outside the agent's control** — a process the
//! agent authored can read its own environment and print it (last-mile, §16).
//! So `high`/`prod` injection is restricted to a configured allowlist of
//! reviewed executables (e.g. a versioned `./deploy.sh`, a Makefile target);
//! ad-hoc commands the agent improvises are not eligible.
//!
//! Matching is on the **resolved program path**, canonicalized (symlinks and
//! relative components resolved) so `./deploy.sh`, `deploy.sh`, and the absolute
//! path all compare equal when they name the same reviewed file.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// A set of reviewed executable paths eligible to receive `high`/`prod`
/// injection. An empty allowlist refuses **every** `high`/`prod` command (fails
/// safe); `low`/`medium` non-prod injection never consults it (§5.1).
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    /// Canonicalized (where possible) absolute paths of reviewed executables.
    entries: BTreeSet<PathBuf>,
}

impl Allowlist {
    /// An empty allowlist — refuses all `high`/`prod` commands.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build an allowlist from a set of reviewed executable paths.
    pub fn from_paths<I, P>(paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        Self {
            entries: paths
                .into_iter()
                .map(|p| canonical_or_owned(&p.into()))
                .collect(),
        }
    }

    /// Add one reviewed executable to the allowlist.
    pub fn allow(&mut self, path: impl Into<PathBuf>) {
        self.entries.insert(canonical_or_owned(&path.into()));
    }

    /// Whether `program` is a reviewed, allowlisted executable.
    pub fn allows(&self, program: &Path) -> bool {
        self.entries.contains(&canonical_or_owned(program))
    }

    /// Whether the allowlist is empty (refuses every `high`/`prod` command).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Canonicalize a path, falling back to the path as-given when it does not exist
/// on disk (a non-existent command can never match a real reviewed file, so the
/// fallback is safe — it simply will not be on the list).
fn canonical_or_owned(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_allowlist_refuses_everything() {
        let a = Allowlist::empty();
        assert!(a.is_empty());
        assert!(!a.allows(Path::new("/usr/bin/env")));
    }

    #[test]
    fn allowlisted_program_matches_through_canonicalization() {
        // A real file so canonicalize succeeds on both sides.
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("deploy.sh");
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap();

        let a = Allowlist::from_paths([&exe]);
        assert!(a.allows(&exe));

        // A different file is not on the list.
        let other = dir.path().join("evil.sh");
        std::fs::write(&other, b"#!/bin/sh\n").unwrap();
        assert!(!a.allows(&other));
    }

    #[test]
    fn allow_adds_an_entry() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("run.sh");
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
        let mut a = Allowlist::empty();
        assert!(!a.allows(&exe));
        a.allow(&exe);
        assert!(a.allows(&exe));
    }
}
