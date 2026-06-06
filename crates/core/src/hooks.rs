//! Pre-commit secret-scan hook generation (L12, KOV-19).
//!
//! Generates a git `pre-commit` hook that runs a secret scanner (gitleaks or
//! trufflehog) over the **staged** changes and **fails the commit** when a
//! secret-like pattern is found (spec §13). It is the safety net for when a
//! value escapes every other control — cheap and disproportionately valuable
//! because the agent commits often.
//!
//! The hook **fails closed**: if the scanner is not installed it aborts the
//! commit rather than letting an unscanned commit through. The generated script
//! and config are pure data here (no I/O), so they are unit-tested; the CLI
//! `kovra hooks install` writes them into a repo's `.git/hooks`.

/// A secret scanner the generated hook can drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scanner {
    /// gitleaks (default) — <https://github.com/gitleaks/gitleaks>.
    Gitleaks,
    /// trufflehog — <https://github.com/trufflesecurity/trufflehog>.
    Trufflehog,
}

impl Scanner {
    /// The executable the hook invokes.
    pub fn binary(&self) -> &'static str {
        match self {
            Scanner::Gitleaks => "gitleaks",
            Scanner::Trufflehog => "trufflehog",
        }
    }
}

/// A marker line embedded in every generated hook so `kovra hooks install` can
/// recognize (and safely replace) a hook it wrote earlier, without clobbering a
/// hand-written one.
pub const HOOK_MARKER: &str = "kovra-pre-commit-secret-scan";

/// The git `pre-commit` hook script for `scanner`. Scans only the staged diff,
/// exits non-zero on a finding (which aborts the commit), and fails closed when
/// the scanner binary is absent.
pub fn hook_script(scanner: Scanner) -> String {
    let common = format!(
        "#!/usr/bin/env bash\n\
         # {marker} (L12) — blocks a commit when a secret-like pattern is found\n\
         # in the STAGED changes. Fails closed: a missing scanner aborts the commit.\n\
         set -euo pipefail\n\n",
        marker = HOOK_MARKER
    );
    match scanner {
        Scanner::Gitleaks => format!(
            "{common}\
             if ! command -v gitleaks >/dev/null 2>&1; then\n\
             \x20 echo \"kovra pre-commit: gitleaks not on PATH — install it \
             (https://github.com/gitleaks/gitleaks) or remove .git/hooks/pre-commit.\" >&2\n\
             \x20 exit 1\n\
             fi\n\n\
             # Scan only the staged diff. gitleaks exits non-zero on a finding,\n\
             # aborting the commit; --redact keeps any matched value out of the log.\n\
             exec gitleaks git --staged --redact --no-banner\n"
        ),
        Scanner::Trufflehog => format!(
            "{common}\
             if ! command -v trufflehog >/dev/null 2>&1; then\n\
             \x20 echo \"kovra pre-commit: trufflehog not on PATH — install it \
             (https://github.com/trufflesecurity/trufflehog) or remove .git/hooks/pre-commit.\" >&2\n\
             \x20 exit 1\n\
             fi\n\n\
             # Scan the working tree (which holds the STAGED-but-uncommitted\n\
             # content) — NOT `trufflehog git`, which scans committed history and\n\
             # would miss the secret being committed right now. --fail aborts the\n\
             # commit on any detection; --no-update avoids a network self-update.\n\
             exec trufflehog filesystem . --fail --no-update\n"
        ),
    }
}

/// A `.gitleaks.toml` that extends the default ruleset and allowlists
/// `.env.refs` — which holds only coordinates (addresses), never values — so the
/// committable secret *contract* never trips the scanner.
pub fn gitleaks_config() -> &'static str {
    "# kovra gitleaks config. Extends the default rules; allowlists `.env.refs`,\n\
     # which holds only coordinates (addresses), never secret values.\n\
     [extend]\n\
     useDefault = true\n\n\
     [[allowlists]]\n\
     description = \"kovra .env.refs holds only coordinates, never values\"\n\
     paths = ['''\\.env\\.refs$''']\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gitleaks_hook_scans_staged_and_fails_closed() {
        let s = hook_script(Scanner::Gitleaks);
        assert!(s.starts_with("#!/usr/bin/env bash"));
        assert!(s.contains(HOOK_MARKER));
        assert!(s.contains("gitleaks"));
        assert!(s.contains("--staged"), "must scan only the staged diff");
        // Fails closed: a missing scanner exits non-zero (no unscanned commit).
        assert!(s.contains("exit 1"));
        assert!(s.contains("set -euo pipefail"));
    }

    #[test]
    fn trufflehog_hook_scans_working_tree_not_committed_history() {
        let s = hook_script(Scanner::Trufflehog);
        assert!(s.contains("trufflehog"));
        assert!(s.contains("--fail"));
        assert!(s.contains("exit 1"));
        // Must scan the working tree (which holds the staged-but-uncommitted
        // content), NOT `trufflehog git` — that scans committed history and would
        // miss the very secret being committed (a fail-open hole).
        assert!(s.contains("filesystem"));
        assert!(
            !s.contains("git file://"),
            "must not scan committed history (would miss the staged secret)"
        );
    }

    #[test]
    fn gitleaks_config_allowlists_env_refs() {
        let cfg = gitleaks_config();
        assert!(cfg.contains("useDefault = true"));
        assert!(cfg.contains(".env.refs") || cfg.contains(r"\.env\.refs"));
    }

    #[test]
    fn scanner_binaries() {
        assert_eq!(Scanner::Gitleaks.binary(), "gitleaks");
        assert_eq!(Scanner::Trufflehog.binary(), "trufflehog");
    }
}
