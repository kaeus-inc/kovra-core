//! Agent scope configuration (KOV-13, decision Q3: a **config file**).
//!
//! The daemon serves keys under an [`AgentScope`] (I13). Rather than CLI flags,
//! the scope is read from a small config file at **`<vault-root>/agent.toml`**.
//! The format is intentionally minimal — only the two scope filters an
//! ssh-agent needs (which environments / projects it serves):
//!
//! ```toml
//! # <vault-root>/agent.toml — kovra ssh-agent scope
//! environments = ["dev", "test"]   # omit (or []) → any environment
//! projects     = ["api"]           # omit (or []) → global + any project
//! ```
//!
//! **Operation axis.** An ssh-agent only ever *uses a private key through a sign*
//! — it never reveals plaintext. So the scope's operation set is fixed to
//! `{Metadata, Inject}` and **never** includes `Reveal`, regardless of the file.
//! This is strictly tighter than `AgentScope::full()` and cannot be loosened by
//! the config (defense in depth).
//!
//! **Absent file → safe default.** When `agent.toml` does not exist, the agent
//! serves **all** environments and projects (`environments`/`projects` = any),
//! still with the no-reveal operation set above. This matches the approved plan
//! (the human deliberately started the daemon on their own host) and is safe
//! because the real boundary is per-signature: every `high`/`prod` key still
//! confirms on **every** signature (I3/I15) no matter the scope. Operators who
//! want a narrower agent drop in an `agent.toml`.
//!
//! The parser is a tiny, dependency-free line reader (no `toml` crate) — it
//! understands exactly the two array keys and ignores blank/`#`-comment lines.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use kovra_core::{AgentScope, Filter, Operation};

use crate::error::AgentError;

/// The conventional config filename under the vault root.
pub const AGENT_CONFIG_FILE: &str = "agent.toml";

/// The full path of the agent config under a vault root.
pub fn config_path(root: &Path) -> PathBuf {
    root.join(AGENT_CONFIG_FILE)
}

/// The fixed operation axes an ssh-agent operates under: metadata (enumerate)
/// and inject (sign through the key). **Never** reveal — an agent does not return
/// plaintext into anyone's context.
fn agent_operations() -> BTreeSet<Operation> {
    [Operation::Metadata, Operation::Inject]
        .into_iter()
        .collect()
}

/// Build the agent's [`AgentScope`] from `<root>/agent.toml`, or the safe
/// default when the file is absent (see the module docs). The operation axes are
/// fixed to `{Metadata, Inject}` regardless of the file.
pub fn load_scope(root: &Path) -> Result<AgentScope, AgentError> {
    let path = config_path(root);
    if !path.exists() {
        return Ok(default_scope());
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| AgentError::Socket(format!("read {}: {e}", path.display())))?;
    parse_scope(&text)
}

/// The absent-file default: any environment, any project, no reveal.
pub fn default_scope() -> AgentScope {
    AgentScope {
        operations: agent_operations(),
        projects: Filter::Any,
        environments: Filter::Any,
    }
}

/// Parse the minimal `agent.toml` body into an [`AgentScope`].
pub fn parse_scope(text: &str) -> Result<AgentScope, AgentError> {
    let mut environments = Filter::Any;
    let mut projects = Filter::Any;

    for (lineno, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            AgentError::Socket(format!(
                "agent.toml line {}: expected `key = [..]`",
                lineno + 1
            ))
        })?;
        let key = key.trim();
        let values = parse_array(value.trim()).ok_or_else(|| {
            AgentError::Socket(format!(
                "agent.toml line {}: expected an array like [\"dev\", \"test\"]",
                lineno + 1
            ))
        })?;
        let filter = if values.is_empty() {
            Filter::Any
        } else {
            Filter::only(values)
        };
        match key {
            "environments" => environments = filter,
            "projects" => projects = filter,
            other => {
                return Err(AgentError::Socket(format!(
                    "agent.toml line {}: unknown key `{other}` (expected `environments`/`projects`)",
                    lineno + 1
                )));
            }
        }
    }

    Ok(AgentScope {
        operations: agent_operations(),
        projects,
        environments,
    })
}

/// Drop a trailing `# comment` (the format has no quoted `#`, so this is safe).
fn strip_comment(line: &str) -> &str {
    match line.split_once('#') {
        Some((before, _)) => before,
        None => line,
    }
}

/// Parse a tiny TOML array of double-quoted strings: `["a", "b"]`. Returns
/// `None` if the value is not a bracketed list.
fn parse_array(s: &str) -> Option<Vec<String>> {
    let inner = s.strip_prefix('[')?.strip_suffix(']')?.trim();
    if inner.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for part in inner.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let unq = part.strip_prefix('"')?.strip_suffix('"')?;
        out.push(unq.to_string());
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_default_is_any_no_reveal() {
        let s = default_scope();
        assert!(s.permits(Operation::Metadata));
        assert!(s.permits(Operation::Inject));
        // An agent never reveals — Reveal is never in scope.
        assert!(!s.permits(Operation::Reveal));
        assert_eq!(s.environments, Filter::Any);
        assert_eq!(s.projects, Filter::Any);
    }

    #[test]
    fn parses_environment_and_project_filters() {
        let toml = r#"
            # scope for the dev box
            environments = ["dev", "test"]
            projects = ["api"]
        "#;
        let s = parse_scope(toml).unwrap();
        assert_eq!(s.environments, Filter::only(["dev", "test"]));
        assert_eq!(s.projects, Filter::only(["api"]));
        // Operation axes are still fixed (no reveal).
        assert!(!s.permits(Operation::Reveal));
    }

    #[test]
    fn empty_array_means_any() {
        let s = parse_scope("environments = []\nprojects = []\n").unwrap();
        assert_eq!(s.environments, Filter::Any);
        assert_eq!(s.projects, Filter::Any);
    }

    #[test]
    fn unknown_key_is_rejected() {
        assert!(parse_scope("revealable = [\"yes\"]").is_err());
    }

    #[test]
    fn malformed_line_is_rejected() {
        assert!(parse_scope("environments dev").is_err());
        assert!(parse_scope("environments = dev").is_err());
    }
}
