//! `AgentScope` — the capability that bounds an MCP session (spec §3.2, I13).
//!
//! Scope is enforced **first**: a coordinate outside the session's scope is
//! *unaddressable* — it does not exist for that channel — rather than being
//! resolved and then denied. This is defense in depth: even a hijacked agent
//! cannot reach what the scope excludes, because the relevant secrets are never
//! surfaced to it (I13).
//!
//! The scope is defined on **operation axes** and a **project/environment
//! filter**, never on environment alone (a blunt "no prod for Claude" would
//! break legitimate diagnose/deploy flows — §3.2).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::coordinate::{Coordinate, EnvSegment};

/// What an operation does with a secret's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Operation {
    /// List / status / fingerprint — no value touched.
    Metadata,
    /// Deliver a value *through* an operation; the value never returns to the
    /// caller's context (injection into a child process).
    Inject,
    /// Return plaintext *into* the caller's context.
    Reveal,
}

/// Which face is asking — selects the §3.1 delivery column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    /// The `kovra` CLI (host, attended).
    Cli,
    /// The local Web UI (loopback).
    WebUi,
    /// The MCP server (the model's channel).
    Mcp,
}

/// Who initiated the request — weighs differently for `prod` reveals (I14, §8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Origin {
    /// Agent-initiated (MCP, or a wrapper invoked by the agent).
    Agent,
    /// Human-initiated (a deliberate act at the CLI / UI).
    Human,
}

impl Origin {
    /// Stable lowercase label, for audit records and prompts.
    pub fn as_str(&self) -> &'static str {
        match self {
            Origin::Agent => "agent",
            Origin::Human => "human",
        }
    }
}

/// A set-membership filter over a string axis (projects or environments).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    /// Every value is in scope.
    Any,
    /// Only the listed values are in scope.
    Only(BTreeSet<String>),
}

impl Filter {
    /// Build an `Only` filter from an iterator of names.
    pub fn only<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Filter::Only(values.into_iter().map(Into::into).collect())
    }

    /// Whether `value` passes the filter.
    pub fn allows(&self, value: &str) -> bool {
        match self {
            Filter::Any => true,
            Filter::Only(set) => set.contains(value),
        }
    }
}

/// The bounded capability a session operates under (§3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentScope {
    /// Operation axes this session may perform at all.
    pub operations: BTreeSet<Operation>,
    /// Which projects are addressable (`None` project = the global vault).
    pub projects: Filter,
    /// Which environments are addressable.
    pub environments: Filter,
}

impl AgentScope {
    /// The unrestricted scope — every operation, every project/environment.
    /// The local CLI/UI operate under this; MCP sessions get something narrower.
    pub fn full() -> Self {
        Self {
            operations: [Operation::Metadata, Operation::Inject, Operation::Reveal]
                .into_iter()
                .collect(),
            projects: Filter::Any,
            environments: Filter::Any,
        }
    }

    /// A metadata-only scope (diagnose without any value flow) — §3.2.
    pub fn metadata_only() -> Self {
        Self {
            operations: [Operation::Metadata].into_iter().collect(),
            projects: Filter::Any,
            environments: Filter::Any,
        }
    }

    /// Whether `operation` is permitted at all in this session.
    pub fn permits(&self, operation: Operation) -> bool {
        self.operations.contains(&operation)
    }

    /// Whether the coordinate (under an optional project) is **addressable** in
    /// this scope — the first gate (I13). A `${ENV}` placeholder is treated as
    /// not-yet-resolved and therefore not addressable until substituted (L4).
    pub fn addresses(&self, coord: &Coordinate, project: Option<&str>) -> bool {
        let env_ok = match &coord.environment {
            EnvSegment::Literal(env) => self.environments.allows(env),
            EnvSegment::Placeholder => false,
        };
        // `None` project means the global vault; it is addressable unless the
        // project filter is an explicit allowlist that the global is not in.
        let project_ok = match project {
            Some(name) => self.projects.allows(name),
            None => matches!(self.projects, Filter::Any),
        };
        env_ok && project_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn coord(s: &str) -> Coordinate {
        Coordinate::from_str(s).unwrap()
    }

    #[test]
    fn full_scope_addresses_everything() {
        let s = AgentScope::full();
        assert!(s.addresses(&coord("secret:prod/db/password"), Some("api")));
        assert!(s.addresses(&coord("secret:dev/app/key"), None));
        assert!(s.permits(Operation::Reveal));
    }

    #[test]
    fn env_filter_excludes_out_of_scope_env() {
        let s = AgentScope {
            operations: [Operation::Metadata].into_iter().collect(),
            projects: Filter::Any,
            environments: Filter::only(["dev", "test"]),
        };
        assert!(s.addresses(&coord("secret:dev/app/key"), None));
        assert!(!s.addresses(&coord("secret:prod/db/password"), None));
    }

    #[test]
    fn project_allowlist_excludes_global_and_other_projects() {
        let s = AgentScope {
            operations: [Operation::Metadata].into_iter().collect(),
            projects: Filter::only(["api"]),
            environments: Filter::Any,
        };
        assert!(s.addresses(&coord("secret:dev/app/key"), Some("api")));
        assert!(!s.addresses(&coord("secret:dev/app/key"), Some("billing")));
        // global (None) is not in an explicit project allowlist
        assert!(!s.addresses(&coord("secret:dev/app/key"), None));
    }

    #[test]
    fn placeholder_env_is_not_addressable() {
        let s = AgentScope::full();
        assert!(!s.addresses(&coord("secret:${ENV}/db/password"), Some("api")));
    }

    #[test]
    fn metadata_only_scope_forbids_reveal_and_inject() {
        let s = AgentScope::metadata_only();
        assert!(s.permits(Operation::Metadata));
        assert!(!s.permits(Operation::Reveal));
        assert!(!s.permits(Operation::Inject));
    }
}
