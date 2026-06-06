//! The execution environment, behind a trait (spec §4.1 line type 3,
//! `${env:NAME}`).
//!
//! `${env:NAME}` passthrough reads from the process environment at resolution
//! time. Behind [`EnvSource`] so the resolver is tested deterministically with
//! [`MockEnvSource`]; production uses [`SystemEnvSource`].

/// A read-only view of named environment variables.
pub trait EnvSource {
    /// The value of `name`, or `None` if unset.
    fn get(&self, name: &str) -> Option<String>;
}

/// The real process environment (`std::env::var`).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemEnvSource;

impl EnvSource for SystemEnvSource {
    fn get(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

/// An in-memory environment for tests.
#[derive(Debug, Default, Clone)]
pub struct MockEnvSource {
    vars: std::collections::HashMap<String, String>,
}

impl MockEnvSource {
    /// An empty environment.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a variable (builder style).
    pub fn with(mut self, name: &str, value: &str) -> Self {
        self.vars.insert(name.to_string(), value.to_string());
        self
    }
}

impl EnvSource for MockEnvSource {
    fn get(&self, name: &str) -> Option<String> {
        self.vars.get(name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_env_source_reads_set_vars() {
        let env = MockEnvSource::new().with("CI_TOKEN", "abc");
        assert_eq!(env.get("CI_TOKEN").as_deref(), Some("abc"));
        assert_eq!(env.get("MISSING"), None);
    }
}
