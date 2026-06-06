//! External secret providers for **reference** secrets (spec §6).
//!
//! A reference secret stores only a pointer (`azure-kv://vault/name`, …); its
//! value is materialized **at run time** by invoking the provider with the
//! executing environment's own identity, and is never stored (I8). This module
//! defines the seam (the [`SecretProvider`] trait) plus the [`SchemeRouter`]
//! that dispatches a reference to the registered provider for its URI scheme.
//!
//! The resolver **knows nothing of Azure** (§6.1): it holds a `&dyn
//! SecretProvider` and the concrete provider impl (e.g. `kovra-providers-azure`)
//! is injected by the CLI/FFI. `core` therefore never depends on any provider
//! crate — adding a provider is registering an impl on the router, touching
//! neither the resolver, the grammar, nor this trait.

use crate::error::CoreError;
use crate::secret::SecretValue;

/// Materializes a reference URI into its value. Behind a trait so the resolver
/// is tested with [`MockProvider`]; real providers (L6+) shell out to a cloud CLI
/// with the executing environment's own identity (§6.2). A provider declares the
/// URI [`scheme`](SecretProvider::scheme) it handles so the [`SchemeRouter`] can
/// dispatch by scheme without knowing the concrete type.
pub trait SecretProvider {
    /// Fetch the value for a reference URI (e.g. `azure-kv://corp-kv/db-url`).
    fn materialize(&self, reference: &str) -> Result<SecretValue, CoreError>;

    /// The URI scheme this provider handles (`"azure-kv"`, `"aws-sm"`, …),
    /// without the `://`. The [`SchemeRouter`] dispatches on it.
    fn scheme(&self) -> &'static str;
}

/// The scheme of a reference URI (`azure-kv://vault/name` → `azure-kv`), or
/// `None` when the string has no `://` separator. Never returns the rest of the
/// URI — only the scheme token, which is safe to log/audit (it is not a value).
pub fn reference_scheme(reference: &str) -> Option<&str> {
    reference.split_once("://").map(|(scheme, _)| scheme)
}

/// Dispatches a reference to the registered provider for its URI scheme (§6.1).
///
/// Built by the CLI/FFI with the concrete provider impls (e.g. the Azure
/// provider); `core` depends only on the trait, never on a provider crate. An
/// unknown scheme falls through to [`UnsupportedProvider`], yielding a clear
/// "unsupported scheme" error rather than a silent empty or a fabricated value.
#[derive(Default)]
pub struct SchemeRouter {
    providers: Vec<Box<dyn SecretProvider>>,
}

impl SchemeRouter {
    /// An empty router (every reference is unsupported until a provider is
    /// registered).
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a provider for its declared scheme (builder style). The last
    /// registration for a scheme wins (callers register one impl per scheme).
    pub fn with(mut self, provider: Box<dyn SecretProvider>) -> Self {
        self.providers.push(provider);
        self
    }

    /// The registered provider handling `scheme`, if any.
    fn provider_for(&self, scheme: &str) -> Option<&dyn SecretProvider> {
        self.providers
            .iter()
            .rev()
            .find(|p| p.scheme() == scheme)
            .map(|p| p.as_ref())
    }
}

impl SecretProvider for SchemeRouter {
    fn materialize(&self, reference: &str) -> Result<SecretValue, CoreError> {
        let scheme = reference_scheme(reference).ok_or_else(|| {
            // No `://` at all — never invent a value; report the malformed form
            // without echoing it as if it were a coordinate.
            CoreError::Provider(format!(
                "reference `{reference}` is malformed: expected `<scheme>://…`"
            ))
        })?;
        match self.provider_for(scheme) {
            Some(p) => p.materialize(reference),
            // Unknown scheme → the explicit unsupported error (never silent).
            None => UnsupportedProvider.materialize(reference),
        }
    }

    /// The router itself has no single scheme; it dispatches across many.
    fn scheme(&self) -> &'static str {
        "*"
    }
}

/// A provider that refuses every reference with a clear "unsupported scheme"
/// error — the [`SchemeRouter`]'s fallback for an unknown scheme, and the
/// stand-in when no provider crate is wired in (e.g. a build without Azure).
pub struct UnsupportedProvider;

impl SecretProvider for UnsupportedProvider {
    fn materialize(&self, reference: &str) -> Result<SecretValue, CoreError> {
        let scheme = reference_scheme(reference).unwrap_or(reference);
        Err(CoreError::Provider(format!(
            "no provider registered for reference scheme `{scheme}` (supported: azure-kv, aws-sm)"
        )))
    }

    fn scheme(&self) -> &'static str {
        // Sentinel — `UnsupportedProvider` is never registered under a scheme;
        // it is only used as the router's fallback.
        ""
    }
}

/// Deterministic provider for tests: maps a reference string to a value and
/// counts how many times each reference was materialized (to prove dedup).
#[derive(Default)]
pub struct MockProvider {
    entries: std::collections::HashMap<String, Vec<u8>>,
    calls: std::sync::Mutex<std::collections::HashMap<String, usize>>,
}

impl MockProvider {
    /// An empty provider.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a reference → value mapping (builder style).
    pub fn with(mut self, reference: &str, value: &str) -> Self {
        self.entries
            .insert(reference.to_string(), value.as_bytes().to_vec());
        self
    }

    /// How many times `reference` was materialized.
    pub fn call_count(&self, reference: &str) -> usize {
        self.calls
            .lock()
            .expect("mock provider mutex poisoned")
            .get(reference)
            .copied()
            .unwrap_or(0)
    }
}

impl SecretProvider for MockProvider {
    fn materialize(&self, reference: &str) -> Result<SecretValue, CoreError> {
        *self
            .calls
            .lock()
            .expect("mock provider mutex poisoned")
            .entry(reference.to_string())
            .or_insert(0) += 1;
        match self.entries.get(reference) {
            Some(bytes) => Ok(SecretValue::new(bytes.clone())),
            None => Err(CoreError::EnvRefs(format!(
                "provider has no value for reference `{reference}`"
            ))),
        }
    }

    fn scheme(&self) -> &'static str {
        "azure-kv"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_materializes_and_counts() {
        let p = MockProvider::new().with("azure-kv://kv/db-url", "postgres://h/db");
        assert_eq!(
            p.materialize("azure-kv://kv/db-url").unwrap().expose(),
            b"postgres://h/db"
        );
        assert_eq!(p.call_count("azure-kv://kv/db-url"), 1);
        assert!(p.materialize("azure-kv://kv/missing").is_err());
    }

    #[test]
    fn reference_scheme_splits_on_separator() {
        assert_eq!(reference_scheme("azure-kv://kv/name"), Some("azure-kv"));
        assert_eq!(reference_scheme("aws-sm://arn:..."), Some("aws-sm"));
        assert_eq!(reference_scheme("no-separator"), None);
    }

    #[test]
    fn router_dispatches_by_scheme() {
        let router =
            SchemeRouter::new().with(Box::new(MockProvider::new().with("azure-kv://kv/n", "v")));
        assert_eq!(
            router.materialize("azure-kv://kv/n").unwrap().expose(),
            b"v"
        );
    }

    #[test]
    fn router_unknown_scheme_is_unsupported_not_silent() {
        let router = SchemeRouter::new();
        let err = router.materialize("aws-sm://kv/n").unwrap_err();
        assert!(matches!(err, CoreError::Provider(_)));
        // names the scheme, never fabricates a value
        assert!(format!("{err}").contains("aws-sm"));
    }

    #[test]
    fn router_malformed_reference_errors() {
        let router = SchemeRouter::new();
        assert!(matches!(
            router.materialize("not-a-uri").unwrap_err(),
            CoreError::Provider(_)
        ));
    }

    // ---- KOV-28 hardening: scheme-splitter / router fuzzing ----
    mod fuzz {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            // `reference_scheme` is total and never panics: it returns `Some`
            // exactly when the input contains "://", and the returned token is
            // precisely the prefix before the first "://". It never carries the
            // rest of the URI — only the scheme, which is the part safe to audit
            // (I12: a reference value never enters a log via the scheme split).
            #[test]
            fn reference_scheme_is_total_and_leak_free(s in ".*") {
                match reference_scheme(&s) {
                    Some(scheme) => {
                        prop_assert!(s.contains("://"));
                        prop_assert!(!scheme.contains("://"));
                        prop_assert!(s.starts_with(scheme));
                        prop_assert_eq!(scheme, s.split("://").next().unwrap());
                    }
                    None => prop_assert!(!s.contains("://")),
                }
            }

            // An empty router never fabricates a value: every reference errors,
            // never a silent empty or a made-up secret. A reference with no "://"
            // is the explicit malformed error; an unknown scheme is the explicit
            // unsupported error — both `CoreError::Provider`, neither an `Ok`.
            #[test]
            fn empty_router_never_fabricates(s in ".*") {
                let router = SchemeRouter::new();
                prop_assert!(router.materialize(&s).is_err());
            }
        }
    }
}
