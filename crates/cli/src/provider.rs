//! Provider wiring for the CLI (L6).
//!
//! The CLI composes the [`SchemeRouter`] that the resolver dispatches through:
//! it registers the concrete provider impls (Azure Key Vault, AWS Secrets Manager)
//! keyed by URI scheme. `core` stays free of any provider crate (§6.1) — the
//! router holds only `&dyn SecretProvider`, and the cloud-specific knowledge (the
//! `az`/`aws` CLIs) lives entirely in the `kovra-providers-*` crates.
//!
//! An unknown scheme falls through the router to its `UnsupportedProvider`
//! fallback, yielding a clear "no provider registered" error rather than a silent
//! empty injection.

use kovra_core::SchemeRouter;
use kovra_providers_aws::{AwsProvider, SystemAwsRunner};
use kovra_providers_azure::{AzureProvider, SystemAzRunner};

/// Build the provider router for a real run: the Azure Key Vault provider over the
/// real `az` CLI and the AWS Secrets Manager provider over the real `aws` CLI
/// (`[host]` — each inherits the environment's own cloud identity, §6.2). Adding
/// another provider is one more `.with(...)` here — the resolver and grammar are
/// untouched (§6.1).
pub fn build_router() -> SchemeRouter {
    SchemeRouter::new()
        .with(Box::new(AzureProvider::new(SystemAzRunner)))
        .with(Box::new(AwsProvider::new(SystemAwsRunner)))
}
