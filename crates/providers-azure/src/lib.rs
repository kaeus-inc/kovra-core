//! `kovra-providers-azure` — the Azure Key Vault [`SecretProvider`] (spec §6.2).
//!
//! Materializes an `azure-kv://<vault>/<secret-name>` reference **at run time**
//! by invoking the `az` CLI with the **executing environment's own identity**
//! (the dev machine's `az login`, or a host's managed identity). `kovra` manages
//! no cloud credential and passes no `--subscription` — the ambient `az` context
//! decides who you are (§6.2). The materialized value is never stored (I8), never
//! logged or written to disk (I7), and never placed on an audit event (I12 — the
//! resolver audits only the coordinate + the `azure-kv` scheme).
//!
//! The `az` invocation goes through the [`AzRunner`] trait so the provider is
//! unit-tested with [`MockAzRunner`] (no real `az`, no network); the real
//! [`SystemAzRunner`] is `[host]` and validated by a human against a live Key
//! Vault. `core` depends only on the [`SecretProvider`] trait (§6.1); this crate
//! is the only place that knows about Azure.

use std::time::Duration;

use kovra_core::{CoreError, SecretProvider, SecretValue};
use zeroize::Zeroizing;

/// The URI scheme this provider handles.
pub const SCHEME: &str = "azure-kv";

/// Default per-invocation timeout (§6.1) when the caller does not set one.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// A strictly-parsed `azure-kv://<vault>/<secret-name>` reference (§6.2).
///
/// The grammar is exact: the `azure-kv://` scheme, then a non-empty vault name,
/// a single `/`, then a non-empty secret name (which may not itself contain a
/// `/`). A malformed reference is a clear error — never a silent empty, never a
/// fabricated value (decision 2). The parsed parts are addresses, not secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AzureRef {
    /// The Key Vault name (`--vault-name`).
    pub vault: String,
    /// The secret name within the vault (`--name`).
    pub secret: String,
}

impl AzureRef {
    /// Parse `azure-kv://<vault>/<secret-name>`, validating the grammar exactly.
    pub fn parse(reference: &str) -> Result<Self, CoreError> {
        let rest = reference.strip_prefix("azure-kv://").ok_or_else(|| {
            CoreError::Provider(format!(
                "reference `{reference}` is not an `azure-kv://<vault>/<secret>` URI"
            ))
        })?;
        // Exactly one `/`, splitting a non-empty vault from a non-empty secret.
        let (vault, secret) = rest.split_once('/').ok_or_else(|| {
            CoreError::Provider(format!(
                "azure-kv reference `{reference}` is missing the `/<secret-name>` part"
            ))
        })?;
        if vault.is_empty() {
            return Err(CoreError::Provider(format!(
                "azure-kv reference `{reference}` has an empty vault name"
            )));
        }
        if secret.is_empty() {
            return Err(CoreError::Provider(format!(
                "azure-kv reference `{reference}` has an empty secret name"
            )));
        }
        // No nested path: `azure-kv://kv/a/b` is rejected rather than silently
        // dropping `/b` or fabricating a coordinate.
        if secret.contains('/') {
            return Err(CoreError::Provider(format!(
                "azure-kv reference `{reference}` has an unexpected `/` in the secret name"
            )));
        }
        Ok(Self {
            vault: vault.to_string(),
            secret: secret.to_string(),
        })
    }

    /// The `az` argv (after the `az` program) for this reference (§6.2):
    /// `keyvault secret show --vault-name <v> --name <s> --query value -o tsv`.
    /// No `--subscription` — the ambient `az` context decides identity.
    pub fn az_args(&self) -> Vec<String> {
        vec![
            "keyvault".into(),
            "secret".into(),
            "show".into(),
            "--vault-name".into(),
            self.vault.clone(),
            "--name".into(),
            self.secret.clone(),
            "--query".into(),
            "value".into(),
            "-o".into(),
            "tsv".into(),
        ]
    }
}

/// The captured result of running `az`. `stdout` is **secret-bearing** (it is the
/// materialized value) and is held in a zeroizing buffer; it is never logged.
pub struct AzOutput {
    /// Process exit code, or `None` if terminated by a signal.
    pub status: Option<i32>,
    /// Captured stdout — the secret value on success (zeroized on drop).
    pub stdout: Zeroizing<Vec<u8>>,
    /// Captured stderr — diagnostics only; must not be assumed value-free, so it
    /// is mapped to coarse, non-echoing errors below (never surfaced verbatim).
    pub stderr: Vec<u8>,
}

/// Runs the `az` CLI. Behind a trait so [`AzureProvider`] is tested with
/// [`MockAzRunner`] (no real `az`); production uses [`SystemAzRunner`].
pub trait AzRunner {
    /// Run `az <args...>` to completion under `timeout`, capturing its output.
    /// An `Err` here is a *failure to launch/await* `az` itself (e.g. the binary
    /// is absent) — a non-zero exit is reported through [`AzOutput::status`].
    fn run(&self, args: &[String], timeout: Duration) -> Result<AzOutput, CoreError>;
}

/// The Azure Key Vault provider. Holds an [`AzRunner`] and a per-invocation
/// timeout (§6.1); the runner is the only seam to the outside world.
pub struct AzureProvider<R: AzRunner> {
    runner: R,
    timeout: Duration,
}

impl<R: AzRunner> AzureProvider<R> {
    /// A provider over `runner` with the default timeout.
    pub fn new(runner: R) -> Self {
        Self {
            runner,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Set the per-invocation timeout (§6.1).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl<R: AzRunner> SecretProvider for AzureProvider<R> {
    fn materialize(&self, reference: &str) -> Result<SecretValue, CoreError> {
        // Strict parse first (decision 2): a malformed URI never reaches `az`.
        let parsed = AzureRef::parse(reference)?;
        let out = self.runner.run(&parsed.az_args(), self.timeout)?;

        if out.status != Some(0) {
            // Map the failure to a clear, specific error without echoing stderr
            // verbatim (it may carry incidental detail; I12 keeps us coarse).
            return Err(classify_failure(&parsed, out.status, &out.stderr));
        }

        // Success: the value is stdout with a single trailing newline trimmed
        // (`-o tsv` appends one). Trim exactly one `\n`/`\r\n` — do not strip
        // interior or intentional trailing whitespace that is part of the value.
        let trimmed = trim_one_trailing_newline(&out.stdout);
        // An empty value after a successful `az` is suspicious (Key Vault secrets
        // are non-empty); refuse rather than inject an empty string silently.
        if trimmed.is_empty() {
            return Err(CoreError::Provider(format!(
                "azure-kv secret `{}` in vault `{}` resolved to an empty value",
                parsed.secret, parsed.vault
            )));
        }
        Ok(SecretValue::new(trimmed.to_vec()))
    }

    fn scheme(&self) -> &'static str {
        SCHEME
    }
}

/// Trim exactly one trailing newline (`\n`, or `\r\n`) from `az`'s tsv output.
fn trim_one_trailing_newline(bytes: &[u8]) -> &[u8] {
    if let Some(stripped) = bytes.strip_suffix(b"\n") {
        stripped.strip_suffix(b"\r").unwrap_or(stripped)
    } else {
        bytes
    }
}

/// Map a non-zero `az` exit into a specific, non-echoing provider error. The
/// distinctions (CLI absent / not authenticated / secret not found) are derived
/// from coarse stderr signals so a misconfiguration is actionable (§6.3) without
/// surfacing arbitrary CLI text (I12).
fn classify_failure(parsed: &AzureRef, status: Option<i32>, stderr: &[u8]) -> CoreError {
    let lower = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    let kind = if lower.contains("az login")
        || lower.contains("please run")
        || lower.contains("not logged in")
        || lower.contains("authentication")
        || lower.contains("credential")
        // An Azure Key Vault auth failure — an expired/wrong-tenant token
        // ("Unauthorized" / "Invalid issuer" / the `AKV10032` issuer code) or a
        // 403 — is an identity problem, not a generic CLI failure: re-login or
        // fix the tenant/access policy.
        || lower.contains("unauthorized")
        || lower.contains("invalid issuer")
        || lower.contains("akv10032")
        || lower.contains("forbidden")
    {
        "az is not authenticated or lacks access (run `az login`; check the tenant and the vault access policy)"
    } else if lower.contains("vaultnotfound")
        || lower.contains("no such host")
        || lower.contains("could not be resolved")
        // DNS / connection failure: the vault host never resolved, so the vault
        // is unreachable (a missing *secret* would have resolved the host first).
        // Checked BEFORE the secret-not-found branch so a connection failure is
        // never misread as a missing secret. Covers macOS ("nodename nor
        // servname"), Linux ("name or service not known"), and the `az`/requests
        // wrappers ("failed to resolve", "getaddrinfo", "max retries exceeded").
        || lower.contains("failed to resolve")
        || lower.contains("nodename nor servname")
        || lower.contains("name or service not known")
        || lower.contains("getaddrinfo")
        || lower.contains("max retries exceeded")
    {
        "the vault was not found or is unreachable"
    } else if lower.contains("secretnotfound")
        || lower.contains("was not found")
        || lower.contains("not found")
    {
        "the secret was not found in the vault (check the name and your access)"
    } else {
        "the `az` invocation failed"
    };
    CoreError::Provider(format!(
        "azure-kv: {kind} [vault=`{}`, secret=`{}`, exit={}]",
        parsed.vault,
        parsed.secret,
        status
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".into()),
    ))
}

// ─────────────────────────── [host] real runner ───────────────────────────
//
// [host] — NOT unit-tested. This is the only code path that shells out to the
// real `az` CLI; a human validates it against a live Key Vault (see the §6
// checklist). It inherits the environment's identity (no stored credential, no
// `--subscription`). Kept isolated from the trait/parse logic above so the unit
// tests exercise everything else with `MockAzRunner`.

/// The production runner: launches the real `az` CLI via `std::process`. `[host]`
/// — validated by a human against a live Key Vault, never in CI unit tests.
pub struct SystemAzRunner;

impl AzRunner for SystemAzRunner {
    // [host]: shells out to the real `az`, enforcing the per-invocation timeout
    // (§6.3) via `wait-timeout` so a hung `az` can't block the wrapper forever.
    // A spawn failure (no `az` on PATH) is the "CLI absent" case and surfaces as
    // a clear provider error.
    fn run(&self, args: &[String], timeout: Duration) -> Result<AzOutput, CoreError> {
        use std::io::Read;
        use std::process::{Command, Stdio};
        use wait_timeout::ChildExt;

        let mut child = Command::new("az")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                CoreError::Provider(format!(
                    "azure-kv: could not run `az` — is the Azure CLI installed and on PATH? ({e})"
                ))
            })?;

        let status = match child
            .wait_timeout(timeout)
            .map_err(|e| CoreError::Provider(format!("azure-kv: waiting on `az` failed ({e})")))?
        {
            Some(status) => status,
            None => {
                // Timed out: kill the hung `az` and reap it. No value materialized.
                let _ = child.kill();
                let _ = child.wait();
                return Err(CoreError::Provider(format!(
                    "azure-kv: `az` timed out after {}s",
                    timeout.as_secs()
                )));
            }
        };

        // Exited within the deadline; drain its (small) output. `az` emits a
        // single secret value, well under the pipe buffer.
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        if let Some(mut o) = child.stdout.take() {
            let _ = o.read_to_end(&mut stdout);
        }
        if let Some(mut e) = child.stderr.take() {
            let _ = e.read_to_end(&mut stderr);
        }
        Ok(AzOutput {
            status: status.code(),
            stdout: Zeroizing::new(stdout),
            stderr,
        })
    }
}

// ─────────────────────────── mock runner (tests) ───────────────────────────

/// A scripted `az` runner for tests: returns a configured [`AzOutput`] and
/// records the args it was called with (to assert the exact command form).
pub struct MockAzRunner {
    output: std::sync::Mutex<Option<AzOutput>>,
    last_args: std::sync::Mutex<Option<Vec<String>>>,
    launch_error: bool,
}

impl MockAzRunner {
    /// A runner that returns a success (`exit 0`) with `stdout` as the value.
    pub fn ok(stdout: &str) -> Self {
        Self::with_output(AzOutput {
            status: Some(0),
            stdout: Zeroizing::new(stdout.as_bytes().to_vec()),
            stderr: Vec::new(),
        })
    }

    /// A runner returning a non-zero exit with the given stderr (a failure mode).
    pub fn failed(code: i32, stderr: &str) -> Self {
        Self::with_output(AzOutput {
            status: Some(code),
            stdout: Zeroizing::new(Vec::new()),
            stderr: stderr.as_bytes().to_vec(),
        })
    }

    /// A runner whose underlying `az` cannot be launched at all (CLI absent).
    pub fn launch_failure() -> Self {
        Self {
            output: std::sync::Mutex::new(None),
            last_args: std::sync::Mutex::new(None),
            launch_error: true,
        }
    }

    fn with_output(output: AzOutput) -> Self {
        Self {
            output: std::sync::Mutex::new(Some(output)),
            last_args: std::sync::Mutex::new(None),
            launch_error: false,
        }
    }

    /// The args the runner was last invoked with (to assert the `az` command).
    pub fn last_args(&self) -> Option<Vec<String>> {
        self.last_args.lock().expect("mock mutex poisoned").clone()
    }
}

impl AzRunner for MockAzRunner {
    fn run(&self, args: &[String], _timeout: Duration) -> Result<AzOutput, CoreError> {
        *self.last_args.lock().expect("mock mutex poisoned") = Some(args.to_vec());
        if self.launch_error {
            return Err(CoreError::Provider(
                "azure-kv: could not run `az` — is the Azure CLI installed and on PATH? (mock)"
                    .into(),
            ));
        }
        self.output
            .lock()
            .expect("mock mutex poisoned")
            .take()
            .ok_or_else(|| CoreError::Provider("mock runner already consumed".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── strict URI grammar (decision 2) ──

    #[test]
    fn parses_a_well_formed_reference() {
        let r = AzureRef::parse("azure-kv://corp-kv/db-url").unwrap();
        assert_eq!(r.vault, "corp-kv");
        assert_eq!(r.secret, "db-url");
    }

    #[test]
    fn az_args_match_the_spec_command_form() {
        // spec §6.2: az keyvault secret show --vault-name <v> --name <s>
        //            --query value -o tsv   (no --subscription)
        let r = AzureRef::parse("azure-kv://corp-kv/db-url").unwrap();
        assert_eq!(
            r.az_args(),
            vec![
                "keyvault",
                "secret",
                "show",
                "--vault-name",
                "corp-kv",
                "--name",
                "db-url",
                "--query",
                "value",
                "-o",
                "tsv",
            ]
        );
        assert!(
            !r.az_args().iter().any(|a| a == "--subscription"),
            "must not pin a subscription — identity is ambient (§6.2)"
        );
    }

    #[test]
    fn rejects_malformed_references_clearly() {
        for bad in [
            "azure-kv://",           // nothing after scheme
            "azure-kv://only-vault", // no /secret
            "azure-kv:///secret",    // empty vault
            "azure-kv://vault/",     // empty secret
            "azure-kv://vault/a/b",  // nested path
            "aws-sm://vault/secret", // wrong scheme
            "not-a-uri",             // no scheme
        ] {
            assert!(
                matches!(AzureRef::parse(bad), Err(CoreError::Provider(_))),
                "`{bad}` must be a clear Provider error, never silently parsed"
            );
        }
    }

    // ── resolution success ──

    #[test]
    fn materialize_returns_the_value_and_trims_one_newline() {
        let provider = AzureProvider::new(MockAzRunner::ok("postgres://h/db\n"));
        let v = provider.materialize("azure-kv://corp-kv/db-url").unwrap();
        assert_eq!(v.expose(), b"postgres://h/db");
        // the exact spec command form reached the runner
        let args = provider.runner.last_args().unwrap();
        assert_eq!(args[0], "keyvault");
        assert!(args.contains(&"--vault-name".to_string()));
    }

    #[test]
    fn declares_the_azure_kv_scheme() {
        let provider = AzureProvider::new(MockAzRunner::ok("x"));
        assert_eq!(provider.scheme(), "azure-kv");
    }

    // ── failure modes: each a distinct, clear error (never silent-empty) ──

    #[test]
    fn az_missing_is_a_clear_error() {
        let provider = AzureProvider::new(MockAzRunner::launch_failure());
        let err = provider
            .materialize("azure-kv://corp-kv/db-url")
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("az"), "names the missing CLI: {msg}");
    }

    #[test]
    fn az_not_authenticated_is_a_distinct_error() {
        let provider = AzureProvider::new(MockAzRunner::failed(
            1,
            "ERROR: Please run 'az login' to setup account.",
        ));
        let err = provider
            .materialize("azure-kv://corp-kv/db-url")
            .unwrap_err();
        assert!(format!("{err}").contains("authenticated"));
    }

    #[test]
    fn secret_not_found_is_a_distinct_error() {
        let provider = AzureProvider::new(MockAzRunner::failed(
            3,
            "ERROR: (SecretNotFound) A secret with (name/id) db-url was not found in this key vault.",
        ));
        let err = provider
            .materialize("azure-kv://corp-kv/db-url")
            .unwrap_err();
        assert!(format!("{err}").contains("not found"));
    }

    #[test]
    fn akv_unauthorized_issuer_classifies_as_auth() {
        // Real Key Vault auth failure (wrong-tenant / expired token).
        let provider = AzureProvider::new(MockAzRunner::failed(
            1,
            "ERROR: (Unauthorized) AKV10032: Invalid issuer. Expected one of \
             https://sts.windows.net/<t>/, found https://sts.windows.net/<other>/.",
        ));
        let err = provider
            .materialize("azure-kv://corp-kv/db-url")
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("authenticated") || msg.contains("access"),
            "an Unauthorized/issuer error must classify as auth, not generic: {msg}"
        );
    }

    #[test]
    fn vault_unreachable_dns_failure_is_classified() {
        // The real macOS `az` stderr for a non-existent vault host (DNS failure).
        let provider = AzureProvider::new(MockAzRunner::failed(
            1,
            "ERROR: HTTPSConnection(host='nope.vault.azure.net', port=443): \
             Failed to resolve 'nope.vault.azure.net' \
             ([Errno 8] nodename nor servname provided, or not known)",
        ));
        let err = provider.materialize("azure-kv://nope/secret").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("unreachable"),
            "a DNS failure must classify as vault-unreachable: {msg}"
        );
        // …and must NOT be misread as a missing secret (the host never resolved).
        assert!(!msg.contains("secret was not found"));
    }

    #[test]
    fn empty_value_on_success_is_refused_not_injected() {
        let provider = AzureProvider::new(MockAzRunner::ok("\n"));
        let err = provider
            .materialize("azure-kv://corp-kv/db-url")
            .unwrap_err();
        assert!(format!("{err}").contains("empty value"));
    }

    // I12 — a runner failure error never echoes back interior secret-looking
    // stderr verbatim beyond the coarse classification; the value is never in it.
    #[test]
    fn failure_error_carries_no_value_bytes() {
        // even if stderr somehow contained a value-shaped token, the error is
        // built from the classification + the (non-secret) coordinate, not from
        // the raw stdout (which on failure is empty anyway).
        let provider = AzureProvider::new(MockAzRunner::failed(2, "ERROR: some-opaque-failure"));
        let err = provider
            .materialize("azure-kv://corp-kv/db-url")
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("corp-kv") && msg.contains("db-url"));
        assert!(!msg.contains("some-opaque-failure"));
    }
}
