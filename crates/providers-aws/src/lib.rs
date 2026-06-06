//! `kovra-providers-aws` — the AWS Secrets Manager [`SecretProvider`] (spec §6.2).
//!
//! Materializes an `aws-sm://<region>/<secret-name>` reference **at run time** by
//! invoking the `aws` CLI with the **executing environment's own identity** (the
//! dev machine's `aws configure`/SSO, or a host's instance/role credentials).
//! `kovra` manages no cloud credential and passes no `--profile` — the ambient
//! `aws` context decides who you are (§6.2). AWS Secrets Manager secrets are
//! regional, so the **region travels in the reference** (it is an address, not an
//! identity). The materialized value is never stored (I8), never logged or written
//! to disk (I7), and never placed on an audit event (I12 — the resolver audits
//! only the coordinate + the `aws-sm` scheme).
//!
//! The `aws` invocation goes through the [`AwsRunner`] trait so the provider is
//! unit-tested with [`MockAwsRunner`] (no real `aws`, no network); the real
//! [`SystemAwsRunner`] is `[host]` and validated by a human against a live Secrets
//! Manager secret. `core` depends only on the [`SecretProvider`] trait (§6.1);
//! this crate is the only place that knows about AWS.

use std::time::Duration;

use kovra_core::{CoreError, SecretProvider, SecretValue};
use zeroize::Zeroizing;

/// The URI scheme this provider handles.
pub const SCHEME: &str = "aws-sm";

/// Default per-invocation timeout (§6.1) when the caller does not set one.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// A strictly-parsed `aws-sm://<region>/<secret-name>` reference (§6.2).
///
/// The grammar is exact: the `aws-sm://` scheme, then a non-empty region, a single
/// separating `/`, then a non-empty secret name. **Unlike Azure**, the secret name
/// **may contain `/`** — AWS Secrets Manager names legitimately use slashes
/// (`prod/db/password`), so everything after the first `/` is the secret id. A
/// malformed reference is a clear error — never a silent empty, never a fabricated
/// value (decision 2). The parsed parts are addresses, not secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsRef {
    /// The AWS region the secret lives in (`--region`).
    pub region: String,
    /// The secret id/name within the region (`--secret-id`); may contain `/`.
    pub secret: String,
}

impl AwsRef {
    /// Parse `aws-sm://<region>/<secret-name>`, validating the grammar exactly.
    pub fn parse(reference: &str) -> Result<Self, CoreError> {
        let rest = reference.strip_prefix("aws-sm://").ok_or_else(|| {
            CoreError::Provider(format!(
                "reference `{reference}` is not an `aws-sm://<region>/<secret>` URI"
            ))
        })?;
        // Split the region (first segment) from the secret id (everything after the
        // first `/`). The secret id may itself contain `/` (AWS allows it), so we
        // split once and keep the remainder whole.
        let (region, secret) = rest.split_once('/').ok_or_else(|| {
            CoreError::Provider(format!(
                "aws-sm reference `{reference}` is missing the `/<secret-name>` part"
            ))
        })?;
        if region.is_empty() {
            return Err(CoreError::Provider(format!(
                "aws-sm reference `{reference}` has an empty region"
            )));
        }
        if secret.is_empty() {
            return Err(CoreError::Provider(format!(
                "aws-sm reference `{reference}` has an empty secret name"
            )));
        }
        Ok(Self {
            region: region.to_string(),
            secret: secret.to_string(),
        })
    }

    /// The `aws` argv (after the `aws` program) for this reference (§6.2):
    /// `secretsmanager get-secret-value --secret-id <s> --region <r>
    /// --query SecretString --output text`. No `--profile` — the ambient `aws`
    /// context decides identity; only the region (an address) is pinned.
    pub fn aws_args(&self) -> Vec<String> {
        vec![
            "secretsmanager".into(),
            "get-secret-value".into(),
            "--secret-id".into(),
            self.secret.clone(),
            "--region".into(),
            self.region.clone(),
            "--query".into(),
            "SecretString".into(),
            "--output".into(),
            "text".into(),
        ]
    }
}

/// The captured result of running `aws`. `stdout` is **secret-bearing** (it is the
/// materialized value) and is held in a zeroizing buffer; it is never logged.
pub struct AwsOutput {
    /// Process exit code, or `None` if terminated by a signal.
    pub status: Option<i32>,
    /// Captured stdout — the secret value on success (zeroized on drop).
    pub stdout: Zeroizing<Vec<u8>>,
    /// Captured stderr — diagnostics only; must not be assumed value-free, so it
    /// is mapped to coarse, non-echoing errors below (never surfaced verbatim).
    pub stderr: Vec<u8>,
}

/// Runs the `aws` CLI. Behind a trait so [`AwsProvider`] is tested with
/// [`MockAwsRunner`] (no real `aws`); production uses [`SystemAwsRunner`].
pub trait AwsRunner {
    /// Run `aws <args...>` to completion under `timeout`, capturing its output.
    /// An `Err` here is a *failure to launch/await* `aws` itself (e.g. the binary
    /// is absent) — a non-zero exit is reported through [`AwsOutput::status`].
    fn run(&self, args: &[String], timeout: Duration) -> Result<AwsOutput, CoreError>;
}

/// The AWS Secrets Manager provider. Holds an [`AwsRunner`] and a per-invocation
/// timeout (§6.1); the runner is the only seam to the outside world.
pub struct AwsProvider<R: AwsRunner> {
    runner: R,
    timeout: Duration,
}

impl<R: AwsRunner> AwsProvider<R> {
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

impl<R: AwsRunner> SecretProvider for AwsProvider<R> {
    fn materialize(&self, reference: &str) -> Result<SecretValue, CoreError> {
        // Strict parse first (decision 2): a malformed URI never reaches `aws`.
        let parsed = AwsRef::parse(reference)?;
        let out = self.runner.run(&parsed.aws_args(), self.timeout)?;

        if out.status != Some(0) {
            // Map the failure to a clear, specific error without echoing stderr
            // verbatim (it may carry incidental detail; I12 keeps us coarse).
            return Err(classify_failure(&parsed, out.status, &out.stderr));
        }

        // Success: the value is stdout with a single trailing newline trimmed
        // (`--output text` appends one). Trim exactly one `\n`/`\r\n` — do not strip
        // interior or intentional trailing whitespace that is part of the value.
        let trimmed = trim_one_trailing_newline(&out.stdout);
        // An empty value after a successful `aws` is suspicious (a Secrets Manager
        // SecretString is non-empty); refuse rather than inject an empty string
        // silently.
        if trimmed.is_empty() {
            return Err(CoreError::Provider(format!(
                "aws-sm secret `{}` in region `{}` resolved to an empty value",
                parsed.secret, parsed.region
            )));
        }
        Ok(SecretValue::new(trimmed.to_vec()))
    }

    fn scheme(&self) -> &'static str {
        SCHEME
    }
}

/// Trim exactly one trailing newline (`\n`, or `\r\n`) from `aws`'s text output.
fn trim_one_trailing_newline(bytes: &[u8]) -> &[u8] {
    if let Some(stripped) = bytes.strip_suffix(b"\n") {
        stripped.strip_suffix(b"\r").unwrap_or(stripped)
    } else {
        bytes
    }
}

/// Map a non-zero `aws` exit into a specific, non-echoing provider error. The
/// distinctions (CLI absent / not authenticated / secret not found / region
/// unreachable) are derived from coarse stderr signals so a misconfiguration is
/// actionable (§6.3) without surfacing arbitrary CLI text (I12).
fn classify_failure(parsed: &AwsRef, status: Option<i32>, stderr: &[u8]) -> CoreError {
    let lower = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    let kind = if lower.contains("could not connect to the endpoint")
        || lower.contains("endpointconnectionerror")
        || lower.contains("invalid region")
        || lower.contains("could not be found for the region")
        // DNS / connection failure: the regional endpoint never resolved, so the
        // service is unreachable. Checked BEFORE the secret-not-found branch so a
        // connection failure is never misread as a missing secret. Covers macOS
        // ("nodename nor servname"), Linux ("name or service not known"), and the
        // botocore wrappers ("getaddrinfo", "failed to establish a new connection").
        || lower.contains("failed to establish a new connection")
        || lower.contains("nodename nor servname")
        || lower.contains("name or service not known")
        || lower.contains("getaddrinfo")
    {
        "the region endpoint is unreachable or the region is invalid"
    } else if lower.contains("unable to locate credentials")
        || lower.contains("expiredtoken")
        || lower.contains("token has expired")
        || lower.contains("the security token included in the request is expired")
        || lower.contains("invalidclienttokenid")
        || lower.contains("unrecognizedclientexception")
        || lower.contains("accessdenied")
        || lower.contains("not authorized to perform")
        // An AWS auth failure — missing/expired credentials, an SSO session that
        // lapsed, or an IAM policy denial — is an identity problem, not a generic
        // CLI failure: re-authenticate (`aws sso login` / refresh keys) or fix the
        // IAM permission on `secretsmanager:GetSecretValue`.
        || lower.contains("sso session associated")
        || lower.contains("forbidden")
    {
        "aws is not authenticated or lacks access (refresh credentials, e.g. `aws sso login`; check the IAM permission for secretsmanager:GetSecretValue)"
    } else if lower.contains("resourcenotfoundexception")
        || lower.contains("can't find the specified secret")
        || lower.contains("can't find the resource")
        || lower.contains("was not found")
        || lower.contains("not found")
    {
        "the secret was not found in the region (check the name and your access)"
    } else {
        "the `aws` invocation failed"
    };
    CoreError::Provider(format!(
        "aws-sm: {kind} [region=`{}`, secret=`{}`, exit={}]",
        parsed.region,
        parsed.secret,
        status
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".into()),
    ))
}

// ─────────────────────────── [host] real runner ───────────────────────────
//
// [host] — NOT unit-tested. This is the only code path that shells out to the
// real `aws` CLI; a human validates it against a live Secrets Manager secret (see
// the §6 checklist). It inherits the environment's identity (no stored credential,
// no `--profile`). Kept isolated from the trait/parse logic above so the unit
// tests exercise everything else with `MockAwsRunner`.

/// The production runner: launches the real `aws` CLI via `std::process`. `[host]`
/// — validated by a human against a live Secrets Manager secret, never in CI unit
/// tests.
pub struct SystemAwsRunner;

impl AwsRunner for SystemAwsRunner {
    // [host]: shells out to the real `aws`, enforcing the per-invocation timeout
    // (§6.3) via `wait-timeout` so a hung `aws` can't block the wrapper forever.
    // A spawn failure (no `aws` on PATH) is the "CLI absent" case and surfaces as
    // a clear provider error.
    fn run(&self, args: &[String], timeout: Duration) -> Result<AwsOutput, CoreError> {
        use std::io::Read;
        use std::process::{Command, Stdio};
        use wait_timeout::ChildExt;

        let mut child = Command::new("aws")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                CoreError::Provider(format!(
                    "aws-sm: could not run `aws` — is the AWS CLI installed and on PATH? ({e})"
                ))
            })?;

        let status = match child
            .wait_timeout(timeout)
            .map_err(|e| CoreError::Provider(format!("aws-sm: waiting on `aws` failed ({e})")))?
        {
            Some(status) => status,
            None => {
                // Timed out: kill the hung `aws` and reap it. No value materialized.
                let _ = child.kill();
                let _ = child.wait();
                return Err(CoreError::Provider(format!(
                    "aws-sm: `aws` timed out after {}s",
                    timeout.as_secs()
                )));
            }
        };

        // Exited within the deadline; drain its (small) output. `aws` emits a
        // single secret value, well under the pipe buffer.
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        if let Some(mut o) = child.stdout.take() {
            let _ = o.read_to_end(&mut stdout);
        }
        if let Some(mut e) = child.stderr.take() {
            let _ = e.read_to_end(&mut stderr);
        }
        Ok(AwsOutput {
            status: status.code(),
            stdout: Zeroizing::new(stdout),
            stderr,
        })
    }
}

// ─────────────────────────── mock runner (tests) ───────────────────────────

/// A scripted `aws` runner for tests: returns a configured [`AwsOutput`] and
/// records the args it was called with (to assert the exact command form).
pub struct MockAwsRunner {
    output: std::sync::Mutex<Option<AwsOutput>>,
    last_args: std::sync::Mutex<Option<Vec<String>>>,
    launch_error: bool,
}

impl MockAwsRunner {
    /// A runner that returns a success (`exit 0`) with `stdout` as the value.
    pub fn ok(stdout: &str) -> Self {
        Self::with_output(AwsOutput {
            status: Some(0),
            stdout: Zeroizing::new(stdout.as_bytes().to_vec()),
            stderr: Vec::new(),
        })
    }

    /// A runner returning a non-zero exit with the given stderr (a failure mode).
    pub fn failed(code: i32, stderr: &str) -> Self {
        Self::with_output(AwsOutput {
            status: Some(code),
            stdout: Zeroizing::new(Vec::new()),
            stderr: stderr.as_bytes().to_vec(),
        })
    }

    /// A runner whose underlying `aws` cannot be launched at all (CLI absent).
    pub fn launch_failure() -> Self {
        Self {
            output: std::sync::Mutex::new(None),
            last_args: std::sync::Mutex::new(None),
            launch_error: true,
        }
    }

    fn with_output(output: AwsOutput) -> Self {
        Self {
            output: std::sync::Mutex::new(Some(output)),
            last_args: std::sync::Mutex::new(None),
            launch_error: false,
        }
    }

    /// The args the runner was last invoked with (to assert the `aws` command).
    pub fn last_args(&self) -> Option<Vec<String>> {
        self.last_args.lock().expect("mock mutex poisoned").clone()
    }
}

impl AwsRunner for MockAwsRunner {
    fn run(&self, args: &[String], _timeout: Duration) -> Result<AwsOutput, CoreError> {
        *self.last_args.lock().expect("mock mutex poisoned") = Some(args.to_vec());
        if self.launch_error {
            return Err(CoreError::Provider(
                "aws-sm: could not run `aws` — is the AWS CLI installed and on PATH? (mock)".into(),
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
        let r = AwsRef::parse("aws-sm://us-east-1/db-url").unwrap();
        assert_eq!(r.region, "us-east-1");
        assert_eq!(r.secret, "db-url");
    }

    #[test]
    fn secret_name_may_contain_slashes() {
        // AWS Secrets Manager names legitimately use slashes — unlike Azure, the
        // secret id is everything after the first `/` and is kept whole.
        let r = AwsRef::parse("aws-sm://eu-west-1/prod/db/password").unwrap();
        assert_eq!(r.region, "eu-west-1");
        assert_eq!(r.secret, "prod/db/password");
    }

    #[test]
    fn aws_args_match_the_spec_command_form() {
        // spec §6.2: aws secretsmanager get-secret-value --secret-id <s>
        //            --region <r> --query SecretString --output text  (no --profile)
        let r = AwsRef::parse("aws-sm://us-east-1/db-url").unwrap();
        assert_eq!(
            r.aws_args(),
            vec![
                "secretsmanager",
                "get-secret-value",
                "--secret-id",
                "db-url",
                "--region",
                "us-east-1",
                "--query",
                "SecretString",
                "--output",
                "text",
            ]
        );
        assert!(
            !r.aws_args().iter().any(|a| a == "--profile"),
            "must not pin a profile — identity is ambient (§6.2)"
        );
    }

    #[test]
    fn rejects_malformed_references_clearly() {
        for bad in [
            "aws-sm://",               // nothing after scheme
            "aws-sm://only-region",    // no /secret
            "aws-sm:///secret",        // empty region
            "aws-sm://us-east-1/",     // empty secret
            "azure-kv://vault/secret", // wrong scheme
            "not-a-uri",               // no scheme
        ] {
            assert!(
                matches!(AwsRef::parse(bad), Err(CoreError::Provider(_))),
                "`{bad}` must be a clear Provider error, never silently parsed"
            );
        }
    }

    // ── resolution success ──

    #[test]
    fn materialize_returns_the_value_and_trims_one_newline() {
        let provider = AwsProvider::new(MockAwsRunner::ok("postgres://h/db\n"));
        let v = provider.materialize("aws-sm://us-east-1/db-url").unwrap();
        assert_eq!(v.expose(), b"postgres://h/db");
        // the exact spec command form reached the runner
        let args = provider.runner.last_args().unwrap();
        assert_eq!(args[0], "secretsmanager");
        assert!(args.contains(&"--region".to_string()));
        assert!(args.contains(&"--secret-id".to_string()));
    }

    #[test]
    fn declares_the_aws_sm_scheme() {
        let provider = AwsProvider::new(MockAwsRunner::ok("x"));
        assert_eq!(provider.scheme(), "aws-sm");
    }

    // ── failure modes: each a distinct, clear error (never silent-empty) ──

    #[test]
    fn aws_missing_is_a_clear_error() {
        let provider = AwsProvider::new(MockAwsRunner::launch_failure());
        let err = provider
            .materialize("aws-sm://us-east-1/db-url")
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("aws"), "names the missing CLI: {msg}");
    }

    #[test]
    fn no_credentials_is_a_distinct_auth_error() {
        let provider = AwsProvider::new(MockAwsRunner::failed(
            255,
            "Unable to locate credentials. You can configure credentials by running \"aws configure\".",
        ));
        let err = provider
            .materialize("aws-sm://us-east-1/db-url")
            .unwrap_err();
        assert!(format!("{err}").contains("authenticated"));
    }

    #[test]
    fn expired_token_classifies_as_auth() {
        let provider = AwsProvider::new(MockAwsRunner::failed(
            255,
            "An error occurred (ExpiredTokenException) when calling the GetSecretValue \
             operation: The security token included in the request is expired",
        ));
        let err = provider
            .materialize("aws-sm://us-east-1/db-url")
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("authenticated") || msg.contains("access"),
            "an expired token must classify as auth, not generic: {msg}"
        );
    }

    #[test]
    fn access_denied_classifies_as_auth() {
        let provider = AwsProvider::new(MockAwsRunner::failed(
            255,
            "An error occurred (AccessDeniedException) when calling the GetSecretValue \
             operation: User is not authorized to perform secretsmanager:GetSecretValue",
        ));
        let err = provider
            .materialize("aws-sm://us-east-1/db-url")
            .unwrap_err();
        assert!(format!("{err}").contains("access") || format!("{err}").contains("authenticated"));
    }

    #[test]
    fn secret_not_found_is_a_distinct_error() {
        let provider = AwsProvider::new(MockAwsRunner::failed(
            255,
            "An error occurred (ResourceNotFoundException) when calling the GetSecretValue \
             operation: Secrets Manager can't find the specified secret.",
        ));
        let err = provider
            .materialize("aws-sm://us-east-1/db-url")
            .unwrap_err();
        assert!(format!("{err}").contains("not found"));
    }

    #[test]
    fn region_unreachable_is_classified_not_misread_as_missing_secret() {
        let provider = AwsProvider::new(MockAwsRunner::failed(
            255,
            "Could not connect to the endpoint URL: \
             \"https://secretsmanager.zz-nowhere-1.amazonaws.com/\"",
        ));
        let err = provider
            .materialize("aws-sm://zz-nowhere-1/db-url")
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("unreachable") || msg.contains("region"),
            "a connection failure must classify as region-unreachable: {msg}"
        );
        assert!(!msg.contains("secret was not found"));
    }

    #[test]
    fn empty_value_on_success_is_refused_not_injected() {
        let provider = AwsProvider::new(MockAwsRunner::ok("\n"));
        let err = provider
            .materialize("aws-sm://us-east-1/db-url")
            .unwrap_err();
        assert!(format!("{err}").contains("empty value"));
    }

    // I12 — a runner failure error never echoes back interior secret-looking
    // stderr verbatim beyond the coarse classification; the value is never in it.
    #[test]
    fn failure_error_carries_no_value_bytes() {
        let provider = AwsProvider::new(MockAwsRunner::failed(2, "ERROR: some-opaque-failure"));
        let err = provider
            .materialize("aws-sm://us-east-1/db-url")
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("us-east-1") && msg.contains("db-url"));
        assert!(!msg.contains("some-opaque-failure"));
    }
}
