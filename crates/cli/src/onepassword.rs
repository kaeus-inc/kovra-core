//! 1Password import seam (KOV-24): read a credential's value out of 1Password
//! via the `op` CLI so `kovra import` can store it as a **literal** in the vault.
//!
//! This is **not** a provider — there is no `op://` reference scheme and no
//! run-time materialization. `kovra import` performs a one-time copy: it reads
//! the value once and seals it into the vault as a literal, after which kovra
//! custodies it independently of 1Password (no relationship is kept).
//!
//! The `op` invocation goes through the [`OpRunner`] trait so the import logic
//! is unit-tested with [`MockOpRunner`] (no real `op`, no account); the real
//! [`SystemOpRunner`] is `[host]` and validated against a live 1Password
//! account. The value is secret-bearing: it is held in a [`Zeroizing`] buffer,
//! never logged, and never placed in `argv` (only the `op://` address is — that
//! is not a secret, I6/I12).

use anyhow::{Result, anyhow, bail};
use zeroize::Zeroizing;

/// The captured result of running `op read`. `stdout` is **secret-bearing** (the
/// materialized value) and is held in a zeroizing buffer; it is never logged.
pub struct OpOutput {
    /// Process exit code, or `None` if terminated by a signal.
    pub status: Option<i32>,
    /// Captured stdout — the secret value on success (zeroized on drop).
    pub stdout: Zeroizing<Vec<u8>>,
    /// Captured stderr — diagnostics only; mapped to coarse, non-echoing errors.
    pub stderr: Vec<u8>,
}

/// Runs the `op` CLI. Behind a trait so the import path is tested with
/// [`MockOpRunner`] (no real `op`); production uses [`SystemOpRunner`].
pub trait OpRunner {
    /// Run `op read <reference>` to completion, capturing its output. An `Err`
    /// here is a *failure to launch* `op` (e.g. the binary is absent); a non-zero
    /// exit is reported through [`OpOutput::status`].
    fn read(&self, reference: &str) -> Result<OpOutput>;

    /// Run `op item get <item> --reveal --format json` (optionally `--vault`),
    /// capturing the item JSON. **Secret-bearing** (revealed fields) — held in a
    /// zeroizing buffer, never logged. Used by `key import --op` (KOV-34).
    fn get_item(&self, item: &str, vault: Option<&str>) -> Result<OpOutput>;

    /// Run `op item list --format json`, capturing the inventory (id, title,
    /// vault, dates — **not** secret-bearing). Used to disambiguate same-named
    /// items for `key import --op` (KOV-34).
    fn list_items(&self) -> Result<OpOutput>;
}

/// One duplicate-name candidate: enough to tell apart same-named items (id,
/// vault, and last-edited timestamp).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpItemCandidate {
    pub id: String,
    pub vault: String,
    pub updated: String,
}

/// True if `stderr` is the `op item get` "more than one item matches" ambiguity.
pub fn is_ambiguous_match(stderr: &[u8]) -> bool {
    let l = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    l.contains("more than one item")
        || l.contains("multiple items")
        || l.contains("more than one object")
}

/// List the items titled exactly `name` through `runner` (`op item list`),
/// returning a candidate per match with its vault and last-edited date — so the
/// user can tell duplicates apart by date, not just id (KOV-34).
pub fn named_item_candidates(runner: &dyn OpRunner, name: &str) -> Result<Vec<OpItemCandidate>> {
    let out = runner.list_items()?;
    if out.status != Some(0) {
        return Err(classify_failure(name, out.status, &out.stderr));
    }
    let items: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|_| anyhow!("1Password: could not parse `op item list` output"))?;
    Ok(items
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|it| it["title"].as_str() == Some(name))
        .filter_map(|it| {
            Some(OpItemCandidate {
                id: it["id"].as_str()?.to_string(),
                vault: it["vault"]["name"].as_str().unwrap_or("?").to_string(),
                updated: it["updated_at"]
                    .as_str()
                    .map(|s| s.get(..16).unwrap_or(s).replace('T', " "))
                    .unwrap_or_default(),
            })
        })
        .collect())
}

/// Parse the `age_backup` + `password` fields out of an `op item get --format
/// json` payload, both in zeroizing buffers. A missing field is a clear error.
pub fn parse_backup_fields(json: &[u8]) -> Result<(Zeroizing<String>, Zeroizing<String>)> {
    let v: serde_json::Value = serde_json::from_slice(json)
        .map_err(|_| anyhow!("1Password: could not parse `op item get` output"))?;
    let fields = v["fields"]
        .as_array()
        .ok_or_else(|| anyhow!("1Password item has no fields"))?;
    let field = |id: &str| {
        fields
            .iter()
            .find(|f| f["id"].as_str() == Some(id))
            .and_then(|f| f["value"].as_str())
            .map(str::to_string)
    };
    let blob = field("age_backup").ok_or_else(|| {
        anyhow!("the 1Password item has no `age backup` field — re-create it with `kovra key export --op`")
    })?;
    let pass = field("password")
        .ok_or_else(|| anyhow!("the 1Password item has no recovery-passphrase field"))?;
    Ok((Zeroizing::new(blob), Zeroizing::new(pass)))
}

/// Read a `key export --op` backup item from 1Password through `runner`: returns
/// `(armored_blob, recovery_passphrase)`. If the `item` name matches **more than
/// one** item (and no `vault` was given), `choose` is called with the candidates
/// to pick one by id (the CLI shows an interactive menu); the chosen id is then
/// fetched directly. `op` failures and missing fields map to clear, non-echoing
/// errors (I12).
pub fn read_backup_item<F>(
    runner: &dyn OpRunner,
    item: &str,
    vault: Option<&str>,
    choose: F,
) -> Result<(Zeroizing<String>, Zeroizing<String>)>
where
    F: FnOnce(&[OpItemCandidate]) -> Result<String>,
{
    let out = runner.get_item(item, vault)?;
    let resolved = if out.status == Some(0) {
        out
    } else if vault.is_none() && is_ambiguous_match(&out.stderr) {
        // Look up the same-named items (with dates) and let the caller pick one.
        let candidates = named_item_candidates(runner, item)?;
        if candidates.is_empty() {
            return Err(classify_failure(item, out.status, &out.stderr));
        }
        let id = choose(&candidates)?;
        let by_id = runner.get_item(&id, None)?;
        if by_id.status != Some(0) {
            return Err(classify_failure(&id, by_id.status, &by_id.stderr));
        }
        by_id
    } else {
        return Err(classify_failure(item, out.status, &out.stderr));
    };
    parse_backup_fields(&resolved.stdout)
}

/// Validate that `reference` is an `op://…` secret reference (the form `op read`
/// expects). The detailed grammar (vault/item/field) is `op`'s to enforce; we
/// only require the scheme and a non-empty body so a malformed string never
/// reaches the shell as something other than an address.
pub fn validate_reference(reference: &str) -> Result<()> {
    let rest = reference.strip_prefix("op://").ok_or_else(|| {
        anyhow!("`{reference}` is not an `op://<vault>/<item>/<field>` reference")
    })?;
    if rest.is_empty() {
        bail!("1Password reference `{reference}` is missing the `<vault>/<item>/<field>` part");
    }
    Ok(())
}

/// Read the value at `reference` from 1Password through `runner`. Returns the
/// value in a zeroizing buffer with a single trailing newline trimmed (`op read`
/// appends one). A successful-but-empty read is refused rather than stored as an
/// empty secret. Failures are mapped to clear, non-echoing messages.
pub fn read_value(runner: &dyn OpRunner, reference: &str) -> Result<Zeroizing<Vec<u8>>> {
    validate_reference(reference)?;
    let out = runner.read(reference)?;
    if out.status != Some(0) {
        return Err(classify_failure(reference, out.status, &out.stderr));
    }
    let trimmed = trim_one_trailing_newline(&out.stdout);
    if trimmed.is_empty() {
        bail!("1Password reference `{reference}` resolved to an empty value");
    }
    Ok(Zeroizing::new(trimmed.to_vec()))
}

/// Trim exactly one trailing newline (`\n` or `\r\n`) from `op read` output.
fn trim_one_trailing_newline(bytes: &[u8]) -> &[u8] {
    if let Some(stripped) = bytes.strip_suffix(b"\n") {
        stripped.strip_suffix(b"\r").unwrap_or(stripped)
    } else {
        bytes
    }
}

/// Map a non-zero `op` exit into a specific, non-echoing error. The distinctions
/// (not signed in / item or field not found) are derived from coarse stderr
/// signals so a misconfiguration is actionable, without surfacing arbitrary CLI
/// text (I12 — never the value, never raw stderr verbatim).
fn classify_failure(reference: &str, status: Option<i32>, stderr: &[u8]) -> anyhow::Error {
    let lower = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    let kind = if lower.contains("not currently signed in")
        || lower.contains("not signed in")
        || lower.contains("no account")
        || lower.contains("session expired")
        || lower.contains("sign in")
        || lower.contains("authorization")
        || lower.contains("authentication")
    {
        "not signed in to 1Password (run `op signin`, or enable the desktop app's CLI integration)"
    } else if lower.contains("more than one item")
        || lower.contains("multiple items")
        || lower.contains("more than one object")
    {
        "more than one 1Password item has this name — re-run with the item's **id** (run `op item get <name>` to list the ids), e.g. `kovra key import --op <id>`; or pass `--op-vault` if the duplicates are in different vaults"
    } else if lower.contains("isn't an item")
        || lower.contains("no item")
        || lower.contains("couldn't find")
        || lower.contains("could not find")
        || lower.contains("not found")
        || lower.contains("no such")
        || lower.contains("doesn't exist")
        || lower.contains("isn't a field")
    {
        "the item or field was not found in 1Password (check the name/id and `--op-vault`)"
    } else {
        "the `op` invocation failed"
    };
    anyhow!(
        "1Password: {kind} [reference=`{reference}`, exit={}]",
        status
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".into())
    )
}

// ───────────────────────── write seam (KOV-34, `--op`) ─────────────────────
//
// Storing a backup *into* 1Password (the mirror of `op read`). Behind a trait so
// `kovra key export --op` is unit-tested with [`MockOpWriter`]; the real
// [`SystemOpWriter`] shells out to `op` and is `[host]`-validated.

/// Creates a 1Password item from a JSON template via the `op` CLI.
pub trait OpWriter {
    /// Create a 1Password item from the `op item create -` JSON `template`
    /// (optionally in `vault`). The template is fed on **stdin**, so sensitive
    /// values inside it (the generated recovery passphrase) never touch `argv`
    /// (I6). Returns op's captured output; a non-zero exit is reported via
    /// [`OpOutput::status`]. An `Err` is a *failure to launch* `op`.
    fn create_item(&self, template: &str, vault: Option<&str>) -> Result<OpOutput>;

    /// Run `op vault list --format json`, capturing the output. Vault **names**
    /// are not secrets (used for interactive selection).
    fn list_vaults(&self) -> Result<OpOutput>;
}

/// List the available 1Password vault names through `writer` (for interactive
/// selection). `op` failures map to clear, non-echoing errors (I12).
pub fn vault_names(writer: &dyn OpWriter) -> Result<Vec<String>> {
    let out = writer.list_vaults()?;
    if out.status != Some(0) {
        return Err(classify_write_failure(out.status, &out.stderr));
    }
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|_| anyhow!("1Password: could not parse `op vault list` output"))?;
    Ok(parsed
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default())
}

/// Store a kovra backup in 1Password as a single **Password** item: the generated
/// recovery `passphrase` and the encrypted `blob` each in their own **concealed**
/// field, and the human `note` (restore steps) in `notesPlain` — so everything
/// needed to restore lives together (KOV-34 `--op`). The JSON template is built
/// here (so the secrets travel on stdin, never argv) and zeroized after use.
/// Returns the created item reference; `op` failures map to clear, non-echoing
/// errors (I12).
pub fn store_backup_item(
    writer: &dyn OpWriter,
    title: &str,
    vault: Option<&str>,
    passphrase: &str,
    blob: &str,
    note: &str,
) -> Result<String> {
    let template = Zeroizing::new(build_backup_template(title, passphrase, blob, note));
    let out = writer.create_item(&template, vault)?;
    if out.status != Some(0) {
        return Err(classify_write_failure(out.status, &out.stderr));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Build the op `PASSWORD`-category item JSON: the recovery passphrase and the
/// armored backup each in a **concealed** field, the restore steps in
/// `notesPlain`. `serde_json` escapes the multi-line blob and any special
/// characters.
fn build_backup_template(title: &str, passphrase: &str, blob: &str, note: &str) -> String {
    serde_json::json!({
        "title": title,
        "category": "PASSWORD",
        "fields": [
            {"id":"password","type":"CONCEALED","purpose":"PASSWORD","label":"recovery passphrase","value": passphrase},
            {"id":"age_backup","type":"CONCEALED","label":"age backup","value": blob},
            {"id":"notesPlain","type":"STRING","purpose":"NOTES","label":"notesPlain","value": note},
        ]
    })
    .to_string()
}

/// Map a non-zero `op` create exit into a specific, non-echoing error (I12).
fn classify_write_failure(status: Option<i32>, stderr: &[u8]) -> anyhow::Error {
    let lower = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    let kind = if lower.contains("not currently signed in")
        || lower.contains("not signed in")
        || lower.contains("no account")
        || lower.contains("session expired")
        || lower.contains("sign in")
    {
        "not signed in to 1Password (run `op signin`, or enable the desktop app's CLI integration)"
    } else if lower.contains("vault")
        && (lower.contains("not found")
            || lower.contains("isn't")
            || lower.contains("could not find")
            || lower.contains("couldn't find")
            || lower.contains("no such"))
    {
        "the target 1Password vault was not found (check `--op-vault`)"
    } else {
        "the `op` document-create failed"
    };
    anyhow!(
        "1Password: {kind} [exit={}]",
        status
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".into())
    )
}

// ─────────────────────────── [host] real runner ───────────────────────────
//
// [host] — NOT unit-tested. The only path that shells out to the real `op` CLI;
// validated by a human against a live 1Password account. `op read` triggers the
// account's own auth (desktop-app integration / `op signin` session); kovra
// stores no 1Password credential. Kept isolated so the unit tests exercise
// everything else with `MockOpRunner`.

/// The production runner: launches the real `op` CLI via `std::process`. `[host]`.
pub struct SystemOpRunner;

impl OpRunner for SystemOpRunner {
    fn read(&self, reference: &str) -> Result<OpOutput> {
        use std::process::Command;
        // `op read <op://…>` prints the single field value to stdout. The
        // reference is an address (not a secret), so it is fine on argv (I6).
        let out = Command::new("op")
            .args(["read", reference])
            .output()
            .map_err(|e| {
                anyhow!("1Password: could not run `op` — is the 1Password CLI installed and on PATH? ({e})")
            })?;
        Ok(OpOutput {
            status: out.status.code(),
            stdout: Zeroizing::new(out.stdout),
            stderr: out.stderr,
        })
    }

    fn get_item(&self, item: &str, vault: Option<&str>) -> Result<OpOutput> {
        use std::process::Command;
        // The item name/id is an address (not a secret) → fine on argv (I6).
        let mut cmd = Command::new("op");
        cmd.args(["item", "get", item, "--reveal", "--format", "json"]);
        if let Some(v) = vault {
            cmd.args(["--vault", v]);
        }
        let out = cmd.output().map_err(|e| {
            anyhow!(
                "1Password: could not run `op` — is the 1Password CLI installed and on PATH? ({e})"
            )
        })?;
        Ok(OpOutput {
            status: out.status.code(),
            stdout: Zeroizing::new(out.stdout),
            stderr: out.stderr,
        })
    }

    fn list_items(&self) -> Result<OpOutput> {
        use std::process::Command;
        let out = Command::new("op")
            .args(["item", "list", "--format", "json"])
            .output()
            .map_err(|e| {
                anyhow!(
                    "1Password: could not run `op` — is the 1Password CLI installed and on PATH? ({e})"
                )
            })?;
        Ok(OpOutput {
            status: out.status.code(),
            stdout: Zeroizing::new(out.stdout),
            stderr: out.stderr,
        })
    }
}

/// The production writer: launches the real `op` CLI via `std::process`. `[host]`.
///
/// The JSON item template is fed on **stdin** (`op item create -`), so the
/// generated recovery passphrase inside it never lands on `argv` or on disk
/// (only the non-secret title/vault are flags, I6).
pub struct SystemOpWriter;

impl OpWriter for SystemOpWriter {
    fn create_item(&self, template: &str, vault: Option<&str>) -> Result<OpOutput> {
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        let mut cmd = Command::new("op");
        cmd.args(["item", "create", "-"]);
        if let Some(v) = vault {
            cmd.args(["--vault", v]);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| {
            anyhow!(
                "1Password: could not run `op` — is the 1Password CLI installed and on PATH? ({e})"
            )
        })?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(template.as_bytes()).map_err(|e| {
                anyhow!("1Password: writing the item template to `op` failed ({e})")
            })?;
            drop(stdin); // EOF so `op` proceeds
        }
        let out = child
            .wait_with_output()
            .map_err(|e| anyhow!("1Password: waiting for `op` failed ({e})"))?;
        Ok(OpOutput {
            status: out.status.code(),
            stdout: Zeroizing::new(out.stdout),
            stderr: out.stderr,
        })
    }

    fn list_vaults(&self) -> Result<OpOutput> {
        use std::process::Command;
        let out = Command::new("op")
            .args(["vault", "list", "--format", "json"])
            .output()
            .map_err(|e| {
                anyhow!(
                    "1Password: could not run `op` — is the 1Password CLI installed and on PATH? ({e})"
                )
            })?;
        Ok(OpOutput {
            status: out.status.code(),
            stdout: Zeroizing::new(out.stdout),
            stderr: out.stderr,
        })
    }
}

// ─────────────────────────── mock runner (tests) ───────────────────────────

/// A scripted `op` runner for tests: returns configured [`OpOutput`]s in order
/// (a FIFO queue, so a multi-call path like ambiguity → get-by-id can be driven).
#[cfg(test)]
pub struct MockOpRunner {
    outputs: std::sync::Mutex<std::collections::VecDeque<OpOutput>>,
    launch_error: bool,
}

#[cfg(test)]
impl MockOpRunner {
    fn one(out: OpOutput) -> Self {
        let mut q = std::collections::VecDeque::new();
        q.push_back(out);
        Self {
            outputs: std::sync::Mutex::new(q),
            launch_error: false,
        }
    }
    /// A runner that returns a success (`exit 0`) with `stdout` as the value.
    pub fn ok(stdout: &str) -> Self {
        Self::one(OpOutput {
            status: Some(0),
            stdout: Zeroizing::new(stdout.as_bytes().to_vec()),
            stderr: Vec::new(),
        })
    }
    /// A runner returning a non-zero exit with the given stderr (a failure mode).
    pub fn failed(code: i32, stderr: &str) -> Self {
        Self::one(OpOutput {
            status: Some(code),
            stdout: Zeroizing::new(Vec::new()),
            stderr: stderr.as_bytes().to_vec(),
        })
    }
    /// A runner whose underlying `op` cannot be launched at all (CLI absent).
    pub fn launch_failure() -> Self {
        Self {
            outputs: std::sync::Mutex::new(std::collections::VecDeque::new()),
            launch_error: true,
        }
    }
    /// Enqueue a follow-up success output (for the second `get_item` call).
    pub fn then_ok(self, stdout: &str) -> Self {
        self.outputs.lock().unwrap().push_back(OpOutput {
            status: Some(0),
            stdout: Zeroizing::new(stdout.as_bytes().to_vec()),
            stderr: Vec::new(),
        });
        self
    }
}

#[cfg(test)]
impl OpRunner for MockOpRunner {
    fn read(&self, _reference: &str) -> Result<OpOutput> {
        self.take_output()
    }
    fn get_item(&self, _item: &str, _vault: Option<&str>) -> Result<OpOutput> {
        self.take_output()
    }
    fn list_items(&self) -> Result<OpOutput> {
        self.take_output()
    }
}

#[cfg(test)]
impl MockOpRunner {
    fn take_output(&self) -> Result<OpOutput> {
        if self.launch_error {
            return Err(anyhow!(
                "1Password: could not run `op` — is the 1Password CLI installed and on PATH? (mock)"
            ));
        }
        self.outputs
            .lock()
            .expect("mock mutex poisoned")
            .pop_front()
            .ok_or_else(|| anyhow!("mock runner already consumed"))
    }
}

/// A scripted `op` writer for tests: records what it was asked to store and
/// returns a configured [`OpOutput`].
#[cfg(test)]
pub struct MockOpWriter {
    output: std::sync::Mutex<Option<OpOutput>>,
    launch_error: bool,
    /// `(template, vault)` captured from the last `create_item` call.
    pub seen: std::sync::Mutex<Option<(String, Option<String>)>>,
    /// JSON returned by `list_vaults` (default `[]`).
    pub vaults_json: String,
}

#[cfg(test)]
impl MockOpWriter {
    pub fn ok(stdout: &str) -> Self {
        Self {
            output: std::sync::Mutex::new(Some(OpOutput {
                status: Some(0),
                stdout: Zeroizing::new(stdout.as_bytes().to_vec()),
                stderr: Vec::new(),
            })),
            launch_error: false,
            seen: std::sync::Mutex::new(None),
            vaults_json: "[]".to_string(),
        }
    }
    pub fn failed(code: i32, stderr: &str) -> Self {
        Self {
            output: std::sync::Mutex::new(Some(OpOutput {
                status: Some(code),
                stdout: Zeroizing::new(Vec::new()),
                stderr: stderr.as_bytes().to_vec(),
            })),
            launch_error: false,
            seen: std::sync::Mutex::new(None),
            vaults_json: "[]".to_string(),
        }
    }
    pub fn launch_failure() -> Self {
        Self {
            output: std::sync::Mutex::new(None),
            launch_error: true,
            seen: std::sync::Mutex::new(None),
            vaults_json: "[]".to_string(),
        }
    }
    /// Set the JSON `list_vaults` returns.
    pub fn with_vaults(mut self, json: &str) -> Self {
        self.vaults_json = json.to_string();
        self
    }
}

#[cfg(test)]
impl OpWriter for MockOpWriter {
    fn create_item(&self, template: &str, vault: Option<&str>) -> Result<OpOutput> {
        *self.seen.lock().unwrap() = Some((template.to_string(), vault.map(str::to_string)));
        if self.launch_error {
            return Err(anyhow!("1Password: could not run `op` (mock)"));
        }
        self.output
            .lock()
            .expect("mock mutex poisoned")
            .take()
            .ok_or_else(|| anyhow!("mock writer already consumed"))
    }

    fn list_vaults(&self) -> Result<OpOutput> {
        if self.launch_error {
            return Err(anyhow!("1Password: could not run `op` (mock)"));
        }
        Ok(OpOutput {
            status: Some(0),
            stdout: Zeroizing::new(self.vaults_json.as_bytes().to_vec()),
            stderr: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_op_references() {
        for bad in ["azure-kv://kv/x", "vault/item/field", "op://", "not-a-uri"] {
            assert!(validate_reference(bad).is_err(), "`{bad}` must be rejected");
        }
        assert!(validate_reference("op://Personal/db/password").is_ok());
    }

    #[test]
    fn reads_the_value_and_trims_one_newline() {
        let v = read_value(
            &MockOpRunner::ok("s3cr3t-value\n"),
            "op://Personal/db/password",
        )
        .unwrap();
        assert_eq!(&*v, b"s3cr3t-value");
    }

    #[test]
    fn empty_value_on_success_is_refused() {
        let err = read_value(&MockOpRunner::ok("\n"), "op://Personal/db/password").unwrap_err();
        assert!(format!("{err}").contains("empty value"));
    }

    #[test]
    fn op_missing_is_a_clear_error() {
        let err = read_value(&MockOpRunner::launch_failure(), "op://Personal/db/x").unwrap_err();
        assert!(format!("{err}").contains("op"));
    }

    #[test]
    fn not_signed_in_is_a_distinct_error() {
        let err = read_value(
            &MockOpRunner::failed(
                1,
                "[ERROR] you are not currently signed in. Please run `op signin`.",
            ),
            "op://Personal/db/x",
        )
        .unwrap_err();
        assert!(format!("{err}").contains("signed in"));
    }

    #[test]
    fn item_not_found_is_a_distinct_error() {
        let err = read_value(
            &MockOpRunner::failed(1, "[ERROR] \"db\" isn't an item in the \"Personal\" vault"),
            "op://Personal/db/password",
        )
        .unwrap_err();
        assert!(format!("{err}").contains("not found"));
    }

    // KOV-34 — store_backup_item builds a Password item whose JSON template
    // carries BOTH the recovery passphrase and the blob, and returns the ref.
    #[test]
    fn store_backup_item_builds_template_with_both_fields() {
        let w = MockOpWriter::ok("created item abc123\n");
        let r = store_backup_item(
            &w,
            "kovra vault backup",
            Some("Personal"),
            "GENPASS-xyz",
            "-----BEGIN AGE ENCRYPTED FILE-----\nblob\n-----END AGE ENCRYPTED FILE-----",
            "you also need your KOVRA_PASSPHRASE",
        )
        .unwrap();
        assert_eq!(r, "created item abc123");
        let (template, vault) = w.seen.lock().unwrap().clone().unwrap();
        assert_eq!(vault.as_deref(), Some("Personal"));
        // Valid JSON, PASSWORD category, both values present (escaped by serde).
        let v: serde_json::Value = serde_json::from_str(&template).unwrap();
        assert_eq!(v["category"], "PASSWORD");
        assert_eq!(v["title"], "kovra vault backup");
        assert!(template.contains("GENPASS-xyz"));
        assert!(template.contains("BEGIN AGE ENCRYPTED FILE"));
        assert!(template.contains("KOVRA_PASSPHRASE"));
    }

    const ITEM_JSON: &str = r#"{"id":"x","title":"K","fields":[
        {"id":"password","value":"GEN-PASS"},
        {"id":"age_backup","value":"-----BEGIN AGE...-----"},
        {"id":"notesPlain","value":"steps"}
    ]}"#;

    fn no_choice(_: &[OpItemCandidate]) -> Result<String> {
        panic!("choose must not be called when the name is unambiguous")
    }

    // KOV-34 — read_backup_item pulls the age_backup + password fields.
    #[test]
    fn read_backup_item_extracts_fields() {
        let (blob, pass) =
            read_backup_item(&MockOpRunner::ok(ITEM_JSON), "K", None, no_choice).unwrap();
        assert_eq!(&*blob, "-----BEGIN AGE...-----");
        assert_eq!(&*pass, "GEN-PASS");
    }

    const LIST_JSON: &str = r#"[
        {"id":"aaaa","title":"K","vault":{"name":"Kaeus"},"updated_at":"2026-06-01T09:00:00Z"},
        {"id":"bbbb","title":"K","vault":{"name":"Kaeus"},"updated_at":"2026-06-04T11:52:00Z"},
        {"id":"cccc","title":"Other","vault":{"name":"Kaeus"},"updated_at":"2026-06-04T11:52:00Z"}
    ]"#;

    // KOV-34 — on a duplicate name, candidates (with vault + date) are listed and
    // `choose` picks one by id; the chosen item is then fetched and parsed.
    #[test]
    fn read_backup_item_disambiguates_duplicates() {
        // get_item(name) → ambiguous; list_items → candidates; get_item(id) → item.
        let runner = MockOpRunner::failed(1, "[ERROR] More than one item matches \"K\".")
            .then_ok(LIST_JSON)
            .then_ok(ITEM_JSON);
        let (blob, _pass) = read_backup_item(&runner, "K", None, |cands| {
            assert_eq!(cands.len(), 2, "only the two items titled K");
            assert_eq!(cands[1].vault, "Kaeus");
            assert_eq!(cands[1].updated, "2026-06-04 11:52");
            Ok(cands[1].id.clone())
        })
        .unwrap();
        assert_eq!(&*blob, "-----BEGIN AGE...-----");
    }

    // KOV-34 — named_item_candidates filters by exact title and extracts the date.
    #[test]
    fn named_item_candidates_filters_and_dates() {
        let c = named_item_candidates(&MockOpRunner::ok(LIST_JSON), "K").unwrap();
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].id, "aaaa");
        assert_eq!(c[0].updated, "2026-06-01 09:00");
    }

    // KOV-34 — an item without the age_backup field is a clear, actionable error.
    #[test]
    fn read_backup_item_missing_field_errs() {
        let item = r#"{"fields":[{"id":"password","value":"p"}]}"#;
        let err = read_backup_item(&MockOpRunner::ok(item), "K", None, no_choice).unwrap_err();
        assert!(format!("{err}").contains("age backup"));
    }

    // KOV-34 — vault_names parses `op vault list --format json` to plain names.
    #[test]
    fn vault_names_parses_op_output() {
        let w = MockOpWriter::ok("ignored")
            .with_vaults(r#"[{"id":"a","name":"Private"},{"id":"b","name":"Shared"}]"#);
        assert_eq!(vault_names(&w).unwrap(), vec!["Private", "Shared"]);
    }

    // KOV-34 — not-signed-in maps to the actionable, non-echoing error.
    #[test]
    fn store_backup_item_not_signed_in() {
        let w = MockOpWriter::failed(1, "[ERROR] you are not currently signed in.");
        let err = store_backup_item(&w, "t", None, "p", "b", "n").unwrap_err();
        assert!(format!("{err}").contains("signed in"));
    }

    // KOV-34 — op absent is a clear launch error.
    #[test]
    fn store_backup_item_op_missing() {
        let err = store_backup_item(&MockOpWriter::launch_failure(), "t", None, "p", "b", "n")
            .unwrap_err();
        assert!(format!("{err}").contains("op"));
    }

    // KOV-34 / I12 — a write failure never echoes raw stderr verbatim.
    #[test]
    fn store_backup_item_failure_carries_no_raw_stderr() {
        let w = MockOpWriter::failed(2, "ERROR: opaque-write-internal-detail");
        let err = store_backup_item(&w, "t", None, "p", "b", "n").unwrap_err();
        assert!(!format!("{err}").contains("opaque-write-internal-detail"));
    }

    // I12 — a failure error never echoes raw stderr verbatim; only the coarse
    // classification + the (non-secret) reference.
    #[test]
    fn failure_error_carries_no_raw_stderr() {
        let err = read_value(
            &MockOpRunner::failed(2, "ERROR: some-opaque-internal-detail"),
            "op://Personal/db/x",
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("op://Personal/db/x"));
        assert!(!msg.contains("some-opaque-internal-detail"));
    }
}
