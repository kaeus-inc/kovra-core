//! `kovra` command-line surface (spec §9.2). Definitions only; behavior lives in
//! [`crate::commands`].

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use kovra_core::{KeyAlgorithm, Scanner, Sensitivity};

/// `kovra` — local secrets manager for development.
#[derive(Parser)]
#[command(
    name = "kovra",
    version,
    about = "Local secrets manager for development"
)]
pub struct Cli {
    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Sensitivity as a CLI value (`--sensitivity high`); maps to [`Sensitivity`].
#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum SensitivityArg {
    /// Direct delivery + audit.
    Low,
    /// Direct delivery + audit + notification.
    Medium,
    /// Mandatory attended confirmation before delivery.
    High,
    /// Never revealed; injection only.
    InjectOnly,
}

impl From<SensitivityArg> for Sensitivity {
    fn from(a: SensitivityArg) -> Self {
        match a {
            SensitivityArg::Low => Sensitivity::Low,
            SensitivityArg::Medium => Sensitivity::Medium,
            SensitivityArg::High => Sensitivity::High,
            SensitivityArg::InjectOnly => Sensitivity::InjectOnly,
        }
    }
}

/// Key algorithm as a CLI value (`--type ed25519`); maps to [`KeyAlgorithm`].
#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum KeyAlgorithmArg {
    /// ed25519 (signing + encryption).
    Ed25519,
    /// RSA (signing/verify and SSH only — no encryption).
    Rsa,
}

impl From<KeyAlgorithmArg> for KeyAlgorithm {
    fn from(a: KeyAlgorithmArg) -> Self {
        match a {
            KeyAlgorithmArg::Ed25519 => KeyAlgorithm::Ed25519,
            KeyAlgorithmArg::Rsa => KeyAlgorithm::Rsa,
        }
    }
}

/// Secret scanner as a CLI value (`--scanner gitleaks`); maps to [`Scanner`].
#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum ScannerArg {
    /// gitleaks (default).
    Gitleaks,
    /// trufflehog.
    Trufflehog,
}

impl From<ScannerArg> for Scanner {
    fn from(a: ScannerArg) -> Self {
        match a {
            ScannerArg::Gitleaks => Scanner::Gitleaks,
            ScannerArg::Trufflehog => Scanner::Trufflehog,
        }
    }
}

/// `kovra hooks <action>` — manage git hooks that keep secrets out of commits.
#[derive(Subcommand)]
pub enum HooksAction {
    /// Install a pre-commit secret-scan hook into a repo's `.git/hooks`. The
    /// hook scans the staged diff and fails the commit on a finding (L12).
    Install {
        /// Repo root to install into (default: current directory).
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Secret scanner the hook invokes.
        #[arg(long, value_enum, default_value_t = ScannerArg::Gitleaks)]
        scanner: ScannerArg,
        /// Replace an existing pre-commit hook (a kovra-written hook is always
        /// replaced; this is needed only to overwrite a foreign one).
        #[arg(long)]
        force: bool,
    },
}

/// `kovra key` actions — disaster-recovery backup/restore of the master key
/// (KOV-34). The plaintext key never lands in a file; the backup is an encrypted,
/// ASCII-armored `age` blob protected by a recovery passphrase.
#[derive(Subcommand)]
pub enum KeyAction {
    /// Export the master key as an encrypted backup. Prompts for an attended
    /// confirmation (the key is the vault's root of trust) and a recovery
    /// passphrase (asked twice), then writes a standard armored `age` blob — to
    /// `--out <file>` (mode 0600) or stdout. The blob can be restored with
    /// `kovra key import`, or decrypted with any `age` implementation in a
    /// disaster.
    Export {
        /// Write the armored backup here (mode 0600).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Copy the armored backup to the OS clipboard (it is encrypted, so no
        /// plaintext key is exposed) — handy for pasting into a password manager.
        #[arg(long)]
        clipboard: bool,
        /// Store the backup directly in 1Password via the `op` CLI (`[host]`:
        /// requires `op` installed and signed in). kovra **generates** the
        /// recovery passphrase and saves it together with the encrypted backup in
        /// one item — nothing to type or remember. Combinable with `--out`.
        #[arg(long)]
        op: bool,
        /// 1Password vault for `--op` (skips the interactive vault picker).
        #[arg(long)]
        op_vault: Option<String>,
        /// Item name for `--op` (skips the interactive name prompt).
        #[arg(long)]
        op_title: Option<String>,
    },
    /// Restore the master key from a `kovra key export` backup into the OS
    /// keyring. Reads the blob from `<file>` (or stdin), prompts for the recovery
    /// passphrase, and stores the key. Only applies to OS-keyring vaults; in
    /// passphrase mode the backup is your passphrase + `kdf.salt`.
    Import {
        /// Read the armored backup from here (default: stdin).
        file: Option<PathBuf>,
        /// Overwrite an existing master key already in the keyring.
        #[arg(long)]
        force: bool,
        /// Restore directly from a 1Password item created by `key export --op`,
        /// by its name or id (`[host]`: requires `op` signed in). Reads both the
        /// encrypted backup and the recovery passphrase from the item — no files,
        /// no prompts.
        #[arg(long, value_name = "ITEM")]
        op: Option<String>,
        /// 1Password vault to look in for `--op` (disambiguates same-named items).
        #[arg(long)]
        op_vault: Option<String>,
    },
}

/// `kovra exchange <action>` — the USB offline-exchange kit (§7.3, KOV-39→44,
/// macOS only). One Touch-ID-gated flow to hand a non-prod secret set to another
/// machine over a USB stick, with the access token delivered out-of-band.
#[derive(Subcommand)]
pub enum ExchangeAction {
    /// Build the bootstrap USB on the **origin**: format a removable device
    /// (broker-gated, KOV-40), drop the `kovra` binary, and write `install.sh`
    /// (the destination installs kovra, makes a portable passphrase vault,
    /// `keygen`s its recipient identity, and writes `recipient.pub` back).
    /// macOS only; the device is **erased** — only removable external media is
    /// accepted (a fixed/internal/boot disk is refused outright).
    Init {
        /// The device node to format, e.g. `/dev/disk4`. **Omit it** to pick
        /// interactively from the eligible external/removable devices. It will
        /// be ERASED.
        #[arg(long)]
        device: Option<String>,
    },
    /// Seal an env's secrets to the destination on the **origin**: read
    /// `recipient.pub` from the USB, package the scope (`prod` refused, I4a),
    /// write `package.kovra` + `unpack.sh` to the USB, and print the access token
    /// to **stdout** — deliver it over a SEPARATE channel (never on the USB, §7.2).
    Seal {
        /// Environment to seal (e.g. `dev`/`staging`). Never `prod` (I4a).
        #[arg(long)]
        env: String,
        /// Restrict to these components (repeatable). Omit to take the whole env.
        #[arg(long)]
        component: Vec<String>,
        /// Seconds until the package (and its token) expire. Default 24h.
        #[arg(long, default_value_t = 86_400)]
        ttl: u64,
        /// The mounted USB path (default the exchange volume `/Volumes/KOVRA`).
        #[arg(long, default_value = "/Volumes/KOVRA")]
        usb: PathBuf,
        /// Seal from this project vault instead of the global vault.
        #[arg(long)]
        project: Option<String>,
    },
    /// Register the out-of-band access token on the **destination** so `open` is
    /// a single action. Reads the token from `--from <file>` or stdin (never
    /// argv — it is a bearer credential) and stores it owner-only under the vault.
    RegisterToken {
        /// Read the token from this file instead of stdin.
        #[arg(long)]
        from: Option<PathBuf>,
    },
    /// Destination one-action import: open `package.kovra` from the USB with your
    /// custodied recipient identity (KOV-39), using the registered token (or
    /// `--token`) for `high` entries. Prompts the vault passphrase.
    Open {
        /// The mounted USB path (default the exchange volume `/Volumes/KOVRA`).
        #[arg(long, default_value = "/Volumes/KOVRA")]
        usb: PathBuf,
        /// Use this token file instead of the registered one.
        #[arg(long)]
        token: Option<PathBuf>,
        /// Import into this project vault instead of the global vault.
        #[arg(long)]
        project: Option<String>,
        /// Overwrite coordinates that already exist in the target vault.
        #[arg(long)]
        force: bool,
    },
}

/// The `kovra` subcommands (MVP subset, KOV-7; asymmetric keys, KOV-12).
#[derive(Subcommand)]
pub enum Command {
    /// Initialize the vault registry and master key.
    Init {
        /// Re-initialize even if a key/salt already exists.
        #[arg(long)]
        force: bool,
    },
    /// Onboard the current repo: ensure the vault, register the kovra MCP
    /// server in `./.mcp.json`, and insert the conventions block in `./CLAUDE.md`.
    Setup {
        /// Project vault name (default: the current directory's name).
        #[arg(long)]
        project: Option<String>,
        /// The command that launches the MCP server (default: `kovra-mcp`).
        #[arg(long, default_value = "kovra-mcp")]
        mcp_command: String,
        /// Show what would change without writing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Create a secret (value via hidden prompt or `--stdin`; never argv, I6).
    Add {
        /// Coordinate, e.g. `secret:dev/db/password`.
        coordinate: String,
        /// Read the value from stdin instead of a hidden prompt.
        #[arg(long)]
        stdin: bool,
        /// Sensitivity (prod is forced to `high` at birth, I5).
        #[arg(long, value_enum)]
        sensitivity: Option<SensitivityArg>,
        /// Optional human description.
        #[arg(long)]
        description: Option<String>,
        /// Make this a reference secret with the given provider URI (no value).
        #[arg(long)]
        reference: Option<String>,
        /// Store a public-only keypair entry (KOV-12): the OpenSSH public key of
        /// a peer/recipient (read from stdin or a hidden prompt — never argv).
        /// Holds no private half; used for `encrypt`/`verify`. Mutually exclusive
        /// with `--reference`.
        #[arg(long)]
        public_key: bool,
        /// Store a TOTP enrollment (KOV-11): custody a TOTP **seed** read from
        /// stdin or a hidden prompt (a base32 seed or a full `otpauth://` URI) —
        /// never argv (I6). The seed is never revealed; produce codes on demand
        /// with `kovra code`. Mutually exclusive with `--reference`/`--public-key`.
        #[arg(long)]
        totp: bool,
        /// Opt the secret into agent-side reveal (only ever honored for
        /// non-prod, non-high secrets over MCP — I11). Off by default.
        #[arg(long)]
        revealable: bool,
        /// Target a project vault instead of the global vault.
        #[arg(long)]
        project: Option<String>,
    },
    /// Update a secret's value (hidden prompt or `--stdin`).
    Set {
        /// Coordinate to update.
        coordinate: String,
        /// Read the value from stdin instead of a hidden prompt.
        #[arg(long)]
        stdin: bool,
        /// Target a project vault instead of the global vault.
        #[arg(long)]
        project: Option<String>,
    },
    /// Edit a secret's metadata (sensitivity / description / reference pointer).
    Edit {
        /// Coordinate to edit.
        coordinate: String,
        /// New sensitivity (lowering is an audited downgrade, I5).
        #[arg(long, value_enum)]
        sensitivity: Option<SensitivityArg>,
        /// New description.
        #[arg(long)]
        description: Option<String>,
        /// New reference pointer (only for reference secrets).
        #[arg(long)]
        reference: Option<String>,
        /// Set/clear the reveal opt-in (`--revealable true|false`). Omit to keep
        /// the current value. Only ever honored for non-prod, non-high (I11).
        #[arg(long)]
        revealable: Option<bool>,
        /// Target a project vault instead of the global vault.
        #[arg(long)]
        project: Option<String>,
    },
    /// Delete a secret.
    Rm {
        /// Coordinate to delete.
        coordinate: String,
        /// Target a project vault instead of the global vault.
        #[arg(long)]
        project: Option<String>,
    },
    /// List secrets (metadata only — never values).
    List {
        /// Filter by environment.
        #[arg(long)]
        env: Option<String>,
        /// Filter by component.
        #[arg(long)]
        component: Option<String>,
        /// List only this project vault (else global + all projects).
        #[arg(long)]
        project: Option<String>,
    },
    /// Reveal a secret value to stdout (one coordinate; high requires approval).
    Show {
        /// Coordinate to reveal.
        coordinate: String,
        /// Resolve within this project vault (project overrides global).
        #[arg(long)]
        project: Option<String>,
    },
    /// Print the current RFC-6238 TOTP code for a TOTP enrollment (KOV-11). The
    /// derived code is printed — never the seed. Broker-gated for high/prod like
    /// a reveal (I3/I15), audited (I12); low/medium print directly.
    Code {
        /// Coordinate of the TOTP enrollment.
        coordinate: String,
        /// Resolve within this project vault (project overrides global).
        #[arg(long)]
        project: Option<String>,
        /// Scripting mode: guarantee the returned code has MORE than this many
        /// seconds of validity. Forces non-interactive output (the bare code +
        /// newline to stdout — no countdown UI, even on a TTY). If the current
        /// window has more than N seconds left it is returned immediately; else
        /// `kovra` waits for the window to roll over and returns the next code.
        #[arg(long, short = 'm', value_name = "SECONDS")]
        min_validity: Option<u64>,
    },
    /// Generate a random value, stored directly and never printed.
    Generate {
        /// Coordinate to create.
        coordinate: String,
        /// Number of characters to generate.
        #[arg(long, default_value_t = 32)]
        length: usize,
        /// Sensitivity (prod is forced to `high` at birth, I5).
        #[arg(long, value_enum)]
        sensitivity: Option<SensitivityArg>,
        /// Optional human description.
        #[arg(long)]
        description: Option<String>,
        /// Target a project vault instead of the global vault.
        #[arg(long)]
        project: Option<String>,
    },
    /// Resolve an `.env.refs` and run a command with the values injected.
    Run {
        /// Environment to resolve `${ENV}` against.
        #[arg(long)]
        env: String,
        /// Path to the `.env.refs` (default `./.env.refs`).
        #[arg(long)]
        refs: Option<PathBuf>,
        /// Project vault override (wins over the `project =` line).
        #[arg(long)]
        project: Option<String>,
        /// Add an executable to the allowlist for this run (repeatable).
        #[arg(long = "allow")]
        allow: Vec<PathBuf>,
        /// The command and its arguments, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Approve or deny a pending confirmation request from another session.
    Approve {
        /// List pending requests instead of resolving one.
        #[arg(long)]
        list: bool,
        /// Deny instead of approve.
        #[arg(long)]
        deny: bool,
        /// The request id to resolve.
        id: Option<String>,
    },
    /// Request an attended human confirmation for an action, gated by Touch ID
    /// (KOV-31). Opens the same broker as the rest of the CLI (biometric on
    /// macOS via `KOVRA_CONFIRMER`, `kovra approve` file-broker fallback) showing
    /// `<description>` as the authoritative prompt, and **exits 0 if approved**,
    /// non-zero if denied or timed out. Secret-independent: needs no vault/master
    /// key — a trusted app/host shells out and checks the exit code to gate its
    /// own action. The description is trusted caller text; do not feed it
    /// untrusted/LLM input.
    Confirm {
        /// What the human is approving — shown verbatim as the prompt headline.
        description: String,
        /// Seconds to wait for the human before failing safe to denial.
        #[arg(long, default_value_t = 120)]
        ttl: u64,
    },
    /// Generate an asymmetric keypair and custody it (KOV-12). The private half
    /// is sealed and never printed or written to disk (I7); the public key is
    /// shown.
    Keygen {
        /// Coordinate to create, e.g. `secret:dev/ssh/deploy`.
        coordinate: String,
        /// Key algorithm.
        #[arg(long = "type", value_enum, default_value_t = KeyAlgorithmArg::Ed25519)]
        algorithm: KeyAlgorithmArg,
        /// Sensitivity (prod is forced to `high` at birth, I5).
        #[arg(long, value_enum)]
        sensitivity: Option<SensitivityArg>,
        /// Optional human description.
        #[arg(long)]
        description: Option<String>,
        /// Target a project vault instead of the global vault.
        #[arg(long)]
        project: Option<String>,
    },
    /// Print the OpenSSH public key of a keypair (free — no confirmation).
    Pubkey {
        /// Coordinate of the keypair.
        coordinate: String,
        /// Resolve within this project vault (project overrides global).
        #[arg(long)]
        project: Option<String>,
    },
    /// Load a keypair's private key into the running ssh-agent, in memory only —
    /// never written to `~/.ssh` (I7). Broker-gated for high/prod (I3/I15).
    SshAdd {
        /// Coordinate of the keypair.
        coordinate: String,
        /// Resolve within this project vault (project overrides global).
        #[arg(long)]
        project: Option<String>,
    },
    /// Run kovra as a governed ssh-agent (KOV-13): listen on a UNIX socket,
    /// speak the ssh-agent protocol, and sign each challenge in memory with a
    /// custodied keypair — the private key never leaves kovra / never hits disk
    /// (I7). `high`/`prod` keys confirm on every signature (I3/I15) and are
    /// audited (I12); `low`/`medium` sign silently. Scope (I13) comes from
    /// `<vault-root>/agent.toml`. Foreground only: prints the `SSH_AUTH_SOCK` to
    /// export and serves until Ctrl-C. Refuses to start if `$SSH_AUTH_SOCK` is
    /// already set (it never hijacks another agent).
    ///
    /// Honest limit (spec §16): this governs the authentication event, not the
    /// SSH session that opens after it.
    SshAgent {
        /// Override the socket path (default `<vault-root>/agent.sock`).
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Sign data with a keypair's private key (broker-gated for high/prod). Data
    /// from a file or stdin (`-`); the signature is written to stdout.
    Sign {
        /// Coordinate of the keypair.
        coordinate: String,
        /// Input file, or `-` for stdin (default: stdin).
        #[arg(default_value = "-")]
        input: String,
        /// Resolve within this project vault.
        #[arg(long)]
        project: Option<String>,
    },
    /// Verify a signature against a keypair's (or public-only entry's) public key
    /// (free — no confirmation).
    Verify {
        /// Coordinate of the keypair / public-key entry.
        coordinate: String,
        /// File containing the signature produced by `kovra sign`.
        #[arg(long)]
        signature: PathBuf,
        /// Input file, or `-` for stdin (default: stdin).
        #[arg(default_value = "-")]
        input: String,
        /// Resolve within this project vault.
        #[arg(long)]
        project: Option<String>,
    },
    /// Encrypt data *to* a keypair's public key (ed25519 only; free — no
    /// confirmation). Data from a file or stdin (`-`); ciphertext to stdout.
    Encrypt {
        /// Coordinate of the recipient keypair / public-key entry.
        coordinate: String,
        /// Input file, or `-` for stdin (default: stdin).
        #[arg(default_value = "-")]
        input: String,
        /// Resolve within this project vault.
        #[arg(long)]
        project: Option<String>,
    },
    /// Decrypt data *with* a keypair's private key (ed25519 only; broker-gated
    /// for high/prod). Ciphertext from a file or stdin (`-`); plaintext to stdout.
    Decrypt {
        /// Coordinate of the keypair.
        coordinate: String,
        /// Input file, or `-` for stdin (default: stdin).
        #[arg(default_value = "-")]
        input: String,
        /// Resolve within this project vault.
        #[arg(long)]
        project: Option<String>,
    },
    /// Scan a repo's source for env-var references and PROPOSE an `.env.refs`
    /// (L12 accelerator). Reads only source for variable *names* — never a value
    /// (no `.env*` file is read). Prints the proposal to stdout by default.
    Scaffold {
        /// Repo root to scan (default: current directory).
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Write the proposal to this file instead of stdout. Refuses to
        /// overwrite an existing file unless `--force`.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Overwrite the `--out` file if it already exists.
        #[arg(long)]
        force: bool,
    },
    /// Validate a project's secret config (L12 accelerator): every `.env.refs`
    /// coordinate resolves, no orphan vault entries, no `prod` fallback, and
    /// references are reported by status. Coordinates + status only — never a
    /// value (I11/I12). Exits non-zero on any hard finding. Alias: `lint`.
    #[command(alias = "lint")]
    Doctor {
        /// Environment to resolve `${ENV}` against.
        #[arg(long, default_value = "dev")]
        env: String,
        /// Path to the `.env.refs` (default `./.env.refs`).
        #[arg(long)]
        refs: Option<PathBuf>,
        /// Project vault override (wins over the `project =` line).
        #[arg(long)]
        project: Option<String>,
    },
    /// Manage git hooks that keep secrets out of commits (L12 accelerator).
    Hooks {
        /// The hooks action to run.
        #[command(subcommand)]
        action: HooksAction,
    },
    /// Back up / restore the vault master key (disaster recovery, KOV-34).
    Key {
        /// The key action to run.
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Import a credential from 1Password into the vault as a literal (KOV-24).
    /// Reads the value once via the `op` CLI (`op read`) and seals it — a copy,
    /// not a reference; no relationship to 1Password is kept. The value never
    /// touches argv (only the `op://` address does, I6) and is never printed
    /// (I12); `prod` is born `high` (I5). Requires the `op` CLI signed in.
    Import {
        /// Coordinate to create, e.g. `secret:dev/db/password`.
        coordinate: String,
        /// The 1Password secret reference, e.g. `op://Personal/db/password`.
        #[arg(long)]
        from: String,
        /// Sensitivity (prod is forced to `high` at birth, I5).
        #[arg(long, value_enum)]
        sensitivity: Option<SensitivityArg>,
        /// Optional human description.
        #[arg(long)]
        description: Option<String>,
        /// Opt the secret into agent-side reveal (non-prod, non-high only — I11).
        #[arg(long)]
        revealable: bool,
        /// Target a project vault instead of the global vault.
        #[arg(long)]
        project: Option<String>,
    },
    /// Bring up the on-demand loopback Web UI for administration (L10, §9.3).
    /// Binds `127.0.0.1` only (I10), mints an ephemeral session token, opens the
    /// browser, and shuts down on Ctrl-C or after inactivity. The UI never
    /// renders `high`/`inject-only` plaintext (I1/I2) — those reveal via the CLI.
    Ui {
        /// Loopback port (default 8731).
        #[arg(long, default_value_t = kovra_webui::DEFAULT_PORT)]
        port: u16,
        /// Idle seconds before auto-shutdown (default 300).
        #[arg(long, default_value_t = 300)]
        idle: u64,
        /// Do not try to open a browser (just print the URL).
        #[arg(long)]
        no_open: bool,
        /// Run the Web UI in Docker (L11): master key via a Docker secret in
        /// tmpfs (I9), `~/.vaults` rw-mounted, loopback publish (I10). `[host]` —
        /// requires Docker on the host.
        #[arg(long)]
        docker: bool,
        /// Skip the attended launch confirmation (KOV-30). By default opening the
        /// admin UI requires approval (Touch ID / `kovra approve`); this bypasses
        /// it for dev/CI/Docker. Also settable via `KOVRA_UI_NO_CONFIRM`.
        #[arg(long, env = "KOVRA_UI_NO_CONFIRM")]
        no_confirm: bool,
    },
    /// Seal a bundle of non-prod secrets into an encrypted package for a peer
    /// (L7, §7). Enumerates the vault by `--env` (+ optional `--component`),
    /// seals every matching record to the recipient's ed25519 public key, and
    /// writes the package plus a separate access token (the token authorizes
    /// unattended consumption — deliver it over a different channel). A `prod`
    /// secret is refused (I4a); references travel as pointers, never resolved
    /// (I8). Values never touch argv (I6) and are never printed (I12).
    Package {
        /// Environment to package (e.g. `dev`/`staging`). Never `prod` (I4a).
        #[arg(long)]
        env: String,
        /// Restrict to these components (repeatable). Omit to take the whole env.
        #[arg(long)]
        component: Vec<String>,
        /// File holding the recipient's OpenSSH **ed25519** public key, or `-`
        /// to read it from stdin. The public key is not a secret.
        #[arg(long)]
        recipient: String,
        /// Seconds until the package (and its token) expire. Default 24h.
        #[arg(long, default_value_t = 86_400)]
        ttl: u64,
        /// Where to write the sealed package.
        #[arg(long)]
        out: PathBuf,
        /// Where to write the access token (the second-channel credential).
        #[arg(long = "token-out")]
        token_out: PathBuf,
        /// Package from this project vault instead of the global vault.
        #[arg(long)]
        project: Option<String>,
    },
    /// Open an encrypted package and import its secrets into the local vault
    /// (L7, §7). Decrypts with the recipient's ed25519 private key (from
    /// `--identity-file` or `KOVRA_RECIPIENT_KEY` — never argv, I6). With
    /// `--token`, `high` entries are delivered unattended (audited); without it,
    /// each `high` entry requires an attended approval. Reference pointers are
    /// imported as-is and materialized later by your own provider identity (I8).
    Unpack {
        /// The sealed package file to open.
        #[arg(long)]
        r#in: PathBuf,
        /// File holding your OpenSSH **ed25519** private key. If omitted, the key
        /// is read from the `KOVRA_RECIPIENT_KEY` environment variable (never
        /// argv, I6).
        #[arg(long = "identity-file")]
        identity_file: Option<PathBuf>,
        /// Coordinate of a **custodied** keypair in the vault to open the package
        /// with. The private key is loaded under the master key and used only in
        /// memory — it never leaves kovra (I7) and `high` keystones are
        /// broker-gated like `decrypt` (I3/I15). Mutually exclusive with
        /// `--identity-file`.
        #[arg(long, conflicts_with = "identity_file")]
        identity: Option<String>,
        /// The access token file (enables unattended delivery of `high` entries).
        #[arg(long)]
        token: Option<PathBuf>,
        /// Import into this project vault instead of the global vault.
        #[arg(long)]
        project: Option<String>,
        /// Overwrite coordinates that already exist in the target vault.
        #[arg(long)]
        force: bool,
    },
    /// USB offline-exchange kit (§7.3, KOV-39→44; macOS only): build a bootstrap
    /// USB, seal a package to it, and open it on the destination in one action.
    Exchange {
        #[command(subcommand)]
        action: ExchangeAction,
    },
    /// Query the audit trail (L12 accelerator): access/operation history, backed
    /// by the per-vault redb metadata index for sensitivity. Coordinates,
    /// truncated fingerprints, sensitivity, timestamps, and origin only — never a
    /// value, never a full fingerprint (I11/I12).
    Audit {
        /// Filter to an exact coordinate (`env/component/key`).
        #[arg(long)]
        coordinate: Option<String>,
        /// Filter by environment.
        #[arg(long)]
        env: Option<String>,
        /// Filter by component (the middle coordinate segment).
        #[arg(long)]
        component: Option<String>,
        /// Only events at/after this RFC-3339 instant (e.g. `2026-06-01T00:00:00Z`).
        #[arg(long)]
        since: Option<String>,
        /// Only events at/before this RFC-3339 instant.
        #[arg(long)]
        until: Option<String>,
        /// Only this action (e.g. `reveal`, `inject`, `provider-invocation`).
        #[arg(long)]
        action: Option<String>,
    },
}
