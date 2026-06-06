//! Shared CLI context: the registry root, the keyring backend, the clock, and
//! the audit sink.
//!
//! Backend selection (spec §10.2): the **OS keyring** by default; when
//! `KOVRA_PASSPHRASE` is set, the headless **Argon2** fallback (deterministic
//! from passphrase + a stored salt). `KOVRA_VAULT_DIR` overrides `~/.vaults`.
//! The passphrase mode is also what tests use, so they never touch the real
//! OS keychain.

use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use kovra_core::{
    Argon2Keyring, Clock, Confirmer, FileAuditSink, FileConfirmer, Formatter, Keyring, MasterKey,
    OsKeyring, Registry, SystemClock,
};
use kovra_native_macos::{BiometricConfirmer, DiskutilFormatter, biometrics_available};

/// Override for the registry root (default `~/.vaults`).
pub const VAULT_DIR_ENV: &str = "KOVRA_VAULT_DIR";
/// When set, use the Argon2 passphrase backend instead of the OS keyring.
pub const PASSPHRASE_ENV: &str = "KOVRA_PASSPHRASE";
/// Selects the confirmation channel for `high`/`prod` approvals (spec §8).
///
/// Values:
/// - `biometric` — native attended prompt (Touch ID on macOS).
/// - `file`      — the cross-process `kovra approve <id>` file broker.
///
/// Default: on macOS, `biometric` **with automatic fallback to `file`** when
/// biometrics is unavailable (no hardware / not enrolled). On non-macOS, always
/// `file`. An explicit value overrides the default (but `biometric` still falls
/// back to `file` if the host cannot actually prompt).
pub const CONFIRMER_ENV: &str = "KOVRA_CONFIRMER";
const SALT_FILE: &str = "kdf.salt";
const SALT_LEN: usize = 16;

/// The resolved CLI context.
pub struct Ctx {
    /// The registry root directory.
    pub root: PathBuf,
    /// The opened vault registry.
    pub registry: Registry,
    /// The system clock (audit timestamps).
    pub clock: SystemClock,
}

impl Ctx {
    /// Resolve the root, open the registry (creating `global/`, `projects/`).
    pub fn load() -> Result<Self> {
        let root = match env::var_os(VAULT_DIR_ENV) {
            Some(p) => PathBuf::from(p),
            None => Registry::default_root().context("locating ~/.vaults")?,
        };
        let registry = Registry::open(&root).context("opening the vault registry")?;
        Ok(Self {
            root,
            registry,
            clock: SystemClock,
        })
    }

    pub(crate) fn salt_path(&self) -> PathBuf {
        self.root.join(SALT_FILE)
    }

    /// Whether the Argon2 passphrase backend is in use.
    pub fn passphrase_mode(&self) -> bool {
        env::var_os(PASSPHRASE_ENV).is_some()
    }

    /// The keyring backend for this invocation.
    pub fn keyring(&self) -> Result<Box<dyn Keyring>> {
        if let Some(pass) = env::var_os(PASSPHRASE_ENV) {
            let salt = fs::read(self.salt_path())
                .with_context(|| format!("reading {SALT_FILE} (run `kovra init` first)"))?;
            let pass = pass
                .into_string()
                .map_err(|_| anyhow!("KOVRA_PASSPHRASE is not valid UTF-8"))?;
            Ok(Box::new(Argon2Keyring::new(pass.into_bytes(), salt)?))
        } else {
            Ok(Box::new(OsKeyring::new()))
        }
    }

    /// The confirmation broker for this invocation (spec §8), selected by
    /// [`CONFIRMER_ENV`].
    ///
    /// Selection logic:
    /// - `KOVRA_CONFIRMER=file` → always the file broker.
    /// - `KOVRA_CONFIRMER=biometric` → the native prompt **if** the host can
    ///   actually prompt ([`biometrics_available`]); otherwise fall back to file.
    /// - unset → default `biometric` (macOS), again falling back to file when
    ///   biometrics is unavailable; on non-macOS this is always file.
    ///
    /// Any unrecognized value falls back to the default. The biometric path is
    /// `[host]`; the file broker is what tests and Linux use.
    pub fn confirmer(&self) -> Box<dyn Confirmer + Send + Sync> {
        select_confirmer(&self.root)
    }

    /// The removable-media formatter for this host (KOV-40). The native
    /// `diskutil` impl is `[host]`; off-macOS it errors cleanly. The
    /// security rails + broker gate live in [`kovra_core::format_removable`].
    pub fn formatter(&self) -> Box<dyn Formatter> {
        select_formatter()
    }

    /// Obtain the master key via the selected backend.
    pub fn master_key(&self) -> Result<MasterKey> {
        self.keyring()?
            .get_master_key()
            .context("obtaining the master key (run `kovra init`?)")
    }

    /// The append-only audit sink at `<root>/audit.log`.
    pub fn audit(&self) -> FileAuditSink {
        FileAuditSink::under_root(&self.root)
    }

    /// An RFC-3339 timestamp from the system clock.
    pub fn now(&self) -> String {
        self.clock.now_rfc3339()
    }

    /// Create the KDF salt for passphrase mode (used by `init`). Returns `false`
    /// if a salt already exists and `force` is not set.
    pub fn ensure_salt(&self, force: bool) -> Result<bool> {
        let path = self.salt_path();
        if path.exists() && !force {
            return Ok(false);
        }
        let mut salt = [0u8; SALT_LEN];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut salt);
        fs::write(&path, salt).with_context(|| format!("writing {SALT_FILE}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).ok();
        }
        Ok(true)
    }

    /// Guard: a passphrase-mode write needs the salt to exist (i.e. `init` ran).
    pub fn require_initialized(&self) -> Result<()> {
        if self.passphrase_mode() && !self.salt_path().exists() {
            bail!("vault not initialized — run `kovra init` first");
        }
        Ok(())
    }
}

/// The native removable-media [`Formatter`] (KOV-40). `DiskutilFormatter` is the
/// only impl; off-macOS its methods error cleanly, so this is safe to construct
/// on any host (the CLI only reaches the format path on macOS via `exchange`).
pub fn select_formatter() -> Box<dyn Formatter> {
    Box::new(DiskutilFormatter::new())
}

/// Select the confirmation broker for a vault `root`, per [`CONFIRMER_ENV`]
/// (biometric on macOS with file fallback). Shared by [`Ctx::confirmer`] and the
/// ssh-agent `SessionProvider`, which holds only the root and rebuilds the
/// confirmer per signature.
pub fn select_confirmer(root: &std::path::Path) -> Box<dyn Confirmer + Send + Sync> {
    let file = || -> Box<dyn Confirmer + Send + Sync> { Box::new(FileConfirmer::under_root(root)) };
    match env::var(CONFIRMER_ENV).ok().as_deref() {
        Some("file") => file(),
        Some("biometric") => {
            if biometrics_available() {
                Box::new(BiometricConfirmer::new())
            } else {
                file()
            }
        }
        // Unset or unrecognized → default. Prefer biometric when the host can
        // prompt (macOS, enrolled); otherwise the file broker.
        _ => {
            if biometrics_available() {
                Box::new(BiometricConfirmer::new())
            } else {
                file()
            }
        }
    }
}
