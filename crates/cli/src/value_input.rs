//! Reading a secret value **without ever putting it in `argv`** (I6).
//!
//! A create/update value enters via a hidden TTY prompt or via stdin (`--stdin`)
//! — never as a command-line argument (no `--value` flag exists), so it never
//! lands in shell history or `ps` output.

use std::io::{Read, Write};

use anyhow::{Context, Result, bail};
use kovra_core::SecretValue;
use zeroize::Zeroizing;

/// Read a secret value: from stdin when `from_stdin`, else a hidden prompt.
/// A trailing newline (from `echo`/pipes) is stripped; an empty value is rejected.
pub fn read_secret(prompt: &str, from_stdin: bool) -> Result<SecretValue> {
    let raw = if from_stdin {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .context("reading value from stdin")?;
        // Strip a single trailing newline (from `echo`/pipes); keep interior bytes.
        s.strip_suffix("\r\n")
            .or_else(|| s.strip_suffix('\n'))
            .unwrap_or(&s)
            .to_string()
    } else {
        rpassword::prompt_password(prompt).context("reading hidden value prompt")?
    };
    if raw.is_empty() {
        bail!("empty value rejected — a secret must be non-empty");
    }
    Ok(SecretValue::from(raw))
}

/// Read a **public** value (an OpenSSH public key for `add --public-key`). A
/// public key is not a secret, but it still enters via stdin or a visible prompt
/// rather than argv (I6 hygiene + consistency with `read_secret`). Returns the
/// raw text (caller trims/validates); an empty value is rejected.
pub fn read_public_text(prompt: &str, from_stdin: bool) -> Result<String> {
    let raw = if from_stdin {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .context("reading public key from stdin")?;
        s.trim().to_string()
    } else {
        eprint!("{prompt}");
        std::io::stderr().flush().ok();
        let mut s = String::new();
        std::io::stdin()
            .read_line(&mut s)
            .context("reading public key prompt")?;
        s.trim().to_string()
    };
    if raw.is_empty() {
        bail!("empty public key rejected");
    }
    Ok(raw)
}

/// Prompt (on stderr) for a line of visible text with a `default` shown in
/// brackets; an empty reply accepts the default. Used for the `--op` item name
/// (KOV-34). Not for secrets — those use [`read_secret`]/[`read_passphrase`].
pub fn prompt_with_default(label: &str, default: &str) -> Result<String> {
    eprint!("{label} [{default}]: ");
    std::io::stderr().flush().ok();
    let mut s = String::new();
    std::io::stdin()
        .read_line(&mut s)
        .context("reading prompt input")?;
    let t = s.trim();
    Ok(if t.is_empty() {
        default.to_string()
    } else {
        t.to_string()
    })
}

/// Read a passphrase from a hidden TTY prompt (KOV-34). `rpassword` reads the
/// terminal directly, so this works even when stdin is a piped backup blob. The
/// plaintext is wrapped in [`Zeroizing`] so it is wiped after use; empty is
/// rejected. Used by `kovra key import`.
pub fn read_passphrase(prompt: &str) -> Result<Zeroizing<String>> {
    let pass = rpassword::prompt_password(prompt).context("reading passphrase prompt")?;
    if pass.is_empty() {
        bail!("empty passphrase rejected");
    }
    Ok(Zeroizing::new(pass))
}

/// Read a **new** passphrase, asking twice and requiring a match — a typo must
/// not silently lock a disaster-recovery backup. Used by `kovra key export`.
pub fn read_new_passphrase(prompt: &str, confirm_prompt: &str) -> Result<Zeroizing<String>> {
    let first = read_passphrase(prompt)?;
    let second = Zeroizing::new(
        rpassword::prompt_password(confirm_prompt).context("reading passphrase confirmation")?,
    );
    if first.as_str() != second.as_str() {
        bail!("passphrases do not match — nothing was exported");
    }
    Ok(first)
}
