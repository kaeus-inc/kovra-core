//! USB offline-exchange kit (KOV-41/42/43, §7.3) — the on-USB file/script
//! contract plus the *pure* builders that generate it. The OS-touching pieces
//! (formatting the stick, discovering its mount point) live at the CLI edge
//! behind the [`Formatter`](crate::Formatter) trait; everything here is
//! deterministic and unit-tested.
//!
//! ## On-USB layout (the contract)
//!
//! ```text
//! <USB>/
//!   kovra            the macOS binary (origin drops it; destination installs it)
//!   install.sh       destination bootstrap (install + passphrase vault + keygen)
//!   recipient.pub    destination writes its OpenSSH public key here (handed back)
//!   package.kovra    origin seals the package here (exchange seal, KOV-42)
//!   unpack.sh        origin writes the destination open helper here (KOV-42/43)
//! ```
//!
//! The access **token** is never written to the USB — it travels out-of-band
//! (a second channel), per §7.2.

use std::path::{Path, PathBuf};

use crate::error::CoreError;

/// The bundled binary's name on the USB.
pub const BINARY_NAME: &str = "kovra";
/// Destination bootstrap script.
pub const INSTALL_SCRIPT: &str = "install.sh";
/// Destination open helper (written by `exchange seal`).
pub const UNPACK_SCRIPT: &str = "unpack.sh";
/// Where the destination writes its OpenSSH public key for the origin to seal to.
pub const RECIPIENT_PUB: &str = "recipient.pub";
/// The sealed package the origin writes for the destination.
pub const PACKAGE_FILE: &str = "package.kovra";

/// The custodied recipient identity coordinate. Fixed so all three steps agree:
/// the destination `keygen`s it (install.sh), the origin seals to its public
/// half (`exchange seal`), and the destination opens with it
/// (`unpack --identity`, KOV-39).
pub const RECIPIENT_COORDINATE: &str = "secret:exchange/recipient/key";

/// The ExFAT volume label kovra gives the bootstrap USB. Fixed (uppercase,
/// FAT-safe) so the mount point is predictable on the destination.
pub const VOLUME_LABEL: &str = "KOVRA";

/// The macOS mount point of a freshly-formatted exchange USB (`/Volumes/KOVRA`).
/// `[host]` path convention; used by `exchange init`/`open` to populate/read the
/// stick after a format.
#[must_use]
pub fn mount_point() -> PathBuf {
    Path::new("/Volumes").join(VOLUME_LABEL)
}

/// The destination bootstrap script (`install.sh`). Run from the USB on the
/// destination Mac, it: installs the bundled `kovra`, clears the macOS
/// quarantine flag on the unsigned binary, creates a **portable passphrase
/// vault** (no OS keychain / Touch ID dependency), generates the recipient
/// keypair, and writes `recipient.pub` back to the USB for the origin to seal
/// against. Pure — no secret material is embedded (the passphrase is prompted on
/// the destination, never travels).
#[must_use]
pub fn render_install_script() -> String {
    format!(
        r##"#!/usr/bin/env bash
# kovra offline-exchange — destination bootstrap (origin-generated).
#
# Installs kovra from this USB, creates a PORTABLE passphrase vault (no Touch ID
# needed), generates your recipient keypair, and writes {pub} back to this USB so
# the sender can seal a package to you. The access token arrives separately (a
# second channel) — never on this USB.
#
#   Run it from the USB:   ./{install}
set -euo pipefail

HERE="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
BIN_DIR="${{KOVRA_BIN_DIR:-$HOME/.local/bin}}"
mkdir -p "$BIN_DIR"
cp "$HERE/{binary}" "$BIN_DIR/{binary}"
chmod +x "$BIN_DIR/{binary}"
# Clear the macOS quarantine flag on the bundled (unsigned) binary.
xattr -d com.apple.quarantine "$BIN_DIR/{binary}" 2>/dev/null || true
export PATH="$BIN_DIR:$PATH"

# A portable vault keyed by a passphrase — no OS keychain, works on any Mac.
if [ -z "${{KOVRA_PASSPHRASE:-}}" ]; then
  printf 'Choose a vault passphrase (you will need it to open the package): '
  read -r -s KOVRA_PASSPHRASE; printf '\n'
  export KOVRA_PASSPHRASE
fi

kovra init
kovra keygen '{coord}' --type ed25519 --sensitivity high \
  --description 'kovra offline-exchange recipient identity'
kovra pubkey '{coord}' > "$HERE/{pub}"

echo
echo "{pub} written to the USB. Hand the USB back to the sender so they can run"
echo "'kovra exchange seal'. Keep your passphrase — you'll need it to open the package."
"##,
        binary = BINARY_NAME,
        install = INSTALL_SCRIPT,
        pub = RECIPIENT_PUB,
        coord = RECIPIENT_COORDINATE,
    )
}

/// The destination **open** helper (`unpack.sh`), written to the USB by
/// `exchange seal`. Run on the destination, it opens `package.kovra` with the
/// custodied recipient identity (KOV-39) and imports the secrets, prompting for
/// the vault passphrase. For `high` entries the access token (the second
/// channel) is supplied via `KOVRA_EXCHANGE_TOKEN` and written to a temp file
/// **outside** the USB (deleted on exit) — the token never lands on the stick.
/// Pure; embeds no secret.
#[must_use]
pub fn render_unpack_script() -> String {
    format!(
        r##"#!/usr/bin/env bash
# kovra offline-exchange — destination OPEN helper (origin-generated).
#
# Opens {package} on this USB with your custodied recipient identity and imports
# the secrets. You'll be asked for your vault passphrase. For `high` entries,
# supply the access token the sender sent over a SEPARATE channel:
#   export KOVRA_EXCHANGE_TOKEN=...   (or use `kovra exchange open`)
set -euo pipefail

HERE="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
if [ -z "${{KOVRA_PASSPHRASE:-}}" ]; then
  printf 'Vault passphrase: '
  read -r -s KOVRA_PASSPHRASE; printf '\n'
  export KOVRA_PASSPHRASE
fi

args=(unpack --in "$HERE/{package}" --identity '{coord}')
if [ -n "${{KOVRA_EXCHANGE_TOKEN:-}}" ]; then
  # Land the token in a temp file OFF the USB; never written to the stick.
  tok="$(mktemp -t kovra-token)"
  trap 'rm -f "$tok"' EXIT
  printf '%s' "$KOVRA_EXCHANGE_TOKEN" > "$tok"
  args+=(--token "$tok")
fi

kovra "${{args[@]}}"
echo "Imported. The secrets now live in your local vault."
"##,
        package = PACKAGE_FILE,
        coord = RECIPIENT_COORDINATE,
    )
}

/// Populate a freshly-formatted USB (mounted at `dest`) with the bootstrap kit:
/// copy the `kovra` binary and write an executable `install.sh`. OS-agnostic
/// (plain file I/O), so it is unit-tested against a temp dir — the *format* that
/// precedes it is the `[host]` step.
pub fn write_bootstrap(
    dest: &Path,
    kovra_binary: &Path,
    install_script: &str,
) -> Result<(), CoreError> {
    std::fs::create_dir_all(dest)
        .map_err(|e| CoreError::Io(format!("creating {}: {e}", dest.display())))?;

    let bin_dst = dest.join(BINARY_NAME);
    std::fs::copy(kovra_binary, &bin_dst).map_err(|e| {
        CoreError::Io(format!(
            "copying {} to {}: {e}",
            kovra_binary.display(),
            bin_dst.display()
        ))
    })?;
    make_executable(&bin_dst)?;

    let script_dst = dest.join(INSTALL_SCRIPT);
    std::fs::write(&script_dst, install_script)
        .map_err(|e| CoreError::Io(format!("writing {}: {e}", script_dst.display())))?;
    make_executable(&script_dst)?;

    Ok(())
}

/// `chmod +x` (0755) on Unix; a no-op elsewhere.
fn make_executable(path: &Path) -> Result<(), CoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| CoreError::Io(format!("chmod +x {}: {e}", path.display())))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_script_drives_the_destination_bootstrap() {
        let s = render_install_script();
        assert!(s.starts_with("#!/usr/bin/env bash"), "has a shebang");
        assert!(s.contains("set -euo pipefail"), "fails fast");
        // Installs the bundled binary and clears quarantine.
        assert!(s.contains(&format!("cp \"$HERE/{BINARY_NAME}\"")));
        assert!(s.contains("com.apple.quarantine"));
        // Portable passphrase vault (no Touch ID), prompted not embedded.
        assert!(s.contains("KOVRA_PASSPHRASE"));
        assert!(s.contains("kovra init"));
        // Generates the agreed recipient identity and writes the pubkey to the USB.
        assert!(s.contains(RECIPIENT_COORDINATE));
        assert!(s.contains(&format!("\"$HERE/{RECIPIENT_PUB}\"")));
        // No secret material is embedded in the generated script.
        assert!(!s.to_lowercase().contains("private key"));
    }

    #[test]
    fn write_bootstrap_copies_binary_and_writes_executable_script() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("KOVRA");
        let fake_bin = tmp.path().join("kovra-bin");
        std::fs::write(&fake_bin, b"#!/bin/sh\necho kovra\n").unwrap();

        write_bootstrap(&dest, &fake_bin, &render_install_script()).unwrap();

        let bin = dest.join(BINARY_NAME);
        let script = dest.join(INSTALL_SCRIPT);
        assert!(bin.exists() && script.exists());
        assert_eq!(std::fs::read(&bin).unwrap(), b"#!/bin/sh\necho kovra\n");
        assert!(
            std::fs::read_to_string(&script)
                .unwrap()
                .contains("kovra keygen")
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for p in [&bin, &script] {
                let mode = std::fs::metadata(p).unwrap().permissions().mode();
                assert!(mode & 0o111 != 0, "{} must be executable", p.display());
            }
        }
    }

    #[test]
    fn mount_point_is_volumes_kovra() {
        assert_eq!(mount_point(), Path::new("/Volumes/KOVRA"));
    }

    #[test]
    fn unpack_script_opens_with_recipient_identity_and_offusb_token() {
        let s = render_unpack_script();
        assert!(s.starts_with("#!/usr/bin/env bash"));
        assert!(s.contains(&format!("--in \"$HERE/{PACKAGE_FILE}\"")));
        assert!(s.contains(&format!("--identity '{RECIPIENT_COORDINATE}'")));
        // The token (second channel) is taken from the env and landed OFF the USB.
        assert!(s.contains("KOVRA_EXCHANGE_TOKEN"));
        assert!(s.contains("mktemp"));
        // The token file is cleaned up and never written to the stick.
        assert!(s.contains("rm -f \"$tok\""));
        assert!(!s.to_lowercase().contains("private key"));
    }
}
