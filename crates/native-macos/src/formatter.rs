//! macOS removable-media [`Formatter`] (KOV-40, `[host]`). Shells out to
//! `diskutil` to probe and erase a USB device. This is the *native half* — the
//! security-load-bearing safety rails and the broker gate live in
//! [`kovra_core::format_removable`]; this crate only reports what the OS sees and
//! performs the erase once the core has authorized it.
//!
//! ## `[host]` validation
//!
//! The real `diskutil` path is **not** exercised by CI (it needs a real USB
//! stick and would erase it). It is validated by a human on an M4 (the epic's
//! `[host]` checklist). The OS-independent contract — the external/ejectable/
//! non-boot rail, the I16 headline, deny/timeout fail-closed — is fully covered
//! by the core unit tests against [`kovra_core::MockFormatter`].
//!
//! ## Cross-platform
//!
//! The real implementation is gated on `cfg(target_os = "macos")`. Off-macOS the
//! type still exists but every method returns an explicit "macOS only" error, so
//! the whole workspace builds on Linux CI (matching the biometric stub).

use kovra_core::{CoreError, DeviceInfo, Formatter};

/// The native macOS `Formatter`, backed by `diskutil`.
pub struct DiskutilFormatter;

impl DiskutilFormatter {
    /// Construct the host formatter handle.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for DiskutilFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl Formatter for DiskutilFormatter {
    fn probe(&self, node: &str) -> Result<DeviceInfo, CoreError> {
        #[cfg(target_os = "macos")]
        {
            macos::probe(node)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = node;
            Err(CoreError::Format(
                "removable-media formatting is only supported on macOS".into(),
            ))
        }
    }

    fn list_devices(&self) -> Result<Vec<DeviceInfo>, CoreError> {
        #[cfg(target_os = "macos")]
        {
            macos::list_devices()
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(CoreError::Format(
                "removable-media formatting is only supported on macOS".into(),
            ))
        }
    }

    fn erase(&self, node: &str, label: &str) -> Result<(), CoreError> {
        #[cfg(target_os = "macos")]
        {
            macos::erase(node, label)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (node, label);
            Err(CoreError::Format(
                "removable-media formatting is only supported on macOS".into(),
            ))
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use kovra_core::{CoreError, DeviceInfo};
    use wait_timeout::ChildExt;

    /// `diskutil` is local and fast; a generous ceiling guards against a hung
    /// device without ever blocking the broker prompt indefinitely.
    const DISKUTIL_TIMEOUT: Duration = Duration::from_secs(60);

    /// Run `diskutil <args>` with a timeout. Returns `(exit_code, stdout)`.
    /// stderr is folded into the error message on failure (coarse, no secrets).
    fn diskutil(args: &[&str]) -> Result<String, CoreError> {
        let mut child = Command::new("diskutil")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| CoreError::Format(format!("could not run `diskutil` ({e})")))?;

        let status = match child
            .wait_timeout(DISKUTIL_TIMEOUT)
            .map_err(|e| CoreError::Format(format!("waiting on `diskutil` failed ({e})")))?
        {
            Some(status) => status,
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CoreError::Format(format!(
                    "`diskutil {}` timed out",
                    args.first().copied().unwrap_or("")
                )));
            }
        };

        let mut stdout = String::new();
        let mut stderr = String::new();
        if let Some(mut o) = child.stdout.take() {
            let _ = o.read_to_string(&mut stdout);
        }
        if let Some(mut e) = child.stderr.take() {
            let _ = e.read_to_string(&mut stderr);
        }
        if !status.success() {
            let detail = stderr.trim();
            return Err(CoreError::Format(format!(
                "`diskutil {}` failed{}",
                args.first().copied().unwrap_or(""),
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(": {detail}")
                }
            )));
        }
        Ok(stdout)
    }

    /// The trimmed value after the first `key` line in `diskutil info` output.
    fn field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
        text.lines()
            .find_map(|l| l.trim_start().strip_prefix(key))
            .map(str::trim)
    }

    /// Extract the `(NNN Bytes)` count `diskutil` appends to size fields.
    fn bytes_in_parens(value: &str) -> Option<u64> {
        let open = value.find('(')?;
        let rest = &value[open + 1..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse().ok()
    }

    /// `Part of Whole:` — the whole-disk identifier a node belongs to.
    fn part_of_whole(text: &str) -> Option<String> {
        field(text, "Part of Whole:").map(str::to_string)
    }

    /// The whole-disk identifier backing `/` (the boot/system volume).
    fn boot_whole() -> Option<String> {
        let info = diskutil(&["info", "/"]).ok()?;
        part_of_whole(&info)
    }

    pub fn probe(node: &str) -> Result<DeviceInfo, CoreError> {
        let text = diskutil(&["info", node])?;

        // `Removable Media:` is "Removable"/"Fixed" on modern macOS (older builds
        // print Yes/No). `Device Location:` is External/Internal. Treat the
        // device as removable only when the OS clearly says so.
        let removable = field(&text, "Removable Media:")
            .map(|v| {
                let v = v.to_ascii_lowercase();
                v.contains("removable") || v.starts_with("yes")
            })
            .unwrap_or(false);
        let internal = field(&text, "Internal:")
            .map(|v| v.starts_with("Yes"))
            .or_else(|| field(&text, "Device Location:").map(|v| v.contains("Internal")))
            .unwrap_or(false);
        // `Ejectable:` is the safety-relevant signal — Yes for external USB/TB
        // media (sticks AND SSDs), No for internal disks. This, not
        // `Removable Media:`, is what the core rail keys on.
        let ejectable = field(&text, "Ejectable:")
            .map(|v| v.starts_with("Yes"))
            .unwrap_or(false);

        let name = field(&text, "Volume Name:")
            .filter(|v| !v.is_empty() && *v != "(no value)")
            .or_else(|| field(&text, "Device / Media Name:"))
            .unwrap_or("")
            .to_string();

        let total_bytes = field(&text, "Disk Size:")
            .and_then(bytes_in_parens)
            .or_else(|| field(&text, "Total Size:").and_then(bytes_in_parens))
            .unwrap_or(0);
        let used_bytes = field(&text, "Volume Used Space:").and_then(bytes_in_parens);
        let mounted = field(&text, "Mounted:")
            .map(|v| v.starts_with("Yes"))
            .unwrap_or(false);

        // Boot defense-in-depth: refuse if the target shares the whole disk that
        // backs `/`. (A boot disk is also internal+fixed, so the rail catches it
        // regardless; this is belt-and-suspenders.)
        let boot = match (part_of_whole(&text), boot_whole()) {
            (Some(target), Some(boot)) => target == boot,
            _ => false,
        };

        Ok(DeviceInfo {
            node: node.to_string(),
            name,
            total_bytes,
            used_bytes,
            removable,
            ejectable,
            internal,
            boot,
            mounted,
        })
    }

    /// Enumerate whole **physical** disks (`/dev/diskN (... physical):` lines from
    /// `diskutil list`) and probe each. Probe failures are skipped. The CLI
    /// applies `eligible_targets` to offer only rail-safe devices.
    pub fn list_devices() -> Result<Vec<DeviceInfo>, CoreError> {
        let text = diskutil(&["list"])?;
        let mut out = Vec::new();
        for line in text.lines() {
            // e.g. "/dev/disk6 (internal, physical):" / "/dev/disk4 (external, physical):"
            let Some(rest) = line.strip_prefix("/dev/") else {
                continue;
            };
            let Some((id, descriptor)) = rest.split_once(' ') else {
                continue;
            };
            // Whole physical disks only — skip synthesized containers / images.
            if !descriptor.contains("physical") {
                continue;
            }
            if let Ok(info) = probe(&format!("/dev/{id}")) {
                out.push(info);
            }
        }
        Ok(out)
    }

    pub fn erase(node: &str, label: &str) -> Result<(), CoreError> {
        // ExFAT: read/write on macOS and broadly portable for carrying the
        // bootstrap files. The volume label is sanitized to a conservative,
        // FAT-safe form.
        let label = sanitize_label(label);
        diskutil(&["eraseDisk", "ExFAT", &label, node])?;
        Ok(())
    }

    /// FAT volume labels are short and uppercase-friendly: keep ASCII
    /// alphanumerics, uppercase, cap at 11 chars, never empty.
    fn sanitize_label(label: &str) -> String {
        let cleaned: String = label
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(11)
            .collect::<String>()
            .to_ascii_uppercase();
        if cleaned.is_empty() {
            "KOVRA".to_string()
        } else {
            cleaned
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const SAMPLE: &str = "   Device Node:             /dev/disk4\n   \
            Volume Name:              FIELDKIT\n   \
            Removable Media:          Fixed\n   \
            Internal:                 No\n   \
            Ejectable:                Yes\n   \
            Device Location:          External\n   \
            Part of Whole:            disk4\n   \
            Disk Size:                30.8 GB (30752000000 Bytes) (exactly ...)\n   \
            Volume Used Space:        1.2 GB (1200000000 Bytes) (exactly ...)\n   \
            Mounted:                  Yes\n";

        #[test]
        fn parses_diskutil_fields() {
            assert_eq!(field(SAMPLE, "Volume Name:"), Some("FIELDKIT"));
            // A USB SSD: Fixed media but ejectable — the case the refined rail accepts.
            assert_eq!(field(SAMPLE, "Removable Media:"), Some("Fixed"));
            assert_eq!(field(SAMPLE, "Internal:"), Some("No"));
            assert_eq!(field(SAMPLE, "Ejectable:"), Some("Yes"));
            assert_eq!(part_of_whole(SAMPLE).as_deref(), Some("disk4"));
        }

        #[test]
        fn extracts_byte_counts() {
            assert_eq!(
                bytes_in_parens("30.8 GB (30752000000 Bytes) (exactly ...)"),
                Some(30_752_000_000)
            );
            assert_eq!(bytes_in_parens("no parens"), None);
        }

        #[test]
        fn sanitize_label_is_fat_safe() {
            assert_eq!(sanitize_label("kovra exchange!"), "KOVRAEXCHAN");
            assert_eq!(sanitize_label(""), "KOVRA");
            assert_eq!(sanitize_label("---"), "KOVRA");
        }
    }
}
