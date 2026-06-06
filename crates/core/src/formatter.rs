//! Removable-media formatter (KOV-40, USB offline-exchange epic §7.3) — the
//! destructive piece that wipes a USB stick so kovra can build a bootstrap
//! device (`kovra exchange init`, KOV-41). The OS lives behind a mockable
//! [`Formatter`] trait; the macOS `diskutil` implementation is `[host]`
//! (validated on hardware by the human, not by CI — CLAUDE.md rule 4).
//!
//! ## Non-negotiable safety rails
//!
//! Erasing the wrong disk is irreversible, so the rails are deliberately strict
//! and live in the OS-independent core where they are fully tested:
//!
//! 1. **External + ejectable + non-boot only** — [`assert_eraseable_target`] is a
//!    *hard refusal with no prompt*. An internal/boot/non-ejectable disk never
//!    even reaches the broker; there is no override. (The check is *not*
//!    `RemovableMedia=Yes` — a USB SSD reports `Fixed` yet is a legitimate
//!    target; the safety predicate is internal/boot/ejectable, not media type.)
//! 2. **Attended broker confirmation** — [`format_removable`] gates the wipe
//!    behind the [`Confirmer`] (Touch ID on `[host]`, file broker otherwise)
//!    with an I16 authoritative headline carrying the device node, name, size,
//!    and `ALL DATA WILL BE ERASED`.
//! 3. **Content warning** — when the device is non-empty the headline surfaces
//!    that fact (used bytes / a mounted volume) before the human authorizes.
//!
//! [`Formatter::erase`] is destructive and must only be reached *through*
//! [`format_removable`]; callers never invoke it directly.

use std::time::Duration;

use crate::confirm::{ConfirmOutcome, ConfirmRequest, Confirmer};
use crate::error::CoreError;
use crate::scope::Origin;

/// What the OS reports about a candidate device, authored by [`Formatter::probe`]
/// — never from user input. Carries no secret material (I12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    /// The device node as the OS addresses it (e.g. `/dev/disk4`).
    pub node: String,
    /// Human label (volume / media name), best-effort; may be empty.
    pub name: String,
    /// Total capacity in bytes (`0` if the OS did not report it).
    pub total_bytes: u64,
    /// Bytes in use across mounted volumes, if the OS reported it.
    pub used_bytes: Option<u64>,
    /// The device's *media* is removable from its mechanism (SD card, optical),
    /// as opposed to fixed flash/SSD. Informational only — it is NOT the erase
    /// safety predicate (a USB SSD reports `Fixed` yet is a perfectly safe,
    /// intended target). The rail keys on [`Self::ejectable`] + external instead.
    pub removable: bool,
    /// The device can be ejected from the running system (external bus). Internal
    /// disks are not ejectable. This — together with not-internal and not-boot —
    /// is the actual erase-safety predicate the rail enforces.
    pub ejectable: bool,
    /// The device is internal/onboard — the opposite of an external stick.
    pub internal: bool,
    /// The device backs the current boot/system volume.
    pub boot: bool,
    /// At least one volume on the device is currently mounted.
    pub mounted: bool,
}

impl DeviceInfo {
    /// A human-readable capacity for the I16 headline (never a value).
    #[must_use]
    pub fn human_size(&self) -> String {
        human_bytes(self.total_bytes)
    }

    /// Whether the device appears to hold data — used to decide whether the
    /// confirmation headline must carry a content warning.
    #[must_use]
    pub fn non_empty(&self) -> bool {
        self.used_bytes.map(|u| u > 0).unwrap_or(self.mounted)
    }
}

/// The OS-format capability, behind a trait so the core logic is tested with a
/// deterministic mock and the native `diskutil` half is injected at the edge.
pub trait Formatter {
    /// Inspect a device *without modifying it*.
    fn probe(&self, node: &str) -> Result<DeviceInfo, CoreError>;

    /// Enumerate **whole physical** devices the user could pick to format — the
    /// raw probe list (the CLI applies [`eligible_targets`] to offer only the
    /// safe ones). Read-only.
    fn list_devices(&self) -> Result<Vec<DeviceInfo>, CoreError>;

    /// Erase the device and lay down a single empty volume named `label`.
    /// **Destructive.** Never call this directly — go through
    /// [`format_removable`], which enforces the safety rails and the broker gate.
    fn erase(&self, node: &str, label: &str) -> Result<(), CoreError>;
}

/// Hard safety rail (**no prompt**): refuse the **boot disk** and any **internal,
/// fixed, non-ejectable** disk; allow everything else (external, removable, or
/// ejectable media). Anything refused never reaches the confirmation broker.
/// Erasing the wrong disk is irreversible — this check has no override.
///
/// The principle: the catastrophe to prevent is erasing the **system / an
/// internal fixed** disk. Neither `RemovableMedia` nor `Device Location` alone is
/// the right predicate:
/// - A **USB SSD** reports `Removable Media: Fixed` yet is `Internal: No` — a
///   legitimate external target (caught by `!internal`).
/// - A **built-in SD card reader** reports `Device Location: Internal` yet
///   `Removable Media: Removable` — a legitimate removable target (caught by
///   `removable`).
/// - The **soldered system SSD** is `Internal` + `Fixed` + non-ejectable — the
///   one thing we must never wipe (refused by the `internal && !removable &&
///   !ejectable` clause, and by `boot`).
///
/// So a device is eraseable iff it is **not boot** and (**not internal**, OR its
/// media is **removable**, OR it is **ejectable**). Whether it is the *right*
/// device (and may hold data) is the next layer's job: the content warning + the
/// attended broker confirmation (I16), not this rail.
pub fn assert_eraseable_target(info: &DeviceInfo) -> Result<(), CoreError> {
    if info.boot {
        return Err(CoreError::Format(format!(
            "{} backs the boot/system volume — refusing to format it",
            info.node
        )));
    }
    if info.internal && !info.removable && !info.ejectable {
        return Err(CoreError::Format(format!(
            "{} is an internal fixed disk — kovra only formats external, removable, or ejectable media",
            info.node
        )));
    }
    Ok(())
}

/// Filter probed devices to those the rail accepts — the candidate list a UI/CLI
/// offers the user to pick from (KOV-41 device picker). Pure helper over
/// [`assert_eraseable_target`].
#[must_use]
pub fn eligible_targets(devices: Vec<DeviceInfo>) -> Vec<DeviceInfo> {
    devices
        .into_iter()
        .filter(|d| assert_eraseable_target(d).is_ok())
        .collect()
}

/// The authoritative confirmation headline for a wipe (I16, §8.3): device node,
/// name, size, the irreversible-erase warning, and — when the device is
/// non-empty — a content warning. No secret material.
#[must_use]
pub fn wipe_headline(info: &DeviceInfo) -> String {
    let name = if info.name.trim().is_empty() {
        "unnamed".to_string()
    } else {
        info.name.clone()
    };
    let mut headline = format!(
        "ERASE {} (\"{}\", {}) — ALL DATA ON THIS DEVICE WILL BE ERASED",
        info.node,
        name,
        info.human_size()
    );
    if info.non_empty() {
        match info.used_bytes {
            Some(u) if u > 0 => {
                headline.push_str(&format!(" — it is NOT empty (~{} in use)", human_bytes(u)));
            }
            _ => headline.push_str(" — it has a mounted volume with existing data"),
        }
    }
    headline
}

/// The single guarded entry point for a wipe: probe → safety rail (hard refusal)
/// → attended broker confirmation (I16) → erase. Returns the probed
/// [`DeviceInfo`] on success so the caller can report what was formatted.
///
/// The order is load-bearing: the rail runs *before* the prompt (an unsafe
/// target is never offered for approval), and `erase` runs *only* on an explicit
/// [`ConfirmOutcome::Approved`] (deny/timeout fail closed, §8).
pub fn format_removable(
    formatter: &dyn Formatter,
    confirmer: &dyn Confirmer,
    node: &str,
    label: &str,
    timeout: Duration,
) -> Result<DeviceInfo, CoreError> {
    let info = formatter.probe(node)?;
    // Hard rail first — a dangerous device must not even reach the broker.
    assert_eraseable_target(&info)?;

    let req = ConfirmRequest::for_action(wipe_headline(&info), Origin::Human);
    match confirmer.confirm(&req, timeout) {
        ConfirmOutcome::Approved => {
            formatter.erase(node, label)?;
            Ok(info)
        }
        ConfirmOutcome::Denied => Err(CoreError::Format(format!(
            "denied — {node} was not formatted"
        ))),
        ConfirmOutcome::TimedOut => Err(CoreError::Format(format!(
            "timed out — {node} was not formatted"
        ))),
    }
}

/// A deterministic in-memory [`Formatter`] for tests — no real device is ever
/// touched. Mirrors [`MockSshAgent`](crate::MockSshAgent): construct it with a
/// canned [`DeviceInfo`], then inspect what `erase` recorded.
pub struct MockFormatter {
    info: DeviceInfo,
    devices: Vec<DeviceInfo>,
    erased: std::sync::Mutex<Option<(String, String)>>,
    erase_fails: bool,
}

impl MockFormatter {
    /// A formatter whose `probe` returns `info` (with the queried node overlaid)
    /// and whose `erase` succeeds and records its arguments. `list_devices`
    /// returns just `info`.
    #[must_use]
    pub fn new(info: DeviceInfo) -> Self {
        Self {
            devices: vec![info.clone()],
            info,
            erased: std::sync::Mutex::new(None),
            erase_fails: false,
        }
    }

    /// A formatter whose `list_devices` returns `devices` (probe still returns
    /// the first as the canned info) — to test the candidate-listing/filtering.
    #[must_use]
    pub fn with_devices(devices: Vec<DeviceInfo>) -> Self {
        let info = devices.first().cloned().unwrap_or(DeviceInfo {
            node: String::new(),
            name: String::new(),
            total_bytes: 0,
            used_bytes: None,
            removable: false,
            ejectable: false,
            internal: false,
            boot: false,
            mounted: false,
        });
        Self {
            info,
            devices,
            erased: std::sync::Mutex::new(None),
            erase_fails: false,
        }
    }

    /// Like [`Self::new`], but `erase` fails — to test that a format error
    /// propagates after an approval.
    #[must_use]
    pub fn failing(info: DeviceInfo) -> Self {
        Self {
            devices: vec![info.clone()],
            info,
            erased: std::sync::Mutex::new(None),
            erase_fails: true,
        }
    }

    /// The `(node, label)` the last successful `erase` recorded, if any.
    #[must_use]
    pub fn erased(&self) -> Option<(String, String)> {
        self.erased
            .lock()
            .expect("mock formatter mutex poisoned")
            .clone()
    }
}

impl Formatter for MockFormatter {
    fn probe(&self, node: &str) -> Result<DeviceInfo, CoreError> {
        let mut i = self.info.clone();
        i.node = node.to_string();
        Ok(i)
    }
    fn list_devices(&self) -> Result<Vec<DeviceInfo>, CoreError> {
        Ok(self.devices.clone())
    }
    fn erase(&self, node: &str, label: &str) -> Result<(), CoreError> {
        if self.erase_fails {
            return Err(CoreError::Format("mock erase failed".into()));
        }
        *self.erased.lock().expect("mock formatter mutex poisoned") =
            Some((node.to_string(), label.to_string()));
        Ok(())
    }
}

/// Decimal (SI) human-readable byte size — matches `diskutil`'s GB convention.
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if n < 1000 {
        return format!("{n} B");
    }
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A valid eraseable target by default: external, ejectable, non-boot
    /// (a plain removable stick). Tests tweak fields to exercise the rail.
    fn eraseable(node: &str) -> DeviceInfo {
        DeviceInfo {
            node: node.to_string(),
            name: "FIELDKIT".to_string(),
            total_bytes: 30_752_000_000,
            used_bytes: Some(0),
            removable: true,
            ejectable: true,
            internal: false,
            boot: false,
            mounted: false,
        }
    }

    /// A counting [`Confirmer`] so a test can assert the broker is (or is not)
    /// even consulted, plus what outcome it returned.
    struct CountingConfirmer {
        outcome: ConfirmOutcome,
        calls: AtomicU32,
    }
    impl CountingConfirmer {
        fn new(outcome: ConfirmOutcome) -> Self {
            Self {
                outcome,
                calls: AtomicU32::new(0),
            }
        }
        fn calls(&self) -> u32 {
            self.calls.load(Ordering::SeqCst)
        }
    }
    impl Confirmer for CountingConfirmer {
        fn confirm(&self, _req: &ConfirmRequest, _t: Duration) -> ConfirmOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.outcome
        }
    }

    // The hard safety rail: refuse boot + internal-fixed-non-ejectable; allow
    // external / removable / ejectable. Covers all three real device classes.
    #[test]
    fn rail_allows_external_removable_or_ejectable_refuses_boot_and_internal_fixed() {
        // Plain external removable stick — accepted.
        assert!(assert_eraseable_target(&eraseable("/dev/disk4")).is_ok());

        // USB SSD: `Fixed` media but external + ejectable (the SL600) — accepted.
        let mut usb_ssd = eraseable("/dev/disk4");
        usb_ssd.removable = false;
        usb_ssd.internal = false;
        assert!(
            assert_eraseable_target(&usb_ssd).is_ok(),
            "external ejectable USB SSD must be eraseable even when Fixed"
        );

        // Built-in SD card reader: Device Location Internal but RemovableMedia
        // Removable (the disk6 case) — accepted because it is removable.
        let mut sd = eraseable("/dev/disk6");
        sd.internal = true;
        sd.removable = true;
        sd.ejectable = false;
        assert!(
            assert_eraseable_target(&sd).is_ok(),
            "an internal-location but removable SD card must be eraseable"
        );

        // Soldered internal system SSD: internal + fixed + non-ejectable — REFUSED.
        let mut system = eraseable("/dev/disk0");
        system.internal = true;
        system.removable = false;
        system.ejectable = false;
        assert!(
            assert_eraseable_target(&system).is_err(),
            "an internal fixed non-ejectable disk must be refused"
        );

        // Boot — refused regardless.
        let mut boot = eraseable("/dev/disk1");
        boot.boot = true;
        assert!(assert_eraseable_target(&boot).is_err());
    }

    // The candidate picker offers only rail-eligible devices.
    #[test]
    fn eligible_targets_filters_to_safe_devices() {
        let stick = eraseable("/dev/disk4");
        let mut system = eraseable("/dev/disk0");
        system.internal = true;
        system.removable = false;
        system.ejectable = false;
        let mut boot = eraseable("/dev/disk1");
        boot.boot = true;

        let elig = eligible_targets(vec![stick.clone(), system, boot]);
        assert_eq!(elig.len(), 1, "only the safe stick is eligible");
        assert_eq!(elig[0].node, "/dev/disk4");
    }

    // Happy path: a removable device that is approved gets erased, and the probed
    // info is returned.
    #[test]
    fn format_removable_approved_erases() {
        let fmt = MockFormatter::new(eraseable("/dev/disk4"));
        let confirmer = CountingConfirmer::new(ConfirmOutcome::Approved);
        let info =
            format_removable(&fmt, &confirmer, "/dev/disk4", "KOVRA", Duration::ZERO).unwrap();
        assert_eq!(info.node, "/dev/disk4");
        assert_eq!(confirmer.calls(), 1, "the broker is consulted exactly once");
        assert_eq!(
            fmt.erased(),
            Some(("/dev/disk4".to_string(), "KOVRA".to_string()))
        );
    }

    // Deny and timeout both fail closed — nothing is erased.
    #[test]
    fn format_removable_denied_or_timeout_fails_closed() {
        for outcome in [ConfirmOutcome::Denied, ConfirmOutcome::TimedOut] {
            let fmt = MockFormatter::new(eraseable("/dev/disk4"));
            let confirmer = CountingConfirmer::new(outcome);
            let err = format_removable(&fmt, &confirmer, "/dev/disk4", "KOVRA", Duration::ZERO);
            assert!(err.is_err(), "{outcome:?} must fail closed");
            assert_eq!(fmt.erased(), None, "{outcome:?} must not erase");
        }
    }

    // An unsafe target is refused BEFORE the broker is ever consulted (no prompt
    // for a dangerous disk) and is never erased.
    #[test]
    fn unsafe_target_refused_without_prompting() {
        // An internal, fixed, non-ejectable disk (the soldered system SSD).
        let mut system = eraseable("/dev/disk0");
        system.internal = true;
        system.removable = false;
        system.ejectable = false;
        let fmt = MockFormatter::new(system);
        let confirmer = CountingConfirmer::new(ConfirmOutcome::Approved);
        let err = format_removable(&fmt, &confirmer, "/dev/disk0", "KOVRA", Duration::ZERO);
        assert!(err.is_err(), "internal fixed disk must be refused");
        assert_eq!(
            confirmer.calls(),
            0,
            "the broker must NOT be consulted for an unsafe target"
        );
        assert_eq!(fmt.erased(), None);
    }

    // The I16 headline names the device, size, the erase warning, and a content
    // warning when the device is non-empty.
    #[test]
    fn headline_carries_authoritative_fields_and_content_warning() {
        let mut info = eraseable("/dev/disk4");
        info.used_bytes = Some(12_000_000_000);
        let h = wipe_headline(&info);
        assert!(h.contains("/dev/disk4"), "names the device: {h}");
        assert!(h.contains("FIELDKIT"), "names the volume: {h}");
        assert!(h.contains("GB"), "shows the size: {h}");
        assert!(h.contains("ALL DATA"), "warns of erasure: {h}");
        assert!(h.contains("NOT empty"), "warns about content: {h}");

        let empty = eraseable("/dev/disk4"); // used_bytes Some(0), not mounted
        let h2 = wipe_headline(&empty);
        assert!(
            !h2.contains("NOT empty"),
            "no content warning when empty: {h2}"
        );
    }

    #[test]
    fn human_bytes_uses_si_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(30_752_000_000), "30.8 GB");
    }
}
