//! Time behind a trait (CLAUDE.md rule 4: the clock is a trait).
//!
//! L3 is the first layer that observes time — audit timestamps (§11) and
//! confirmation deadlines (§8). Both go through [`Clock`] so core logic is
//! tested deterministically with [`MockClock`]; production uses [`SystemClock`].

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A source of wall-clock time. Returns both a monotonic-ish epoch instant (for
/// deadline math) and an RFC-3339 rendering (for audit records).
pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch (UTC).
    fn unix_secs(&self) -> u64;

    /// The current time as an RFC-3339 / ISO-8601 UTC string, e.g.
    /// `2026-05-30T22:18:30Z`. Default impl derives it from [`Clock::unix_secs`].
    fn now_rfc3339(&self) -> String {
        format_rfc3339_utc(self.unix_secs())
    }
}

/// Real system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }
}

/// Deterministic, advanceable clock for tests.
#[derive(Debug)]
pub struct MockClock {
    secs: std::sync::atomic::AtomicU64,
}

impl MockClock {
    /// A mock clock fixed at `secs` since the epoch.
    pub fn at(secs: u64) -> Self {
        Self {
            secs: std::sync::atomic::AtomicU64::new(secs),
        }
    }

    /// Advance the mock clock by `secs` seconds (simulating elapsed time).
    pub fn advance(&self, secs: u64) {
        self.secs
            .fetch_add(secs, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Default for MockClock {
    fn default() -> Self {
        // A fixed, recognizable instant: 2026-05-30T00:00:00Z.
        Self::at(1_780_099_200)
    }
}

impl Clock for MockClock {
    fn unix_secs(&self) -> u64 {
        self.secs.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Format a Unix-seconds instant as an RFC-3339 UTC string (`...Z`), using the
/// civil-from-days algorithm — no external date dependency.
fn format_rfc3339_utc(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let secs_of_day = unix_secs % 86_400;
    let (hour, min, sec) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );

    // Howard Hinnant's civil_from_days (epoch = 1970-01-01).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { year + 1 } else { year };

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_clock_is_fixed_then_advances() {
        let c = MockClock::at(1000);
        assert_eq!(c.unix_secs(), 1000);
        c.advance(50);
        assert_eq!(c.unix_secs(), 1050);
    }

    #[test]
    fn rfc3339_formats_known_instants() {
        // 0 → epoch.
        assert_eq!(format_rfc3339_utc(0), "1970-01-01T00:00:00Z");
        // A known instant: 2026-05-30T00:00:00Z.
        assert_eq!(format_rfc3339_utc(1_780_099_200), "2026-05-30T00:00:00Z");
        // With time-of-day.
        assert_eq!(
            format_rfc3339_utc(1_780_099_200 + 3661),
            "2026-05-30T01:01:01Z"
        );
    }

    #[test]
    fn mock_default_clock_renders_expected_date() {
        assert_eq!(MockClock::default().now_rfc3339(), "2026-05-30T00:00:00Z");
    }

    #[test]
    fn system_clock_is_after_2020() {
        // Sanity: real clock returns a plausible recent instant.
        assert!(SystemClock.unix_secs() > 1_577_836_800); // 2020-01-01
    }
}
