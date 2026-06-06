//! TOTP seed custody & RFC-6238 code derivation (KOV-11, extends spec §1.3).
//!
//! kovra custodies a TOTP **seed** (the shared secret of an authenticator
//! enrollment) and derives the current time-based one-time code on demand. The
//! seed lives in a [`SecretValue`](crate::secret::SecretValue) and is sealed by
//! the same AEAD path as a literal ([`crate::crypto`]); it is **never exported**.
//! Exactly like a private key (KOV-12), the seed is used only *through* an
//! operation — here, deriving a short-lived 6-digit code — and never crosses
//! back into the caller's (or the model's) context (I11/I14), is never logged
//! (I7/I12), and is never placed in `argv` (I6).
//!
//! This module is **pure**: it knows nothing about the vault, policy, the broker,
//! or even the wall clock. [`code_at`] takes an explicit `unix_secs`, so the
//! faces drive it through the existing [`Clock`](crate::clock::Clock) trait and
//! tests pin a [`MockClock`](crate::clock::MockClock) to assert the RFC-6238
//! known-answer vectors (Appendix B) deterministically, with no hardware.
//!
//! The implementation of HOTP/TOTP is in-crate on `hmac` + `sha1`/`sha2` — no
//! external TOTP crate (closed decision, KOV-11). The face classifies the code
//! op as an injection-class operation (broker-gated for `high`/`prod`, I3/I15).

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// RFC-6238 default time step (seconds).
pub const DEFAULT_PERIOD: u8 = 30;
/// RFC-6238 default code length (digits).
pub const DEFAULT_DIGITS: u8 = 6;

/// The HMAC hash algorithm backing a TOTP enrollment (RFC-6238 §1.2). SHA1 is
/// the default (Google-Authenticator compatible); SHA256/SHA512 are the other
/// two registered algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TotpAlgorithm {
    /// HMAC-SHA1 — the RFC-6238 default.
    #[default]
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

impl TotpAlgorithm {
    /// Parse an algorithm name (`SHA1`/`SHA256`/`SHA512`, case-insensitive — the
    /// `otpauth://` URI spelling).
    pub fn parse(s: &str) -> Result<Self, CoreError> {
        match s.to_ascii_uppercase().as_str() {
            "SHA1" => Ok(TotpAlgorithm::Sha1),
            "SHA256" => Ok(TotpAlgorithm::Sha256),
            "SHA512" => Ok(TotpAlgorithm::Sha512),
            other => Err(CoreError::Totp(format!(
                "unknown TOTP algorithm `{other}` (expected SHA1|SHA256|SHA512)"
            ))),
        }
    }

    /// The canonical `otpauth://` spelling (`SHA1` / `SHA256` / `SHA512`).
    pub fn as_str(&self) -> &'static str {
        match self {
            TotpAlgorithm::Sha1 => "SHA1",
            TotpAlgorithm::Sha256 => "SHA256",
            TotpAlgorithm::Sha512 => "SHA512",
        }
    }
}

/// The non-secret parameters of a TOTP enrollment. (The seed is held separately
/// in a [`SecretValue`](crate::secret::SecretValue) — never here.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TotpParams {
    /// The HMAC hash algorithm.
    pub algorithm: TotpAlgorithm,
    /// The number of digits in a code (typically 6).
    pub digits: u8,
    /// The time step in seconds (typically 30).
    pub period: u8,
}

impl Default for TotpParams {
    fn default() -> Self {
        Self {
            algorithm: TotpAlgorithm::default(),
            digits: DEFAULT_DIGITS,
            period: DEFAULT_PERIOD,
        }
    }
}

/// The parsed result of an `otpauth://totp/...` enrollment URI: the raw seed
/// bytes (base32-decoded) plus the non-secret parameters. The seed bytes are
/// the caller's responsibility to seal immediately into a `SecretValue`.
pub struct ParsedEnrollment {
    /// The decoded shared-secret seed bytes.
    pub seed: Vec<u8>,
    /// The enrollment parameters.
    pub params: TotpParams,
}

/// Derive the RFC-6238 TOTP code for `unix_secs`.
///
/// `T = floor(unix_secs / period)` is the moving factor; the code is the
/// truncated HOTP (RFC 4226 §5.3) of `HMAC(seed, T)` taken modulo `10^digits`,
/// left-padded to `digits`. Pure: no clock, no I/O — the face passes the time.
///
/// Returns an error for a degenerate parameter (`period == 0`, or `digits` not
/// in `1..=9` so the modulus fits a `u32` truncation). The seed bytes are never
/// echoed into the error (I12).
pub fn code_at(
    seed: &[u8],
    unix_secs: u64,
    algorithm: TotpAlgorithm,
    digits: u8,
    period: u8,
) -> Result<String, CoreError> {
    if period == 0 {
        return Err(CoreError::Totp("period must be at least 1 second".into()));
    }
    if !(1..=9).contains(&digits) {
        return Err(CoreError::Totp(format!(
            "digits must be between 1 and 9 (got {digits})"
        )));
    }
    let counter = unix_secs / period as u64;
    let mac = hmac_counter(seed, counter, algorithm)?;
    // Dynamic truncation (RFC 4226 §5.3): the low nibble of the last byte is an
    // offset into the MAC; read 4 bytes there, mask the high bit, mod 10^digits.
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let bin = ((mac[offset] as u32 & 0x7f) << 24)
        | ((mac[offset + 1] as u32) << 16)
        | ((mac[offset + 2] as u32) << 8)
        | (mac[offset + 3] as u32);
    let modulus = 10u32.pow(digits as u32);
    let code = bin % modulus;
    Ok(format!("{code:0width$}", width = digits as usize))
}

/// Seconds left in the current RFC-6238 time window for `unix_secs`.
///
/// The active counter spans `[T*period, (T+1)*period)`; this returns how many
/// whole seconds remain before it rolls over — `period - (unix_secs % period)`.
/// It is therefore in `1..=period` (never `0`): at the instant the window opens
/// the full `period` is left. Pure arithmetic, no clock and no I/O — the face
/// passes the time, exactly like [`code_at`]. `period == 0` is degenerate and
/// yields `0` (the same guard [`code_at`] rejects at derivation time).
pub fn seconds_remaining(unix_secs: u64, period: u64) -> u64 {
    if period == 0 {
        return 0;
    }
    period - (unix_secs % period)
}

/// Decide, for the `--min-validity N` scripting path, whether the **current**
/// window's code already has enough validity left to return immediately.
///
/// Returns `true` when `remaining` (the seconds left in the current window, as
/// from [`seconds_remaining`]) is **strictly greater** than `min_validity`. When
/// it is `false` the face must wait for the current window to end and derive the
/// next code, so the returned code is guaranteed more than `min_validity` seconds
/// of life. Pure: no clock, no I/O — the threshold comparison only.
///
/// With `min_validity == 0` this is `remaining > 0`, which is always `true` since
/// [`seconds_remaining`] is in `1..=period` for a valid period — so `--min-validity 0`
/// deterministically returns the current code (no boundary wait, no flakiness).
pub fn returns_current(remaining: u64, min_validity: u64) -> bool {
    remaining > min_validity
}

/// Compute `HMAC(seed, counter_be_bytes)` for the chosen algorithm, returning the
/// raw MAC bytes. The 8-byte big-endian counter is the RFC 4226 message.
///
/// `new_from_slice` accepts any key length (HMAC pads/hashes the key as needed);
/// it only errors on a pathological backend, which we map opaquely (I12, no seed).
fn hmac_counter(seed: &[u8], counter: u64, algorithm: TotpAlgorithm) -> Result<Vec<u8>, CoreError> {
    let msg = counter.to_be_bytes();
    let init_err = || CoreError::Totp("hmac init".into());
    let out = match algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac = <Hmac<sha1::Sha1>>::new_from_slice(seed).map_err(|_| init_err())?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut mac = <Hmac<sha2::Sha256>>::new_from_slice(seed).map_err(|_| init_err())?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha512 => {
            let mut mac = <Hmac<sha2::Sha512>>::new_from_slice(seed).map_err(|_| init_err())?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
    };
    Ok(out)
}

/// Decode an RFC 4648 base32 (`A-Z2-7`) seed string into raw bytes. Whitespace
/// and `=` padding are ignored; the alphabet is case-insensitive (authenticator
/// apps display uppercase, but users paste either case). Errors on any other
/// character. The decoded bytes are the secret — never logged (I12).
pub fn decode_base32(input: &str) -> Result<Vec<u8>, CoreError> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = Vec::new();
    for ch in input.chars() {
        if ch == '=' || ch.is_whitespace() || ch == '-' {
            continue;
        }
        let up = ch.to_ascii_uppercase() as u8;
        let val = ALPHABET
            .iter()
            .position(|&c| c == up)
            .ok_or_else(|| CoreError::Totp("seed is not valid base32 (A–Z, 2–7)".into()))?
            as u32;
        bits = (bits << 5) | val;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    if out.is_empty() {
        return Err(CoreError::Totp("empty seed".into()));
    }
    Ok(out)
}

/// Parse an `otpauth://totp/<label>?secret=...&algorithm=...&digits=...&period=...`
/// enrollment URI (the QR-code payload authenticator apps emit). Extracts the
/// base32 `secret` and any overridden parameters, falling back to the RFC-6238
/// defaults (SHA1 / 6 / 30). Only `type == totp` is accepted (`hotp` is event-
/// based and out of scope). The URI itself is not a secret label, but the
/// `secret` parameter is — it is returned as raw bytes for immediate sealing.
pub fn parse_otpauth(uri: &str) -> Result<ParsedEnrollment, CoreError> {
    let rest = uri
        .strip_prefix("otpauth://totp/")
        .ok_or_else(|| CoreError::Totp("not an `otpauth://totp/` URI".into()))?;
    let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");
    let mut secret: Option<String> = None;
    let mut params = TotpParams::default();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| CoreError::Totp("malformed otpauth query parameter".into()))?;
        match k.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(percent_decode(v)),
            "algorithm" => params.algorithm = TotpAlgorithm::parse(&percent_decode(v))?,
            "digits" => {
                params.digits = percent_decode(v)
                    .parse::<u8>()
                    .map_err(|_| CoreError::Totp("digits must be a small integer".into()))?
            }
            "period" => {
                params.period = percent_decode(v)
                    .parse::<u8>()
                    .map_err(|_| CoreError::Totp("period must be a small integer".into()))?
            }
            // issuer / counter / image / unknown keys are ignored.
            _ => {}
        }
    }
    let secret = secret.ok_or_else(|| CoreError::Totp("otpauth URI has no `secret`".into()))?;
    let seed = decode_base32(&secret)?;
    // Validate the parameters now so an enrollment with bad digits/period is
    // rejected at add time, not first `code` time.
    code_at(&seed, 0, params.algorithm, params.digits, params.period)?;
    Ok(ParsedEnrollment { seed, params })
}

/// Minimal percent-decoding for `otpauth://` query values (e.g. `%20`, `%3D`).
/// Sufficient for the small character set authenticator URIs use; leaves
/// already-plain values untouched.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Ingest a manual seed entry: either a full `otpauth://totp/...` URI or a bare
/// base32 seed string (which takes the RFC-6238 defaults). The face calls this
/// on the value read from stdin / a hidden prompt (never argv, I6).
pub fn parse_seed_input(input: &str) -> Result<ParsedEnrollment, CoreError> {
    let trimmed = input.trim();
    if trimmed.starts_with("otpauth://") {
        parse_otpauth(trimmed)
    } else {
        let seed = decode_base32(trimmed)?;
        Ok(ParsedEnrollment {
            seed,
            params: TotpParams::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RFC-6238 Appendix B test seed for SHA1 is the ASCII string
    /// `"12345678901234567890"` (20 bytes). SHA256/SHA512 repeat it to the
    /// algorithm's block size: 32 bytes for SHA256, 64 for SHA512.
    fn sha1_seed() -> Vec<u8> {
        b"12345678901234567890".to_vec()
    }
    fn sha256_seed() -> Vec<u8> {
        b"12345678901234567890123456789012".to_vec()
    }
    fn sha512_seed() -> Vec<u8> {
        b"1234567890123456789012345678901234567890123456789012345678901234".to_vec()
    }

    // RFC-6238 Appendix B — the published 8-digit known-answer vectors. We pin a
    // fixed `unix_secs` (the table's "Time (sec)" column) and assert the exact
    // code for each algorithm. This is the deterministic correctness gate.
    #[test]
    fn rfc6238_known_answer_vectors_sha1() {
        // (unix_secs, expected 8-digit code) from RFC 6238 Appendix B, SHA1.
        for (t, expected) in [
            (59u64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            let code = code_at(&sha1_seed(), t, TotpAlgorithm::Sha1, 8, 30).unwrap();
            assert_eq!(code, expected, "SHA1 vector at t={t}");
        }
    }

    #[test]
    fn rfc6238_known_answer_vectors_sha256() {
        for (t, expected) in [
            (59u64, "46119246"),
            (1_111_111_109, "68084774"),
            (1_234_567_890, "91819424"),
            (20_000_000_000, "77737706"),
        ] {
            let code = code_at(&sha256_seed(), t, TotpAlgorithm::Sha256, 8, 30).unwrap();
            assert_eq!(code, expected, "SHA256 vector at t={t}");
        }
    }

    #[test]
    fn rfc6238_known_answer_vectors_sha512() {
        for (t, expected) in [
            (59u64, "90693936"),
            (1_111_111_109, "25091201"),
            (1_234_567_890, "93441116"),
            (20_000_000_000, "47863826"),
        ] {
            let code = code_at(&sha512_seed(), t, TotpAlgorithm::Sha512, 8, 30).unwrap();
            assert_eq!(code, expected, "SHA512 vector at t={t}");
        }
    }

    // The same derivation through the `Clock` trait at a fixed instant yields the
    // same answer — the seam the CLI uses (MockClock → code_at) is deterministic.
    #[test]
    fn code_via_mock_clock_matches_vector() {
        use crate::clock::{Clock, MockClock};
        let clock = MockClock::at(59);
        let code = code_at(&sha1_seed(), clock.unix_secs(), TotpAlgorithm::Sha1, 8, 30).unwrap();
        assert_eq!(code, "94287082");
    }

    // The default 6-digit code is the last 6 of the 8-digit vector at t=59.
    #[test]
    fn default_six_digits_truncates_the_vector() {
        let code = code_at(&sha1_seed(), 59, TotpAlgorithm::Sha1, 6, 30).unwrap();
        assert_eq!(code, "287082");
        assert_eq!(code.len(), 6);
    }

    // base32 decode round-trips a known RFC 4648 vector and is case-insensitive.
    #[test]
    fn base32_decode_known_vectors() {
        assert_eq!(decode_base32("MFRGG===").unwrap(), b"abc");
        assert_eq!(decode_base32("mfrgg").unwrap(), b"abc");
        // `JBSWY3DPEHPK3PXP` is the canonical "Hello!\xde\xad\xbe\xef" sample.
        assert_eq!(
            decode_base32("JBSWY3DPEHPK3PXP").unwrap(),
            b"Hello!\xde\xad\xbe\xef"
        );
        // whitespace/dashes (display grouping) are ignored
        assert_eq!(decode_base32("MFRG G===").unwrap(), b"abc");
        // a non-base32 char is rejected
        assert!(decode_base32("0189!").is_err());
        assert!(decode_base32("").is_err());
    }

    // An `otpauth://` URI round-trips: secret + overridden params parse, and the
    // derived code matches the manual derivation from the same seed/params.
    #[test]
    fn otpauth_parse_round_trip() {
        // Base32 of the RFC SHA1 seed "12345678901234567890" is
        // "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".
        let uri = "otpauth://totp/ACME:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30";
        let parsed = parse_otpauth(uri).unwrap();
        assert_eq!(parsed.seed, sha1_seed());
        assert_eq!(parsed.params.algorithm, TotpAlgorithm::Sha1);
        assert_eq!(parsed.params.digits, 8);
        assert_eq!(parsed.params.period, 30);
        let code = code_at(
            &parsed.seed,
            59,
            parsed.params.algorithm,
            parsed.params.digits,
            parsed.params.period,
        )
        .unwrap();
        assert_eq!(code, "94287082");
    }

    // Defaults apply when the URI omits params; a bare base32 seed also defaults.
    #[test]
    fn otpauth_defaults_and_bare_seed() {
        let uri = "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let parsed = parse_otpauth(uri).unwrap();
        assert_eq!(parsed.params, TotpParams::default());

        let bare = parse_seed_input("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        assert_eq!(bare.seed, sha1_seed());
        assert_eq!(bare.params, TotpParams::default());
        // a 6-digit default code derives without error
        assert_eq!(bare.params.digits, 6);
    }

    #[test]
    fn parse_seed_input_routes_uri_vs_bare() {
        assert!(parse_seed_input("otpauth://totp/x?secret=MFRGG").is_ok());
        assert!(parse_seed_input("MFRGG").is_ok());
        // an hotp URI is refused (event-based, out of scope)
        assert!(parse_seed_input("otpauth://hotp/x?secret=MFRGG").is_err());
    }

    // `seconds_remaining` returns how many whole seconds are left in the current
    // window (`period - unix_secs % period`), in `1..=period`.
    #[test]
    fn seconds_remaining_counts_down_within_the_window() {
        // period=30: at t=59 the window [30,60) has 1s left; at t=60 a fresh
        // window opens with the full 30s; at t=75 the window [60,90) has 15s.
        assert_eq!(seconds_remaining(59, 30), 1);
        assert_eq!(seconds_remaining(60, 30), 30);
        assert_eq!(seconds_remaining(75, 30), 15);
        // The boundary instant always has the full period left, never 0.
        assert_eq!(seconds_remaining(0, 30), 30);
        assert_eq!(seconds_remaining(30, 30), 30);
        // A degenerate period yields 0 (guarded; code_at rejects it).
        assert_eq!(seconds_remaining(5, 0), 0);
    }

    // `returns_current` is the pure threshold for the `--min-validity N` path:
    // strictly more validity than N means "use the current code"; otherwise wait.
    #[test]
    fn returns_current_thresholds_on_min_validity() {
        // Strictly greater → use the current window's code.
        assert!(returns_current(30, 0));
        assert!(returns_current(11, 10));
        assert!(returns_current(2, 1));
        // Equal or less → must wait for the next window.
        assert!(!returns_current(10, 10));
        assert!(!returns_current(5, 10));
        assert!(!returns_current(0, 0));
        // `--min-validity 0` is always true for a real (>=1) remaining, so the
        // current code is returned deterministically with no boundary wait.
        for remaining in 1..=30 {
            assert!(returns_current(remaining, 0));
        }
    }

    #[test]
    fn rejects_degenerate_params() {
        assert!(code_at(b"seed", 0, TotpAlgorithm::Sha1, 6, 0).is_err()); // period 0
        assert!(code_at(b"seed", 0, TotpAlgorithm::Sha1, 0, 30).is_err()); // 0 digits
        assert!(code_at(b"seed", 0, TotpAlgorithm::Sha1, 10, 30).is_err()); // >9 digits
    }

    #[test]
    fn algorithm_parse_round_trips() {
        assert_eq!(TotpAlgorithm::parse("sha1").unwrap(), TotpAlgorithm::Sha1);
        assert_eq!(
            TotpAlgorithm::parse("SHA256").unwrap(),
            TotpAlgorithm::Sha256
        );
        assert_eq!(TotpAlgorithm::Sha512.as_str(), "SHA512");
        assert!(TotpAlgorithm::parse("md5").is_err());
    }
}
