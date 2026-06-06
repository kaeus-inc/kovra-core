//! Truncated value fingerprint (spec §10.4).
//!
//! A short hash of a **literal** secret value, so an operator can verify "did I
//! update to the right value?" without revealing it. Deliberately **truncated**
//! (leading bytes of BLAKE3) so it cannot ease brute-forcing the value, and so
//! it is safe to store in the index and surface in `list`/`doctor` output
//! (I12). It is never the full hash.
//!
//! References carry no value, so they have no fingerprint.

/// Number of leading BLAKE3 bytes kept in a fingerprint. Truncated on purpose
/// (§10.4): enough to detect a change, too short to brute-force the value.
pub const FINGERPRINT_BYTES: usize = 4;

/// Truncated, lowercase-hex BLAKE3 fingerprint of a literal value.
///
/// Deterministic and stable across runs (no salt, no nonce) — re-fingerprinting
/// the same bytes always yields the same string, which is what makes "did the
/// value change?" answerable without the value. The output is
/// `FINGERPRINT_BYTES * 2` hex characters.
pub fn fingerprint(value: &[u8]) -> String {
    // `to_hex()` is BLAKE3's own lowercase-hex encoder (the same path
    // `Coordinate::storage_id` uses); take the truncated prefix.
    blake3::hash(value).to_hex()[..FINGERPRINT_BYTES * 2].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_stable_across_calls() {
        assert_eq!(fingerprint(b"hunter2"), fingerprint(b"hunter2"));
    }

    #[test]
    fn differs_for_different_values() {
        assert_ne!(fingerprint(b"hunter2"), fingerprint(b"hunter3"));
    }

    #[test]
    fn is_truncated_not_full_hash() {
        let fp = fingerprint(b"hunter2");
        // Exactly the truncated width — never the full 32-byte BLAKE3 digest.
        assert_eq!(fp.len(), FINGERPRINT_BYTES * 2);
        let full = blake3::hash(b"hunter2").to_hex().to_string();
        assert_ne!(fp.len(), full.len());
        // The fingerprint is a strict prefix of the full hex digest.
        assert!(full.starts_with(&fp));
    }

    #[test]
    fn is_lowercase_hex() {
        let fp = fingerprint(b"\x00\xff\x10\xab");
        assert!(
            fp.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }
}
