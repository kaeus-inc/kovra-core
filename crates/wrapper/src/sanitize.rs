//! Output sanitization — the **margin defense** of §5.1.
//!
//! After a child runs, the Wrapper may mask any verbatim occurrence of an
//! injected secret value in the child's stdout/stderr before returning it to the
//! caller (and thence, possibly, to the agent). This catches *naive*
//! exfiltration — `print(os.environ['DB_PASSWORD'])` — and nothing more.
//!
//! **This is a net, never a boundary.** It does not catch obfuscated
//! exfiltration (base64, reversal, splitting, encryption) and must never be
//! presented as security. The real containment for `high`/`prod` is the executor
//! allowlist (§5.1, I15) plus the attended prompt that shows the resolved
//! command — not this masking.

/// The replacement written in place of a matched secret value.
pub const MASK: &[u8] = b"***";

/// Return a copy of `data` with every verbatim occurrence of each value in
/// `secrets` replaced by [`MASK`]. Empty secrets are skipped (they would match
/// everywhere).
pub fn mask_secrets(data: &[u8], secrets: &[&[u8]]) -> Vec<u8> {
    let mut out = data.to_vec();
    for secret in secrets {
        if secret.is_empty() {
            continue;
        }
        out = replace_bytes(&out, secret, MASK);
    }
    out
}

/// Replace every non-overlapping occurrence of `needle` in `haystack` with `rep`.
fn replace_bytes(haystack: &[u8], needle: &[u8], rep: &[u8]) -> Vec<u8> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if i + needle.len() <= haystack.len() && &haystack[i..i + needle.len()] == needle {
            out.extend_from_slice(rep);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_naive_occurrences() {
        let out = mask_secrets(b"connecting with hunter2 now", &[b"hunter2"]);
        assert_eq!(out, b"connecting with *** now");
        assert!(!String::from_utf8_lossy(&out).contains("hunter2"));
    }

    #[test]
    fn masks_multiple_secrets_and_repeats() {
        let out = mask_secrets(b"a=AAA b=BBB a=AAA", &[b"AAA", b"BBB"]);
        assert_eq!(out, b"a=*** b=*** a=***");
    }

    #[test]
    fn empty_secret_is_ignored() {
        let out = mask_secrets(b"untouched", &[b""]);
        assert_eq!(out, b"untouched");
    }

    #[test]
    fn does_not_catch_obfuscated_exfiltration() {
        // Documents the limitation: base64 of the secret slips through (by design;
        // this is a net, not a boundary).
        let out = mask_secrets(b"aHVudGVyMg==", &[b"hunter2"]);
        assert_eq!(out, b"aHVudGVyMg==");
    }
}
