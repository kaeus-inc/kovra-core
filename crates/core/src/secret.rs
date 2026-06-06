//! In-memory secret value: zeroized on drop, never printed.

use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A secret value held in protected memory.
///
/// Wraps [`secrecy::SecretBox`] so the bytes are zeroized on drop and never
/// appear in `Debug` output; there is **no** `Display` impl by design (I12).
/// The value is reachable only via [`SecretValue::expose`], which callers must
/// invoke deliberately.
///
/// The `serde` impls (de)serialize the raw bytes and exist **only** so a record
/// can be serialized into the buffer that is immediately AEAD-sealed (see
/// [`crate::crypto`]); the plaintext serialization is never persisted or logged.
pub struct SecretValue(SecretBox<Vec<u8>>);

impl SecretValue {
    /// Wrap raw secret bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    /// Borrow the protected bytes. Use deliberately — this is the one path out.
    pub fn expose(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl From<String> for SecretValue {
    fn from(s: String) -> Self {
        Self::new(s.into_bytes())
    }
}

impl From<&str> for SecretValue {
    fn from(s: &str) -> Self {
        Self::new(s.as_bytes().to_vec())
    }
}

/// Redacted `Debug`: never reveals the value (I12). No `Display` impl exists.
impl core::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretValue(REDACTED)")
    }
}

impl PartialEq for SecretValue {
    fn eq(&self, other: &Self) -> bool {
        self.expose() == other.expose()
    }
}

impl Serialize for SecretValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.expose().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SecretValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(Self::new(bytes))
    }
}
