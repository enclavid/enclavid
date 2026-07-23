//! [`SecretBytes`] — a secret byte string that MUST be serialized.
//!
//! `secrecy::SecretBox` gives zeroize-on-drop + `Debug`-redaction but DELIBERATELY
//! refuses to implement `Serialize` (serializing a secret is a footgun the crate won't
//! enable). That is exactly the property we cannot have for a secret that rides a wire
//! format — e.g. the ocicrypt layer key, which the CLI writes into an OCI annotation and
//! a KBS releases to the TEE. `SecretBytes` is the "serializable secrecy": same
//! zeroize-on-drop + redacted `Debug`, but it DOES serialize (as a base64 string, the
//! ocicrypt encoding). Reach for `secrecy::SecretBox` for a secret that never leaves
//! memory; reach for `SecretBytes` only when the format forces you to serialize one.

use core::fmt;

use base64ct::{Base64, Encoding};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

/// A `Vec<u8>` secret with zeroize-on-drop, redacted `Debug`, and base64 serde. See the
/// module docs for when to use this vs `secrecy::SecretBox`.
#[derive(Clone)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wrap owned secret bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the secret bytes. Named `expose` (mirroring
    /// `secrecy::ExposeSecret::expose_secret`) so every read is an explicit,
    /// greppable acknowledgement that a secret is being handled.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the bytes — the whole point.
        f.write_str("SecretBytes([REDACTED])")
    }
}

impl Serialize for SecretBytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Base64 string — the ocicrypt annotation encoding, and a safe default for the
        // text/JSON formats this rides today.
        s.serialize_str(&Base64::encode_string(&self.0))
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Base64::decode_vec(&s).map(Self).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts() {
        let s = SecretBytes::from(vec![1, 2, 3, 4]);
        assert_eq!(format!("{s:?}"), "SecretBytes([REDACTED])");
    }

    #[test]
    fn base64_round_trips() {
        let s = SecretBytes::from(b"a 32-byte-ish secret key value!!".to_vec());
        let json = serde_json::to_string(&s).unwrap();
        // Serializes as a quoted base64 string, not a byte array.
        assert!(json.starts_with('"') && json.ends_with('"'));
        let back: SecretBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expose(), s.expose());
    }
}
