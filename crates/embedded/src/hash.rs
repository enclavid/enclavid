//! Content-hash of a component's embedded catalog: what the registry keeps a
//! catalog under, so byte-identical catalogs are one.
//!
//! The hash is over the RAW section payloads, exactly as embedded. wac fusion
//! preserves custom sections byte-for-byte, so every reader of a catalog — in
//! a plugin's sections, or nested in a fused artifact — agrees on it with no
//! parsing or canonicalization.

/// Domain tag mixed into every hash so a future change to the input
/// framing can't collide with an existing hash.
const VERSION: &[u8] = b"enclavid:embedded-catalog:v1";

/// Content-hash of a component's embedded catalog over the raw section
/// payloads, in fixed kind order (disclosure-fields, i18n). Each
/// section is tagged present/absent and length-prefixed, so an absent
/// section differs from an empty one and no section's bytes can be
/// mistaken for another's.
pub fn catalog_hash(disclosure_fields: Option<&[u8]>, i18n: Option<&[u8]>) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(VERSION);
    for section in [disclosure_fields, i18n] {
        match section {
            Some(bytes) => {
                h.update(&[1u8]);
                h.update(&(bytes.len() as u64).to_le_bytes());
                h.update(bytes);
            }
            None => {
                h.update(&[0u8]);
            }
        }
    }
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_bytes_identical_hash() {
        let a = catalog_hash(Some(b"{\"df\":1}"), Some(b"{\"i\":2}"));
        let b = catalog_hash(Some(b"{\"df\":1}"), Some(b"{\"i\":2}"));
        assert_eq!(a, b);
    }

    #[test]
    fn absent_differs_from_empty() {
        assert_ne!(catalog_hash(None, None), catalog_hash(Some(b""), Some(b"")));
    }

    #[test]
    fn section_position_not_confused() {
        // The same bytes as the DF section vs the i18n section must hash
        // differently — length prefixes + fixed order keep the two
        // section namespaces disjoint.
        assert_ne!(
            catalog_hash(Some(b"x"), None),
            catalog_hash(None, Some(b"x"))
        );
    }

    #[test]
    fn content_sensitive() {
        let base = catalog_hash(Some(b"{\"title\":\"KYC\"}"), None);
        let diff = catalog_hash(Some(b"{\"title\":\"AML\"}"), None);
        assert_ne!(base, diff);
    }
}
