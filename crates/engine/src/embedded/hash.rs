//! Content-hash of a component's embedded catalog.
//!
//! Under strict per-component embedded routing (i18n / icons), each
//! component's `enclavid:embedded/{i18n,icons}` import is wired to a
//! DISTINCT composite import named by the hash of that component's
//! catalog — `embedded-slot:<slug>/i18n`. [`catalog_hash`] is that
//! hash, [`slug`] its wire form.
//!
//! The hash is over the RAW section payloads — exactly the author's
//! `disclosure-fields.json` / `i18n.json` / `icons.json` bytes.
//! `enclavid {policy,plugin} embed` writes those files verbatim as the
//! custom-section data (see `crates/cli/src/embed.rs` —
//! `Cow::Borrowed(bytes)`, no re-serialization), and wac fusion
//! preserves custom sections byte-for-byte. So the identical bytes
//! reach every producer that needs the hash — the author-time file,
//! the engine reading a plugin's section, the engine reading a nested
//! section inside a fused artifact — and they all agree with no
//! parsing or canonicalization.

/// Domain tag mixed into every hash so a future change to the input
/// framing can't collide with an existing slug.
const VERSION: &[u8] = b"enclavid:embedded-catalog:v1";

/// Content-hash of a component's embedded catalog over the raw section
/// payloads, in fixed kind order (disclosure-fields, i18n, icons).
/// Each section is tagged present/absent and length-prefixed, so an
/// absent section differs from an empty one and no section's bytes can
/// be mistaken for another's.
pub fn catalog_hash(
    disclosure_fields: Option<&[u8]>,
    i18n: Option<&[u8]>,
    icons: Option<&[u8]>,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(VERSION);
    for section in [disclosure_fields, i18n, icons] {
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

/// Wire form of a catalog hash: a `'h'` letter followed by the first
/// 16 bytes as 32 lowercase-hex characters (33 chars total). Used as
/// the package segment of the distinct import name
/// `embedded-slot:<slug>/<iface>`. The leading letter is required —
/// a WIT/component name segment can't start with a digit, and a hex
/// slug can. 128 bits of hash: a collision between two DISTINCT
/// catalogs is negligible; byte-identical catalogs intentionally share
/// a slug (they route to one instance, which is correct — identical
/// content resolves the same).
pub fn slug(hash: &[u8; 32]) -> String {
    let mut s = String::with_capacity(33);
    s.push('h');
    use std::fmt::Write;
    for b in &hash[..16] {
        write!(s, "{b:02x}").expect("write into String never fails");
    }
    s
}

/// The distinct composite import name a component's
/// `enclavid:embedded/<iface>` import is routed to under strict
/// per-component routing: `embedded-slot:<slug>/<iface>`. Versionless
/// and in its own `embedded-slot` namespace so wac's aggregator never
/// merges it with the versioned `enclavid:embedded/<iface>@x.y` import
/// or with another catalog's slot. `iface` is `"i18n"` or `"icons"`.
pub fn embedded_import_name(hash: &[u8; 32], iface: &str) -> String {
    format!("embedded-slot:{}/{}", slug(hash), iface)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_bytes_identical_hash() {
        let a = catalog_hash(Some(b"{\"df\":1}"), Some(b"{\"i\":2}"), Some(b"[\"ic\"]"));
        let b = catalog_hash(Some(b"{\"df\":1}"), Some(b"{\"i\":2}"), Some(b"[\"ic\"]"));
        assert_eq!(a, b);
    }

    #[test]
    fn absent_differs_from_empty() {
        assert_ne!(
            catalog_hash(None, None, None),
            catalog_hash(Some(b""), Some(b""), Some(b"")),
        );
    }

    #[test]
    fn section_position_not_confused() {
        // The same bytes in the DF slot vs the i18n slot must hash
        // differently — length prefixes + fixed order keep the three
        // section namespaces disjoint.
        assert_ne!(
            catalog_hash(Some(b"x"), None, None),
            catalog_hash(None, Some(b"x"), None),
        );
    }

    #[test]
    fn content_sensitive() {
        let base = catalog_hash(Some(b"{\"title\":\"KYC\"}"), None, None);
        let diff = catalog_hash(Some(b"{\"title\":\"AML\"}"), None, None);
        assert_ne!(base, diff);
    }

    #[test]
    fn slug_is_letter_then_32_lowercase_hex() {
        let s = slug(&catalog_hash(None, None, None));
        assert_eq!(s.len(), 33);
        let mut chars = s.chars();
        assert_eq!(chars.next(), Some('h')); // must start with a letter, not a digit
        assert!(chars.all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn import_name_is_versionless_embedded_slot() {
        let name = embedded_import_name(&catalog_hash(Some(b"x"), None, None), "i18n");
        assert!(name.starts_with("embedded-slot:h"));
        assert!(name.ends_with("/i18n"));
        assert!(!name.contains('@')); // off the semver track so wac won't re-merge
    }
}
