//! `load_embedded_nested` recursion, exercised on synthetic components
//! built with `wasm-encoder` — no cargo-built fixtures needed.
//!
//! The catalogs are section bytes as embedding writes them (a bare array
//! for disclosure-fields, the slot and a `{language: {key: text}}` object
//! for i18n), embedded verbatim as custom sections — what wac fusion
//! preserves byte-for-byte.

use std::borrow::Cow;

use enclavid_embedded::{SECTION_DISCLOSURE_FIELDS, SECTION_I18N};
use engine_compiler::{catalog_hash, load_embedded, load_embedded_nested};
use wasm_encoder::{Component, CustomSection, NestedComponentSection};

const DF: &[u8] = b"[\"passport-number\"]";
const I18N: &[u8] = br#"{"slot":"policy","languages":{"en":{"title":"KYC"}}}"#;

/// A leaf component carrying the given embedded sections verbatim.
fn leaf(df: Option<&[u8]>, i18n: Option<&[u8]>) -> Component {
    let mut c = Component::new();
    for (name, data) in [(SECTION_DISCLOSURE_FIELDS, df), (SECTION_I18N, i18n)] {
        if let Some(bytes) = data {
            c.section(&CustomSection {
                name: Cow::Borrowed(name),
                data: Cow::Borrowed(bytes),
            });
        }
    }
    c
}

/// An outer component wrapping the given leaves as nested components —
/// the shape wac fusion produces (catalogs nested one level down).
fn wrap(leaves: &[&Component]) -> Vec<u8> {
    let mut outer = Component::new();
    for leaf in leaves {
        outer.section(&NestedComponentSection(leaf));
    }
    outer.finish()
}

#[test]
fn load_embedded_reads_top_level_sections_and_hash() {
    let bytes = leaf(Some(DF), Some(I18N)).finish();
    let cat = load_embedded(&bytes).expect("load");
    assert_eq!(cat.hash, catalog_hash(Some(DF), Some(I18N)));
    assert!(cat.decls.disclosure_fields.contains("passport-number"));
    assert!(cat.texts["en"].contains_key("title"));
    assert_eq!(cat.slot.as_deref(), Some("policy"));
    assert!(!cat.is_policy);
}

/// A catalog breaking the format is refused where it is read: texts that are
/// not text by key, a key of another shape, texts with no slot or a slot of
/// another shape than a package's name, and a disclosure field of another
/// shape than a key's.
#[test]
fn a_catalog_breaking_the_format_is_refused() {
    for (df, i18n) in [
        (
            None,
            Some(&br#"{"slot":"policy","languages":{"en":"title = KYC"}}"#[..]),
        ),
        (
            None,
            Some(&br#"{"slot":"policy","languages":{"en":{"Title":"KYC"}}}"#[..]),
        ),
        (None, Some(&br#"{"languages":{"en":{"title":"KYC"}}}"#[..])),
        (None, Some(&br#"{"slot":"Not A Slot","languages":{}}"#[..])),
        (Some(&b"[\"Passport Number\"]"[..]), None),
    ] {
        let refused = load_embedded(&leaf(df, i18n).finish())
            .err()
            .expect("refused");
        assert!(
            refused.is::<engine_compiler::CatalogRefused>(),
            "{refused:?}"
        );
    }
}

#[test]
fn nested_single_leaf_recovered() {
    let inner = leaf(Some(DF), Some(I18N));
    let fused = wrap(&[&inner]);

    let cats = load_embedded_nested(&fused).expect("nested");
    assert_eq!(cats.len(), 1, "one leaf → one catalog");
    assert_eq!(cats[0].hash, catalog_hash(Some(DF), Some(I18N)));
    assert!(cats[0].decls.disclosure_fields.contains("passport-number"));
}

#[test]
fn nested_multiple_leaves_each_recovered() {
    let a = leaf(Some(DF), None);
    let b = leaf(None, Some(I18N));
    let fused = wrap(&[&a, &b]);

    let cats = load_embedded_nested(&fused).expect("nested");
    assert_eq!(cats.len(), 2, "two leaves → two catalogs");

    let hashes: Vec<[u8; 32]> = cats.iter().map(|c| c.hash).collect();
    assert!(hashes.contains(&catalog_hash(Some(DF), None)));
    assert!(hashes.contains(&catalog_hash(None, Some(I18N))));
}

#[test]
fn empty_wrapper_is_not_a_catalog() {
    // An outer component that wraps a section-carrying leaf AND a
    // section-less leaf: only the one with sections is a catalog. The
    // outer wrapper itself (no sections) is never emitted.
    let real = leaf(Some(DF), None);
    let empty = leaf(None, None);
    let fused = wrap(&[&real, &empty]);

    let cats = load_embedded_nested(&fused).expect("nested");
    assert_eq!(cats.len(), 1, "only the section-carrying leaf is a catalog");
    assert_eq!(cats[0].hash, catalog_hash(Some(DF), None));
}

#[test]
fn non_fused_component_yields_its_single_catalog() {
    // load_embedded_nested on a plain (non-fused) component returns its
    // own top-level catalog — the same shape the dynamic path sees.
    let bytes = leaf(Some(DF), Some(I18N)).finish();
    let cats = load_embedded_nested(&bytes).expect("nested");
    assert_eq!(cats.len(), 1);
    assert_eq!(cats[0].hash, catalog_hash(Some(DF), Some(I18N)));
}
