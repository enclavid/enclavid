//! The cap on a composition's embedded sections, held where the compile
//! boundary reads them: summed over the policy and every plugin, at every
//! nesting depth, and before any of them is parsed.

use std::borrow::Cow;

use enclavid_embedded::{SECTION_I18N, SECTION_ICONS};
use engine_compiler::{CatalogRefused, Compiler};
use engine_types::composition::PluginInstance;
use engine_types::limits::MAX_EMBEDDED_SECTION_BYTES;
use wasm_encoder::{Component, CustomSection, NestedComponentSection};

const CAP: usize = MAX_EMBEDDED_SECTION_BYTES as usize;

/// A component carrying `len` bytes of an embedded section that is not JSON at
/// all — so a refusal for its size proves nothing parsed it first.
fn carrying(name: &str, len: usize) -> Component {
    let mut c = Component::new();
    c.section(&CustomSection {
        name: Cow::Borrowed(name),
        data: Cow::Owned(vec![b'x'; len]),
    });
    c
}

/// Why the compile refused the composition — every one here is, its sections
/// not being JSON — so which rule refused it says whether the cap came first.
fn refusal(policy: &[u8], plugins: &[PluginInstance]) -> CatalogRefused {
    match Compiler::new()
        .expect("compiler")
        .compile_to_parts(policy, plugins)
    {
        Ok(_) => panic!("sections that are not JSON must not compile"),
        Err(e) => *e
            .downcast_ref::<CatalogRefused>()
            .unwrap_or_else(|| panic!("sections that are not JSON are refused, got {e:?}")),
    }
}

fn refused(policy: &[u8], plugins: &[PluginInstance]) -> bool {
    refusal(policy, plugins) == CatalogRefused::PastCap
}

#[test]
fn one_byte_past_the_cap_is_refused_before_any_section_is_parsed() {
    assert!(refused(&carrying(SECTION_I18N, CAP + 1).finish(), &[]));
}

#[test]
fn the_cap_is_on_the_composition_not_on_each_component() {
    let plugin = PluginInstance {
        package: "enclavid:p".into(),
        wasm: carrying(SECTION_ICONS, CAP / 2 + 1).finish(),
    };
    assert!(refused(
        &carrying(SECTION_I18N, CAP / 2).finish(),
        &[plugin]
    ));
}

#[test]
fn a_pre_fused_policy_counts_its_nested_catalogs() {
    let mut outer = Component::new();
    outer.section(&NestedComponentSection(&carrying(SECTION_I18N, CAP / 2)));
    outer.section(&NestedComponentSection(&carrying(
        SECTION_I18N,
        CAP / 2 + 1,
    )));
    assert!(refused(&outer.finish(), &[]));
}

/// At the cap the compile goes on, and refuses where it always would: on the
/// sections not being JSON.
#[test]
fn sections_at_the_cap_are_parsed_as_ever() {
    assert_eq!(
        refusal(&carrying(SECTION_I18N, CAP).finish(), &[]),
        CatalogRefused::Invalid
    );
}
