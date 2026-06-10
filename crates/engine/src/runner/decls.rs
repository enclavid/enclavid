//! Extract and parse a policy's "embedded" sections — the static
//! text-ref declarations a component ships inside its wasm:
//!
//!   * `enclavid:embedded.disclosure-fields.v1` — machine identifier
//!     list, surfaces as `DisplayField.key` in `prompt-disclosure`.
//!   * `enclavid:embedded.i18n.v1` — translation catalog for UI refs.
//!
//! Both sections are **independently optional**. A component that
//! ships neither is valid — it just trades the safety of the
//! `registered_text_refs` membership check for nothing, and any call
//! that passes a key the engine never saw declared will trap at use
//! site via `sanitize::ensure_registered`. No load-time atomicity
//! requirement: missing sections are simply absent from the union.
//!
//! The OCI annotation `com.enclavid.component.kind` (set by
//! `enclavid policy push`) discriminates policy vs plugin before the
//! layer is ever pulled; this loader doesn't see that field anymore
//! (it used to live in the JSON we parsed here).

use std::collections::HashSet;

use enclavid_embedded::{
    DisclosureFieldsSection, I18nSection, SECTION_DISCLOSURE_FIELDS, SECTION_I18N,
    parse_disclosure_fields, parse_i18n,
};

use crate::limits::MAX_TEXT_ENTRIES;

/// Output of [`load_static`]. Two pre-split classes match what the
/// api crate's `TextRegistry` consumes:
///
///   * `identifiers` — pure machine keys (registered for
///     membership-check only, never resolved to user-facing text).
///   * `localized` — one `LocalizedDecl` per key, carrying its full
///     translation set. `TextRegistry::from_decls` indexes these by
///     key and the host membership-check union is
///     `identifiers ∪ localized.keys`.
#[derive(Debug, Default)]
pub struct TextDecls {
    pub identifiers: Vec<String>,
    pub localized: Vec<LocalizedDecl>,
}

#[derive(Debug)]
pub struct LocalizedDecl {
    pub key: String,
    /// `(language, value)` rows. Per-language uniqueness is a
    /// policy-authoring discipline, not enforced by the type — the
    /// host can later trap on duplicates during registry build.
    pub translations: Vec<(String, String)>,
}

/// Walk the component-level custom sections of a wasm component
/// binary, look up our two embedded sections, parse whichever are
/// present, and project into [`TextDecls`].
///
/// `wasm_bytes` is the (decrypted) policy wasm — caller already
/// pulled and unwrapped any age-encrypted layer. We don't reach for
/// wasmtime here: `wasmparser` walks the component's outer payloads
/// without compiling anything, which is enough to extract custom
/// sections by name.
pub fn load_static(wasm_bytes: &[u8]) -> wasmtime::Result<TextDecls> {
    let mut disclosure_section: Option<DisclosureFieldsSection> = None;
    let mut i18n_section: Option<I18nSection> = None;

    use wasmparser::{Parser, Payload};
    for payload in Parser::new(0).parse_all(wasm_bytes) {
        let payload = payload.map_err(|e| {
            wasmtime::Error::msg(format!("wasm component parse: {e}"))
        })?;
        let Payload::CustomSection(reader) = payload else {
            continue;
        };
        match reader.name() {
            n if n == SECTION_DISCLOSURE_FIELDS => {
                if disclosure_section.is_some() {
                    return Err(wasmtime::Error::msg(format!(
                        "duplicate custom section `{n}` in policy wasm",
                    )));
                }
                disclosure_section = Some(parse_disclosure_fields(reader.data()).map_err(
                    |e| {
                        wasmtime::Error::msg(format!(
                            "parsing custom section `{n}` as JSON: {e}",
                        ))
                    },
                )?);
            }
            n if n == SECTION_I18N => {
                if i18n_section.is_some() {
                    return Err(wasmtime::Error::msg(format!(
                        "duplicate custom section `{n}` in policy wasm",
                    )));
                }
                i18n_section = Some(parse_i18n(reader.data()).map_err(|e| {
                    wasmtime::Error::msg(format!(
                        "parsing custom section `{n}` as JSON: {e}",
                    ))
                })?);
            }
            _ => {}
        }
    }

    // Memory bound — independent of per-entry validation. Stops a
    // malicious or malformed component from blowing up TextRegistry
    // state. Per-translation byte sizes bounded separately by the
    // transport-level cap on the wasm layer in `policy_pull`.
    let identifier_count =
        disclosure_section.as_ref().map(|d| d.fields.len()).unwrap_or(0);
    let localized_count = i18n_section.as_ref().map(|i| i.entries.len()).unwrap_or(0);
    let total = identifier_count + localized_count;
    if total > MAX_TEXT_ENTRIES {
        return Err(wasmtime::Error::msg(format!(
            "policy declares {total} embedded entries, max is {MAX_TEXT_ENTRIES}",
        )));
    }

    // Disclosure fields: dedupe within the list (JSON allows
    // duplicates in arrays — collapse here so the membership set
    // doesn't accidentally double-count). Overlap with i18n is
    // permitted by design.
    let mut seen_disclosure: HashSet<String> = HashSet::new();
    let identifiers: Vec<String> = disclosure_section
        .map(|s| s.fields)
        .unwrap_or_default()
        .into_iter()
        .filter(|key| seen_disclosure.insert(key.clone()))
        .collect();

    // `i18n.entries` is a BTreeMap (JSON object keys unique by
    // construction). Push verbatim — format / language / length /
    // sanitisation deferred to `TextRegistry::resolve_string`.
    let localized: Vec<LocalizedDecl> = i18n_section
        .map(|i| i.entries)
        .unwrap_or_default()
        .into_iter()
        .map(|(key, translations)| LocalizedDecl {
            key,
            translations: translations.into_iter().collect(),
        })
        .collect();

    Ok(TextDecls { identifiers, localized })
}
