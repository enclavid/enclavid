//! Extract and parse a policy's "embedded" sections — the embedded
//! `enclavid:embedded.*` declarations a component ships inside its
//! wasm:
//!
//!   * `enclavid:embedded.disclosure-fields.v1` — machine identifier
//!     list, surfaces as `DisplayField.key` in `prompt-disclosure`.
//!   * `enclavid:embedded.i18n.v1` — translation catalog for UI refs.
//!
//! Both sections are **independently optional**. A component that
//! ships neither is valid — it just trades the safety of registry
//! membership for nothing, and any call that passes a key the engine
//! never saw declared will trap at use site via
//! `sanitize::ensure_registered`. No load-time atomicity requirement:
//! missing sections are simply absent from the union.
//!
//! The OCI annotation `com.enclavid.component.kind` (set by
//! `enclavid policy push`) discriminates policy vs plugin before the
//! layer is ever pulled; this loader doesn't see that field anymore
//! (it used to live in the JSON we parsed here).

use std::collections::{HashMap, HashSet};

use enclavid_embedded::{
    SECTION_DISCLOSURE_FIELDS, SECTION_I18N,
    parse_disclosure_fields, parse_i18n,
};

use super::registry::{ComponentDecls, Translation};
use crate::limits::MAX_TEXT_ENTRIES;

/// Walk the component-level custom sections of a wasm component
/// binary, look up our two embedded sections, parse whichever are
/// present, and project into [`ComponentDecls`].
///
/// `wasm_bytes` is the (decrypted) policy or plugin wasm — caller
/// already pulled and unwrapped any age-encrypted layer. We don't
/// reach for wasmtime here: `wasmparser` walks the component's outer
/// payloads without compiling anything, which is enough to extract
/// custom sections by name.
pub fn load_embedded(wasm_bytes: &[u8]) -> wasmtime::Result<ComponentDecls> {
    let mut disclosure_section = None;
    let mut i18n_section = None;

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
                        "duplicate custom section `{n}` in component wasm",
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
                        "duplicate custom section `{n}` in component wasm",
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
    // malicious or malformed component from blowing up registry
    // state. Per-translation byte sizes bounded separately by the
    // transport-level cap on the wasm layer in `policy_pull`.
    let df_count = disclosure_section.as_ref().map(|d| d.fields.len()).unwrap_or(0);
    let l_count = i18n_section.as_ref().map(|i| i.entries.len()).unwrap_or(0);
    let total = df_count + l_count;
    if total > MAX_TEXT_ENTRIES {
        return Err(wasmtime::Error::msg(format!(
            "component declares {total} embedded entries, max is {MAX_TEXT_ENTRIES}",
        )));
    }

    // Disclosure fields: HashSet collapses any in-list duplicates
    // (JSON arrays allow them, but the registry's membership is
    // set-typed and would have the same effect).
    let disclosure_fields: HashSet<String> = disclosure_section
        .map(|s| s.fields.into_iter().collect())
        .unwrap_or_default();

    // i18n: `entries` is a BTreeMap<key, BTreeMap<lang, text>> — JSON
    // object keys are unique by construction. We flatten the inner
    // map into `Vec<Translation>` so the consumer sees translation
    // rows in a fixed iteration shape; per-language uniqueness is
    // guaranteed by the inner map. Sanitisation of the text values
    // is deferred to the consumer (api views call
    // `sanitize_text_value` after locale picking).
    let localized: HashMap<String, Vec<Translation>> = i18n_section
        .map(|i| i.entries)
        .unwrap_or_default()
        .into_iter()
        .map(|(key, translations)| {
            let rows: Vec<Translation> = translations
                .into_iter()
                .map(|(language, text)| Translation { language, text })
                .collect();
            (key, rows)
        })
        .collect();

    Ok(ComponentDecls {
        disclosure_fields,
        localized,
    })
}
