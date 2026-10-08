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
    SECTION_DISCLOSURE_FIELDS, SECTION_I18N, SECTION_ICONS, parse_disclosure_fields, parse_i18n,
    parse_icons,
};
use wasmparser::{Parser, Payload};

use engine_types::embedded::{ComponentDecls, Translation};
use engine_types::limits::{
    MAX_DECLARED_DISCLOSURE_FIELDS, MAX_DECLARED_ICONS, MAX_DECLARED_LOCALIZED,
};

use crate::hash::catalog_hash;

/// WIT interface a component exports iff it is the POLICY (not a
/// plugin). Matched by prefix so a version bump doesn't break policy
/// attribution in a fused artifact.
const POLICY_EXPORT_PREFIX: &str = "enclavid:policy/policy";

/// A single component's embedded catalog plus its identity. `hash` is
/// the content-hash of the raw section bytes ([`catalog_hash`]) — the
/// name each component's `enclavid:embedded/*` import is routed to
/// under strict per-component routing, and the key the registry stores
/// the catalog under. `is_policy` is true iff the component exports
/// `enclavid:policy/policy` (used to attribute the policy slot when
/// recovering catalogs from a fused artifact, where nesting order is
/// not meaningful).
pub struct EmbeddedCatalog {
    pub is_policy: bool,
    pub decls: ComponentDecls,
    pub hash: [u8; 32],
}

/// Load one component's embedded catalog from the top-level custom
/// sections of a wasm component binary. For a NON-fused policy or
/// plugin this is the whole story; a component that ships no embedded
/// sections yields an empty catalog. A fused artifact carries its
/// catalogs NESTED — use [`load_embedded_nested`] for those.
///
/// `wasm_bytes` is the (decrypted) policy or plugin wasm — caller
/// already pulled and unwrapped any age-encrypted layer. We don't
/// reach for wasmtime here: `wasmparser` walks the component's outer
/// payloads without compiling anything, which is enough to extract
/// custom sections by name and spot the policy export.
pub fn load_embedded(wasm_bytes: &[u8]) -> wasmtime::Result<EmbeddedCatalog> {
    // `parse_all` descends into nested components (flat stream with
    // ComponentSection/End as depth markers), so restrict absorption to
    // depth 0 — the component's OWN top-level sections. A non-fused
    // policy/plugin never nests, so this is just its catalog.
    let mut frame = RawFrame::default();
    let mut depth = 0usize;
    for payload in Parser::new(0).parse_all(wasm_bytes) {
        let payload =
            payload.map_err(|e| wasmtime::Error::msg(format!("wasm component parse: {e}")))?;
        match &payload {
            Payload::ComponentSection { .. } | Payload::ModuleSection { .. } => depth += 1,
            Payload::End(_) => depth = depth.saturating_sub(1),
            other if depth == 0 => frame.absorb(other)?,
            _ => {}
        }
    }
    frame.finish()
}

/// Recover every embedded catalog from a (possibly) fused artifact.
/// Descends into nested sub-components — under wac fusion each original
/// policy/plugin becomes a nested component carrying its own embedded
/// sections. Returns one [`EmbeddedCatalog`] per component that ships
/// at least one embedded section (empty wrappers are skipped). Works
/// on a non-fused component too (returns its single catalog, if any).
pub fn load_embedded_nested(wasm_bytes: &[u8]) -> wasmtime::Result<Vec<EmbeddedCatalog>> {
    // `parse_all` yields a flat stream across all nesting levels with
    // ComponentSection/ModuleSection as descend markers and End as the
    // ascend marker. Maintain a frame per open component/module: push
    // on descend, pop + emit on ascend, absorb everything else into the
    // current frame. Each frame collects only its OWN sections, so
    // catalogs are correctly attributed per component.
    let mut out = Vec::new();
    let mut stack: Vec<RawFrame> = vec![RawFrame::default()];
    for payload in Parser::new(0).parse_all(wasm_bytes) {
        let payload =
            payload.map_err(|e| wasmtime::Error::msg(format!("wasm component parse: {e}")))?;
        match &payload {
            Payload::ComponentSection { .. } | Payload::ModuleSection { .. } => {
                if stack.len() > MAX_NESTING {
                    return Err(invalid(format!(
                        "component nesting exceeds {MAX_NESTING} levels",
                    )));
                }
                stack.push(RawFrame::default());
            }
            Payload::End(_) => {
                if let Some(frame) = stack.pop() {
                    if !frame.is_empty() {
                        out.push(frame.finish()?);
                    }
                }
            }
            other => {
                if let Some(frame) = stack.last_mut() {
                    frame.absorb(other)?;
                }
            }
        }
    }
    Ok(out)
}

/// Max component nesting we'll descend. `wac plug` output is depth 1;
/// a re-fused hybrid core adds one more. A generous bound guards
/// against pathological inputs without constraining real artifacts.
const MAX_NESTING: usize = 8;

/// Why a composition's embedded catalogs are not accepted.
///
/// Its own type, carried inside the `wasmtime::Error` the loaders and
/// [`Compiler::compile_to_parts`](crate::Compiler::compile_to_parts) return, with
/// what broke as the error's context. These are the failures this crate can tell
/// are the composition's: each is a rule of the catalog format, checked against
/// the pinned bytes before anything is fused, so the same pins meet it every
/// time. The compile child looks for it there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogRefused {
    /// The embedded sections, summed over the policy and every plugin, are past
    /// `MAX_EMBEDDED_SECTION_BYTES`. Decided on lengths, before any is parsed.
    PastCap,
    /// One catalog breaks its format: a section repeated in one component, one
    /// that does not parse, one declaring past a `MAX_DECLARED_*` count, or
    /// catalogs nested deeper than the loader descends.
    Invalid,
}

impl std::fmt::Display for CatalogRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CatalogRefused::PastCap => "the composition's embedded catalogs are past their cap",
            CatalogRefused::Invalid => "an embedded catalog breaks its format",
        })
    }
}
impl std::error::Error for CatalogRefused {}

/// A [`CatalogRefused::Invalid`], with `cause` as its context for the debug log.
fn invalid(cause: String) -> wasmtime::Error {
    wasmtime::Error::new(CatalogRefused::Invalid).context(cause)
}

/// The raw bytes of every embedded section in `wasm_bytes` — its own and every
/// nested component's and module's — summed. Lengths only: nothing is parsed,
/// so this can run before anything that parses does. Every depth, because a
/// pre-fused policy's nested catalogs are parsed too ([`load_embedded_nested`]).
pub(crate) fn embedded_section_bytes(wasm_bytes: &[u8]) -> wasmtime::Result<u64> {
    let mut total = 0u64;
    for payload in Parser::new(0).parse_all(wasm_bytes) {
        let payload =
            payload.map_err(|e| wasmtime::Error::msg(format!("wasm component parse: {e}")))?;
        if let Payload::CustomSection(reader) = &payload {
            let name = reader.name();
            if name == SECTION_DISCLOSURE_FIELDS || name == SECTION_I18N || name == SECTION_ICONS {
                total += reader.data().len() as u64;
            }
        }
    }
    Ok(total)
}

/// The import names of a component's OWN (top-level) world. Used to
/// recover the `embedded-slot:<hash>/<iface>` imports a pre-fused
/// artifact already carries, so the host `Linker` can re-register them
/// (static / hybrid consumption). Depth-0 only — nested components'
/// imports are internal and already satisfied.
pub fn top_level_imports(wasm_bytes: &[u8]) -> wasmtime::Result<Vec<String>> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    for payload in Parser::new(0).parse_all(wasm_bytes) {
        let payload =
            payload.map_err(|e| wasmtime::Error::msg(format!("wasm component parse: {e}")))?;
        match &payload {
            Payload::ComponentSection { .. } | Payload::ModuleSection { .. } => depth += 1,
            Payload::End(_) => depth = depth.saturating_sub(1),
            Payload::ComponentImportSection(reader) if depth == 0 => {
                for import in reader.clone() {
                    let import = import.map_err(|e| {
                        wasmtime::Error::msg(format!("component import parse: {e}"))
                    })?;
                    out.push(import.name.0.to_string());
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

/// Accumulator for one component node's raw embedded-section bytes plus
/// whether it exports the policy interface. Borrows the section bytes
/// from the wasm; [`finish`](RawFrame::finish) parses + hashes them
/// into an owned [`EmbeddedCatalog`].
#[derive(Default)]
struct RawFrame<'a> {
    disclosure_fields: Option<&'a [u8]>,
    i18n: Option<&'a [u8]>,
    icons: Option<&'a [u8]>,
    is_policy: bool,
}

impl<'a> RawFrame<'a> {
    /// True if this component shipped no embedded sections at all.
    fn is_empty(&self) -> bool {
        self.disclosure_fields.is_none() && self.i18n.is_none() && self.icons.is_none()
    }

    /// Fold one payload into the frame: capture our custom sections
    /// (rejecting duplicates), and flag the policy export.
    fn absorb(&mut self, payload: &Payload<'a>) -> wasmtime::Result<()> {
        match payload {
            Payload::CustomSection(reader) => {
                let slot = match reader.name() {
                    n if n == SECTION_DISCLOSURE_FIELDS => &mut self.disclosure_fields,
                    n if n == SECTION_I18N => &mut self.i18n,
                    n if n == SECTION_ICONS => &mut self.icons,
                    _ => return Ok(()),
                };
                if slot.is_some() {
                    return Err(invalid(format!(
                        "duplicate custom section `{}` in component wasm",
                        reader.name(),
                    )));
                }
                *slot = Some(reader.data());
            }
            Payload::ComponentExportSection(reader) => {
                for export in reader.clone() {
                    let export = export.map_err(|e| {
                        wasmtime::Error::msg(format!("component export parse: {e}"))
                    })?;
                    if export.name.0.starts_with(POLICY_EXPORT_PREFIX) {
                        self.is_policy = true;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Parse the captured sections into a [`ComponentDecls`], enforce
    /// the per-kind cardinality caps, and compute the content-hash.
    fn finish(self) -> wasmtime::Result<EmbeddedCatalog> {
        let hash = catalog_hash(self.disclosure_fields, self.i18n, self.icons);
        let decls = build_decls(self.disclosure_fields, self.i18n, self.icons)?;
        Ok(EmbeddedCatalog {
            is_policy: self.is_policy,
            decls,
            hash,
        })
    }
}

/// Parse the raw section bytes into a [`ComponentDecls`], enforcing the
/// per-kind cardinality caps.
fn build_decls(
    disclosure_bytes: Option<&[u8]>,
    i18n_bytes: Option<&[u8]>,
    icons_bytes: Option<&[u8]>,
) -> wasmtime::Result<ComponentDecls> {
    let disclosure_section = disclosure_bytes
        .map(|b| parse_disclosure_fields(b))
        .transpose()
        .map_err(|e| {
            invalid(format!(
                "parsing custom section `{SECTION_DISCLOSURE_FIELDS}` as JSON: {e}",
            ))
        })?;
    let i18n_section = i18n_bytes.map(|b| parse_i18n(b)).transpose().map_err(|e| {
        invalid(format!(
            "parsing custom section `{SECTION_I18N}` as JSON: {e}"
        ))
    })?;
    let icons_section = icons_bytes
        .map(|b| parse_icons(b))
        .transpose()
        .map_err(|e| {
            invalid(format!(
                "parsing custom section `{SECTION_ICONS}` as JSON: {e}"
            ))
        })?;

    // Per-kind cardinality caps. Each kind has a different covert-
    // channel surface (DF leak to consumer; localized fully resolved
    // before wire framing; icons reach browser only) and a different
    // cap accordingly — see the constants' module-level docs in
    // `enclavid-embedded`. Defence-in-depth alongside the seal-time
    // `validate` check; engine refuses to load anything that slipped
    // past the CLI validation gate.
    let df_count = disclosure_section
        .as_ref()
        .map(|d| d.fields.len())
        .unwrap_or(0);
    if df_count > MAX_DECLARED_DISCLOSURE_FIELDS {
        return Err(invalid(format!(
            "component declares {df_count} disclosure-fields, max is \
             {MAX_DECLARED_DISCLOSURE_FIELDS}",
        )));
    }
    let l_count = i18n_section.as_ref().map(|i| i.entries.len()).unwrap_or(0);
    if l_count > MAX_DECLARED_LOCALIZED {
        return Err(invalid(format!(
            "component declares {l_count} i18n entries, max is {MAX_DECLARED_LOCALIZED}",
        )));
    }
    let icon_count = icons_section.as_ref().map(|i| i.names.len()).unwrap_or(0);
    if icon_count > MAX_DECLARED_ICONS {
        return Err(invalid(format!(
            "component declares {icon_count} icons, max is {MAX_DECLARED_ICONS}",
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

    // Icons: same set semantics as disclosure-fields — flat list of
    // identifiers; duplicates collapse on insertion.
    let icons: HashSet<String> = icons_section
        .map(|s| s.names.into_iter().collect())
        .unwrap_or_default();

    Ok(ComponentDecls {
        disclosure_fields,
        localized,
        icons,
    })
}
