//! Extract and parse a component's "embedded" sections — the embedded
//! `enclavid:embedded.*` declarations a component ships inside its
//! wasm:
//!
//!   * `enclavid:embedded.disclosure-fields.v1` — machine identifier
//!     list, surfaces as `DisplayField.key` in `prompt-disclosure`.
//!   * `enclavid:embedded.i18n.v1` — the texts, each language's by key.
//!
//! Both sections are **independently optional**. A component that ships
//! neither is valid; a key no catalog declared traps where it is minted. No
//! load-time atomicity requirement: missing sections are simply absent from
//! the union.
//!
//! Every section is read in full here, and held to the bounds of the format,
//! so a composition whose catalogs break it is refused at compile rather than
//! in a round.
//!
//! The OCI annotation `com.enclavid.component.kind` (set by
//! `enclavid policy push`) discriminates policy vs plugin before the
//! layer is ever pulled; this loader doesn't see that field anymore
//! (it used to live in the JSON we parsed here).

use std::collections::HashSet;

use enclavid_embedded::{
    Catalog, SECTION_DISCLOSURE_FIELDS, SECTION_I18N, catalog_hash, is_valid_text_ref,
    parse_disclosure_fields, read_i18n,
};
use wasmparser::{Parser, Payload};

use engine_types::compile::{Artifact, CompileFault};
use engine_types::embedded::ComponentDecls;
use engine_types::limits::MAX_DECLARED_DISCLOSURE_FIELDS;

/// A single component's embedded catalog plus its identity. `hash` is
/// the content-hash of the raw section bytes ([`catalog_hash`]) — the key
/// the registry stores the catalog under.
pub struct EmbeddedCatalog {
    pub decls: ComponentDecls,
    /// The texts of `decls`, read: what the slot's imports are held to.
    pub texts: Catalog,
    /// The slot the texts are served through, `enclavid-ext:<slot>`; `None`
    /// for a catalog of no texts.
    pub slot: Option<String>,
    pub hash: [u8; 32],
}

/// Load one component's embedded catalog from the top-level custom
/// sections of a wasm component binary; a component that ships no
/// embedded sections yields an empty catalog. A fusion carries its
/// components' catalogs NESTED — use [`load_embedded_nested`] for those.
///
/// `wasm_bytes` is the (decrypted) policy or plugin wasm — caller
/// already pulled and unwrapped any age-encrypted layer. We don't
/// reach for wasmtime here: `wasmparser` walks the component's outer
/// payloads without compiling anything, which is enough to extract
/// custom sections by name.
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

/// Recover every embedded catalog from an artifact. Descends into nested
/// sub-components — under wac fusion each original policy/plugin becomes a
/// nested component carrying its own embedded sections. Returns one
/// [`EmbeddedCatalog`] per component that ships at least one embedded
/// section (empty wrappers are skipped). Works on a component with its
/// sections at the top too (returns its single catalog, if any).
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

/// Max component nesting we'll descend. An embedded component's catalog
/// is at depth 0, under `wac plug` at depth 1; a re-fused hybrid core adds
/// one more. A generous bound guards against pathological inputs without
/// constraining real artifacts.
const MAX_NESTING: usize = 8;

/// An embedded catalog breaks its format: a section repeated in one component,
/// one that does not parse, one declaring past a `MAX_DECLARED_*` count, or
/// catalogs nested deeper than the loader descends.
///
/// Its own type, carried inside the `wasmtime::Error` the loaders return, with
/// what broke as the error's context: a rule of the catalog format, checked
/// against the pinned bytes, so the same pins meet it every time.
/// [`Compiler::compile_to_parts`](crate::Compiler::compile_to_parts) looks for it
/// there, and refuses the composition for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogRefused;

impl std::fmt::Display for CatalogRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an embedded catalog breaks its format")
    }
}
impl std::error::Error for CatalogRefused {}

/// A [`CatalogRefused`], with `cause` as its context for the debug log.
fn invalid(cause: String) -> wasmtime::Error {
    wasmtime::Error::new(CatalogRefused).context(cause)
}

/// What a loader's failure to read `artifact` refuses the composition for: a
/// catalog that breaks its format, or — the bytes not reading as wasm at all —
/// an artifact that is not a component.
pub(crate) fn unreadable(artifact: Artifact, e: wasmtime::Error) -> wasmtime::Error {
    let fault = if e.is::<CatalogRefused>() {
        CompileFault::CatalogInvalid(artifact)
    } else {
        CompileFault::NotAComponent(artifact)
    };
    e.context(fault)
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
            if name == SECTION_DISCLOSURE_FIELDS || name == SECTION_I18N {
                total += reader.data().len() as u64;
            }
        }
    }
    Ok(total)
}

/// The import names of a component's OWN (top-level) world. Depth-0 only —
/// nested components' imports are internal and already satisfied.
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

/// Accumulator for one component node's raw embedded-section bytes.
/// Borrows the section bytes from the wasm; [`finish`](RawFrame::finish)
/// parses + hashes them into an owned [`EmbeddedCatalog`].
#[derive(Default)]
struct RawFrame<'a> {
    disclosure_fields: Option<&'a [u8]>,
    i18n: Option<&'a [u8]>,
}

impl<'a> RawFrame<'a> {
    /// True if this component shipped no embedded sections at all.
    fn is_empty(&self) -> bool {
        self.disclosure_fields.is_none() && self.i18n.is_none()
    }

    /// Fold one payload into the frame: capture our custom sections,
    /// rejecting duplicates.
    fn absorb(&mut self, payload: &Payload<'a>) -> wasmtime::Result<()> {
        let Payload::CustomSection(reader) = payload else {
            return Ok(());
        };
        let section = match reader.name() {
            n if n == SECTION_DISCLOSURE_FIELDS => &mut self.disclosure_fields,
            n if n == SECTION_I18N => &mut self.i18n,
            _ => return Ok(()),
        };
        if section.is_some() {
            return Err(invalid(format!(
                "duplicate custom section `{}` in component wasm",
                reader.name(),
            )));
        }
        *section = Some(reader.data());
        Ok(())
    }

    /// Parse the captured sections into a [`ComponentDecls`], hold them to
    /// the format's bounds, and compute the content-hash.
    fn finish(self) -> wasmtime::Result<EmbeddedCatalog> {
        let hash = catalog_hash(self.disclosure_fields, self.i18n);
        let (decls, texts, slot) = build_decls(self.disclosure_fields, self.i18n)?;
        Ok(EmbeddedCatalog {
            decls,
            texts,
            slot,
            hash,
        })
    }
}

/// Parse the raw section bytes into a [`ComponentDecls`], its texts read and
/// the slot they are served through, holding them to the bounds embedding
/// holds them to.
fn build_decls(
    disclosure_bytes: Option<&[u8]>,
    i18n_bytes: Option<&[u8]>,
) -> wasmtime::Result<(ComponentDecls, Catalog, Option<String>)> {
    let disclosure_section = disclosure_bytes
        .map(|b| parse_disclosure_fields(b))
        .transpose()
        .map_err(|e| {
            invalid(format!(
                "parsing custom section `{SECTION_DISCLOSURE_FIELDS}` as JSON: {e}",
            ))
        })?;
    let (slot, texts) = match i18n_bytes.map(read_i18n).transpose() {
        Ok(Some(section)) => (Some(section.slot), section.languages),
        Ok(None) => (None, Catalog::default()),
        Err(e) => {
            return Err(invalid(format!(
                "reading custom section `{SECTION_I18N}`: {e}"
            )));
        }
    };

    // Disclosure fields reach the consumer and are shown to the applicant
    // by their raw key, so a key is held to an alphabet nothing invisible or
    // confusable is in, and the list to its cap: what the consent screen
    // counts as the bound on what a field's key can carry.
    let fields = disclosure_section.map(|s| s.fields).unwrap_or_default();
    if fields.len() > MAX_DECLARED_DISCLOSURE_FIELDS {
        return Err(invalid(format!(
            "component declares {} disclosure-fields, max is \
             {MAX_DECLARED_DISCLOSURE_FIELDS}",
            fields.len(),
        )));
    }
    if let Some(field) = fields.iter().find(|field| !is_valid_text_ref(field)) {
        return Err(invalid(format!(
            "the disclosure field `{field}` is not a key's shape"
        )));
    }

    // Disclosure fields: HashSet collapses any in-list duplicates
    // (JSON arrays allow them, but the registry's membership is
    // set-typed and would have the same effect).
    let disclosure_fields: HashSet<String> = fields.into_iter().collect();
    Ok((
        ComponentDecls {
            disclosure_fields,
            i18n: i18n_bytes.map(<[u8]>::to_vec).unwrap_or_default(),
        },
        texts,
        slot,
    ))
}
