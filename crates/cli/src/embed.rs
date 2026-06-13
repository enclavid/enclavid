//! Shared helper for appending `enclavid:embedded.*.v1` custom
//! sections to a wasm component. Used by both `enclavid policy embed`
//! and `enclavid plugin embed`.
//!
//! `wasm-encoder::CustomSection` writes the canonical encoding (`0x00`
//! section id + LEB128-prefixed name and payload); we stitch its
//! output onto the tail of the existing wasm bytes.
//!
//! Custom sections per the WASM core spec can appear anywhere
//! (before, between, or after standard sections). Appending at the
//! end keeps us from re-parsing the existing wasm and matches the
//! convention LLVM/rustc/cargo-component already follow for `name` /
//! `producers` sections.
//!
//! Sections are appended only when their source bytes are present
//! (`Some(..)`); absent sources simply produce no section, and the
//! TEE-side loader treats the missing section as "no declarations of
//! this kind".

use std::borrow::Cow;
use wasm_encoder::ComponentSection;

use enclavid_embedded::{SECTION_DISCLOSURE_FIELDS, SECTION_I18N, SECTION_ICONS};

/// Append the three embedded-section kinds to a wasm component.
/// Each kind is independently optional. The returned `Vec<u8>` is
/// the original wasm with appended custom sections; callers stream
/// it to disk verbatim.
pub fn embed_sections(
    wasm_bytes: &[u8],
    disclosure: Option<&[u8]>,
    i18n: Option<&[u8]>,
    icons: Option<&[u8]>,
) -> Vec<u8> {
    let extra_capacity = disclosure.map(|b| b.len()).unwrap_or(0)
        + i18n.map(|b| b.len()).unwrap_or(0)
        + icons.map(|b| b.len()).unwrap_or(0)
        + 96;
    let mut out = Vec::with_capacity(wasm_bytes.len() + extra_capacity);
    out.extend_from_slice(wasm_bytes);
    if let Some(bytes) = disclosure {
        wasm_encoder::CustomSection {
            name: Cow::Borrowed(SECTION_DISCLOSURE_FIELDS),
            data: Cow::Borrowed(bytes),
        }
        .append_to_component(&mut out);
    }
    if let Some(bytes) = i18n {
        wasm_encoder::CustomSection {
            name: Cow::Borrowed(SECTION_I18N),
            data: Cow::Borrowed(bytes),
        }
        .append_to_component(&mut out);
    }
    if let Some(bytes) = icons {
        wasm_encoder::CustomSection {
            name: Cow::Borrowed(SECTION_ICONS),
            data: Cow::Borrowed(bytes),
        }
        .append_to_component(&mut out);
    }
    out
}
