//! Shared schema for the "embedded" sections embedded in policy and
//! plugin wasm components, and the text model they carry.
//!
//! A component's project holds its catalogs beside its WIT:
//!
//! ```text
//! my-policy/
//! ├── wit/world.wit     # the keys: `interface i18n { enum key { … } }`,
//! │                     # and for a policy its disclosure fields
//! ├── i18n/
//! │   ├── en.json       # the texts, one file per language: key → text
//! │   └── ru.json
//! └── src/…
//! ```
//!
//! or, all languages in one file, `language → key → text`, the section's own
//! shape:
//!
//! ```text
//! my-policy/
//! ├── wit/world.wit
//! ├── i18n.json         # { "en": { … }, "ru": { … } }
//! └── src/…
//! ```
//!
//! Embedding (`enclavid {policy,plugin} embed`, see [`embed`]) checks the
//! texts against the keys, and writes two independent wasm custom sections:
//!
//!   * `enclavid:embedded.disclosure-fields.v1` — the policy's disclosure
//!     fields, the cases of its `enclavid:host-ext/disclosure-fields` key:
//!     a JSON list; see [`SECTION_DISCLOSURE_FIELDS`].
//!   * `enclavid:embedded.i18n.v1` — the texts: a JSON map of
//!     `language → key → text`; see [`SECTION_I18N`].
//!
//! Each section is optional; a component with no texts ships without one.
//!
//! Component kind (policy vs plugin) lives in the OCI manifest annotation
//! `com.enclavid.component.kind`, so registry consumers can branch on it
//! without pulling the wasm layer.
//!
//! Keeping the parsers, the checks and the types in this dedicated crate (no
//! wasmtime, no oci-client) gives one source of truth — wire-format field
//! names, validation rules, size caps — that the CLI (author-time lint +
//! embed) and the engine (load-time parse) both reference. Drift between them
//! is impossible by construction.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

mod hash;
pub mod keys;
pub mod text;

#[cfg(feature = "embed")]
pub mod embed;

pub use hash::{catalog_hash, embedded_import_name, slug};

// ---------- Schema-level limits ----------
//
// These are the wire-format constraints that bound a single source's
// size and per-key/per-value shapes. They live here because they are
// part of the schema definition itself, not a runtime concern — both
// the author-time linter (CLI `validate` / `embed`) and the runtime
// loader (engine `load_embedded`) consult them through this crate.
// The engine re-exports them via `engine-types::limits` so engine
// callers can use one short path; bumps land here once.

// Per-kind cap on declarations. Split per kind because the covert-
// channel surfaces aren't symmetric:
//
//   * `disclosure-fields` declarations leak their raw key into the
//     consumer-facing envelope (consumer SDK dispatches by literal
//     key). Channel bandwidth is `log2(MAX_DECLARED_DISCLOSURE_FIELDS)`
//     bits per `DisplayField.key` position. Tight cap here is the
//     primary defence; transparency UI surfaces the declared
//     count + full vocabulary so user can audit.
//   * `i18n` texts never reach the consumer — the platform picks one for
//     the applicant inside the TEE, in the applicant's language.
//     Generous cap is safe.
//
// Icons are no section: the set is the host's own, the functions of
// `enclavid:host-icons/icons`.
pub const MAX_DECLARED_DISCLOSURE_FIELDS: usize = 256;
/// The most texts one language of a component's catalog may hold.
pub const MAX_DECLARED_LOCALIZED: usize = 4096;
/// The most languages one component's catalog may hold.
pub const MAX_LANGUAGES: usize = 64;

/// The most bytes one text may hold.
pub const MAX_TEXT_VALUE_HARD_BYTES: usize = 16 * 1024;
pub const MAX_KEY_LENGTH: usize = 128;
pub const MAX_LANGUAGE_LENGTH: usize = 16;

/// Custom section name for the disclosure-fields list.
pub const SECTION_DISCLOSURE_FIELDS: &str = "enclavid:embedded.disclosure-fields.v1";

/// Custom section name for the i18n catalog.
pub const SECTION_I18N: &str = "enclavid:embedded.i18n.v1";

/// Conventional directory of a project's texts, one `<language>.json` each —
/// or, with `.json` after it, the one file of every language.
pub const DIR_I18N: &str = "i18n";

/// The language a text is shown in when the applicant's has none of its own.
pub const DEFAULT_LANGUAGE: &str = "en";

/// Contents of `enclavid:embedded.disclosure-fields.v1`. A flat list of
/// machine identifiers the policy declares it will pass as
/// `DisplayField.key` to `prompt-disclosure`. Identifiers never get
/// translated — they're the canonical machine name.
///
/// Wire format:
///
/// ```text
/// ["passport-number", "risk-category", "address"]
/// ```
#[derive(Deserialize, Serialize, Debug, Clone, Default)]
#[serde(transparent)]
pub struct DisclosureFieldsSection {
    pub fields: Vec<String>,
}

/// A component's texts: per language, each text by its key.
pub type Catalog = BTreeMap<String, BTreeMap<String, String>>;

/// Contents of `enclavid:embedded.i18n.v1`: each language's texts by key.
/// `BTreeMap`s so the bytes are a pure function of the texts, which the slot
/// name is a hash of.
///
/// Wire format:
///
/// ```text
/// { "en": { "consent-reason": "To verify your identity." }, "ru": { … } }
/// ```
#[derive(Deserialize, Serialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(transparent)]
pub struct I18nSection {
    pub languages: Catalog,
}

/// Parse a disclosure-fields section from a byte buffer.
pub fn parse_disclosure_fields(bytes: &[u8]) -> serde_json::Result<DisclosureFieldsSection> {
    serde_json::from_slice(bytes)
}

/// Parse an i18n section from a byte buffer.
pub fn parse_i18n(bytes: &[u8]) -> serde_json::Result<I18nSection> {
    serde_json::from_slice(bytes)
}

/// The texts of an i18n section, held to the bounds a component's texts are:
/// or the first thing wrong with them.
pub fn read_i18n(bytes: &[u8]) -> Result<Catalog, String> {
    let section = parse_i18n(bytes).map_err(|e| e.to_string())?;
    if section.languages.len() > MAX_LANGUAGES {
        return Err(format!(
            "holds {} languages, at most {MAX_LANGUAGES}",
            section.languages.len()
        ));
    }
    for (language, texts) in &section.languages {
        if let Some(problem) = language_problems(language, texts).into_iter().next() {
            return Err(format!("{language}: {problem}"));
        }
    }
    Ok(section.languages)
}

/// What is wrong with one language's texts against the bounds a component's
/// texts are held to; nothing when they keep to them.
pub fn language_problems(language: &str, texts: &BTreeMap<String, String>) -> Vec<String> {
    let mut problems = Vec::new();
    if !is_valid_language(language) {
        problems.push("is not named for a language tag, such as `en` or `pt-BR`".into());
    }
    if texts.len() > MAX_DECLARED_LOCALIZED {
        problems.push(format!(
            "holds {} texts, at most {MAX_DECLARED_LOCALIZED}",
            texts.len()
        ));
    }
    for (key, text) in texts {
        if !is_valid_text_ref(key) {
            problems.push(format!(
                "`{key}` is not lowercase letters, digits, `_` and `-`, at most {MAX_KEY_LENGTH} bytes"
            ));
        } else if text.len() > MAX_TEXT_VALUE_HARD_BYTES {
            problems.push(format!(
                "`{key}` holds more than {MAX_TEXT_VALUE_HARD_BYTES} bytes of text"
            ));
        }
    }
    problems
}

/// Whether `s` is a declared key's shape: `[a-z][a-z0-9_-]*`, at most
/// [`MAX_KEY_LENGTH`] bytes.
pub fn is_valid_text_ref(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_KEY_LENGTH {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
}

/// Whether `s` is a language tag's shape: `[A-Za-z][A-Za-z0-9-]*`, at most
/// [`MAX_LANGUAGE_LENGTH`] bytes.
pub fn is_valid_language(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_LANGUAGE_LENGTH {
        return false;
    }
    if !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(languages: &[(&str, &[(&str, &str)])]) -> Vec<u8> {
        let catalog: Catalog = languages
            .iter()
            .map(|(language, texts)| {
                let texts = texts
                    .iter()
                    .map(|(key, text)| (key.to_string(), text.to_string()))
                    .collect();
                (language.to_string(), texts)
            })
            .collect();
        serde_json::to_vec(&I18nSection { languages: catalog }).unwrap()
    }

    #[test]
    fn a_section_within_the_bounds_reads() {
        let catalog = read_i18n(&section(&[
            ("en", &[("title", "Title")]),
            ("pt-BR", &[("title", "Título")]),
        ]))
        .unwrap();
        assert_eq!(catalog["pt-BR"]["title"], "Título");
    }

    #[test]
    fn a_section_past_the_bounds_is_refused_and_named() {
        let long = "x".repeat(MAX_TEXT_VALUE_HARD_BYTES + 1);
        let refused = |bytes: &[u8]| read_i18n(bytes).unwrap_err();
        assert!(refused(&section(&[("en", &[("title", long.as_str())])])).contains("`title`"));
        assert!(refused(&section(&[("en us", &[])])).contains("language tag"));
        assert!(refused(&section(&[("en", &[("Title", "x")])])).contains("`Title`"));
        assert!(refused(br#"{"en": {"title": 1}}"#).contains("invalid type"));
    }
}
