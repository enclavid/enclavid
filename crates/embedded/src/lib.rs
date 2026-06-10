//! Shared schema for the "embedded" sections embedded in policy and
//! plugin wasm components.
//!
//! A component author keeps the source on disk as plain JSON files
//! next to `Cargo.toml`:
//!
//! ```text
//! my-policy/
//! ├── Cargo.toml
//! ├── disclosure-fields.json   # optional — see DisclosureFieldsSection
//! ├── i18n.json                # optional — see I18nSection
//! └── src/lib.rs
//! ```
//!
//! At seal time `enclavid policy seal` reads whichever files exist and
//! embeds their bytes verbatim into independent wasm custom sections:
//!
//!   * `enclavid:embedded.disclosure-fields.v1` — JSON list of
//!     identifier keys; see [`SECTION_DISCLOSURE_FIELDS`].
//!   * `enclavid:embedded.i18n.v1` — JSON map of `key → { locale → text }`;
//!     see [`SECTION_I18N`].
//!
//! Each section is optional, both at file level and at section level.
//! A component that uses neither just ships without them. The engine
//! traps only at runtime if the component passes a key that wasn't
//! declared in any section it shipped.
//!
//! Component kind (policy vs plugin) used to live inside this schema
//! as a `kind` field; it now lives in the OCI manifest annotation
//! `com.enclavid.component.kind` so registry consumers can branch on
//! it without pulling the wasm layer.
//!
//! Keeping the parsers + types in this dedicated crate (no wasmtime,
//! no oci-client) gives one source of truth — wire-format field
//! names, validation rules, size caps — that the CLI (author-time
//! lint + seal) and the engine (load-time parse) both reference.
//! Drift between them is impossible by construction.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

// ---------- Schema-level limits ----------
//
// These are the wire-format constraints that bound a single source's
// size and per-key/per-value shapes. They live here because they are
// part of the schema definition itself, not a runtime concern — both
// the author-time linter (CLI `validate` / `seal`) and the runtime
// loader (engine `load_static`) consult them through this crate.
// The engine re-exports them via `enclavid-engine::limits` so engine
// callers can use one short path; bumps land here once.

pub const MAX_TEXT_ENTRIES: usize = 4096;
pub const MAX_TEXT_VALUE_HARD_BYTES: usize = 16 * 1024;
pub const MAX_KEY_LENGTH: usize = 128;
pub const MAX_LANGUAGE_LENGTH: usize = 16;

/// Custom section name for the disclosure-fields list.
pub const SECTION_DISCLOSURE_FIELDS: &str = "enclavid:embedded.disclosure-fields.v1";

/// Custom section name for the i18n translation catalog.
pub const SECTION_I18N: &str = "enclavid:embedded.i18n.v1";

/// Conventional on-disk filename for the disclosure-fields source.
/// CLI seal looks here in the component's project directory.
pub const FILE_DISCLOSURE_FIELDS: &str = "disclosure-fields.json";

/// Conventional on-disk filename for the i18n source.
pub const FILE_I18N: &str = "i18n.json";

/// Parsed contents of `disclosure-fields.json` /
/// `enclavid:embedded.disclosure-fields.v1`. A flat list of machine
/// identifiers the component declares it will pass as
/// `DisplayField.key` to `prompt-disclosure`. Sealed once and read
/// once at engine load. Identifiers never get translated — they're
/// the canonical machine name.
///
/// Wire format:
///
/// ```text
/// ["passport_number", "risk_category", "address"]
/// ```
#[derive(Deserialize, Serialize, Debug, Clone, Default)]
#[serde(transparent)]
pub struct DisclosureFieldsSection {
    pub fields: Vec<String>,
}

/// Parsed contents of `i18n.json` / `enclavid:embedded.i18n.v1`. A
/// translation catalog: each key has zero or more `(locale, text)`
/// rows. We keep `BTreeMap` so wire-format serialization is
/// deterministic (matters for content-addressing reproducibility).
///
/// Wire format:
///
/// ```text
/// {
///   "passport_title":  { "en": "Your passport", "ru": "Ваш паспорт" },
///   "consent_reason":  { "en": "Identity verification." }
/// }
/// ```
#[derive(Deserialize, Serialize, Debug, Clone, Default)]
#[serde(transparent)]
pub struct I18nSection {
    pub entries: BTreeMap<String, BTreeMap<String, String>>,
}

/// Validation outcome with separated errors (fail) and warnings
/// (informational, don't block push).
#[derive(Default)]
pub struct Report {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl Report {
    pub fn fail(&mut self, msg: impl Into<String>) {
        self.errors.push(msg.into());
    }

    pub fn warn(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }

    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Read + JSON-parse `disclosure-fields.json` from disk. Returns
/// `Ok(None)` if the file simply isn't there — sections are optional.
pub fn read_disclosure_fields(path: &Path) -> Result<Option<DisclosureFieldsSection>> {
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let parsed: DisclosureFieldsSection = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {} as JSON", path.display()))?;
    Ok(Some(parsed))
}

/// Read + JSON-parse `i18n.json` from disk. `Ok(None)` if missing.
pub fn read_i18n(path: &Path) -> Result<Option<I18nSection>> {
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let parsed: I18nSection = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {} as JSON", path.display()))?;
    Ok(Some(parsed))
}

/// Read the raw bytes of a section source file. Used by CLI seal —
/// the wasm custom section bytes are the on-disk JSON verbatim, no
/// re-serialization (which could change key order and break
/// content-addressing reproducibility).
pub fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    if !path.is_file() {
        bail!("file not found: {}", path.display());
    }
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

/// Parse a disclosure-fields section from a byte buffer. Used by the
/// engine and api when the bytes have already been extracted from the
/// wasm custom section (vs. read from disk).
pub fn parse_disclosure_fields(bytes: &[u8]) -> Result<DisclosureFieldsSection> {
    serde_json::from_slice(bytes).with_context(|| "parsing disclosure-fields JSON")
}

/// Parse an i18n section from a byte buffer.
pub fn parse_i18n(bytes: &[u8]) -> Result<I18nSection> {
    serde_json::from_slice(bytes).with_context(|| "parsing i18n JSON")
}

/// Semantic validation across whatever sections the author supplied.
/// Sections are independently optional — a component shipping neither
/// is valid. The engine traps only on actual unregistered key use.
pub fn validate(
    disclosure_fields: Option<&DisclosureFieldsSection>,
    i18n: Option<&I18nSection>,
) -> Report {
    let mut r = Report::default();

    // --- disclosure-fields checks ---
    if let Some(df) = disclosure_fields {
        let mut seen: std::collections::BTreeSet<&str> = Default::default();
        for key in &df.fields {
            if !is_valid_text_ref(key) {
                r.fail(format!(
                    "disclosure-fields entry '{key}' fails text-ref format \
                     (must be [a-z][a-z0-9_-]{{0,{}}})",
                    MAX_KEY_LENGTH - 1,
                ));
                continue;
            }
            if !seen.insert(key.as_str()) {
                r.fail(format!(
                    "disclosure-fields entry '{key}' appears more than once"
                ));
            }
        }
    }

    // --- i18n checks ---
    if let Some(i18n) = i18n {
        for (key, translations) in &i18n.entries {
            if !is_valid_text_ref(key) {
                r.fail(format!("i18n key '{key}' fails text-ref format"));
                continue;
            }
            for (locale, value) in translations {
                if !is_valid_language(locale) {
                    r.fail(format!(
                        "locale tag '{locale}' for '{key}' fails BCP-47-shape \
                         (must be [A-Za-z][A-Za-z0-9-]{{0,{}}})",
                        MAX_LANGUAGE_LENGTH - 1,
                    ));
                }
                if value.len() > MAX_TEXT_VALUE_HARD_BYTES {
                    r.fail(format!(
                        "translation '{key}'/'{locale}' is {} bytes, max is {MAX_TEXT_VALUE_HARD_BYTES}",
                        value.len(),
                    ));
                }
            }
            if translations.is_empty() {
                r.warn(format!(
                    "'{key}' has no translations; engine will return the raw \
                     key string when resolving"
                ));
            } else if !translations.contains_key("en") {
                r.warn(format!(
                    "'{key}' has no `en` translation; consider adding one as \
                     the universal fallback (engine's locale-pick chain ends \
                     at `en` before falling back to the first available)"
                ));
            }
        }
    }

    // No disjointness check: a ref can legitimately appear in both
    // disclosure-fields (as field.key machine identifier) AND i18n
    // (with a translation for use as label / reason). Engine handles
    // via union semantics.

    // --- total entries ---
    let total = disclosure_fields.map(|d| d.fields.len()).unwrap_or(0)
        + i18n.map(|i| i.entries.len()).unwrap_or(0);
    if total > MAX_TEXT_ENTRIES {
        r.fail(format!(
            "{total} total entries (disclosure-fields ∪ i18n), max is {MAX_TEXT_ENTRIES}"
        ));
    }

    r
}

fn is_valid_text_ref(s: &str) -> bool {
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

fn is_valid_language(s: &str) -> bool {
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
