//! Polici manifest: single declarative file the polici author keeps
//! alongside their source code, shipped as the plain-JSON layer of
//! the OCI artifact.
//!
//! ```
//! my-policy/
//! ├── Cargo.toml
//! ├── policy.json          # this file
//! └── src/lib.rs
//! ```
//!
//! Wire format (same as on-disk, push reads bytes verbatim):
//!
//! ```json
//! {
//!   "version": 1,
//!   "disclosure_fields": ["passport_number", "risk_category"],
//!   "localized": {
//!     "passport_title":  { "en": "Your passport", "ru": "Ваш паспорт" },
//!     "consent_reason":  { "en": "..." }
//!   }
//! }
//! ```
//!
//! `disclosure_fields` lists machine keys used as `field.key` in
//! `prompt_disclosure` — opaque identifiers shown raw on the consent
//! screen for non-canonical names. `localized` carries translations
//! for refs that surface as UI text (labels, reasons, instructions).
//!
//! Disjointness is structural: a key is in `disclosure_fields` XOR
//! in `localized` — impossible to violate by schema (`overlap` check
//! still done as defence-in-depth).
//!
//! Validation rules here mirror the engine's `load_manifest` checks
//! so any error here is also what the TEE would trap on. Lint at
//! author time → clean local error; lint at /connect time → opaque
//! 500 in production. Bumping limits or schema requires touching
//! both crates.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

// ---------- Engine-side limits, mirrored here ----------
//
// Engine source: `crates/engine/src/limits.rs`. Keep in sync — drift
// means a polici that passes `enclavid validate` trips at engine
// load, which is exactly what the lint is supposed to prevent.
//
// Bump in both places when the engine changes.

const MAX_TEXT_ENTRIES: usize = 4096;
const MAX_TEXT_VALUE_HARD_BYTES: usize = 16 * 1024;
const MAX_KEY_LENGTH: usize = 128;
const MAX_LANGUAGE_LENGTH: usize = 16;
const CURRENT_VERSION: u32 = 1;

/// Parsed manifest. Mirrors the on-disk JSON shape. We keep the
/// `BTreeMap` for `localized` so wire-format serialization is
/// deterministic across runs — matters for content-addressing
/// (same source produces the same digest).
#[derive(Deserialize, Serialize)]
pub struct PolicyManifest {
    /// Optional in JSON (defaults to `1`). Bumped only on BREAKING
    /// schema changes. Additive evolution (new optional top-level
    /// keys) doesn't require a bump.
    #[serde(default = "default_version")]
    pub version: u32,
    /// Disclosure field machine keys — opaque identifiers used as
    /// `DisplayField.key` in `prompt_disclosure`.
    #[serde(default)]
    pub disclosure_fields: Vec<String>,
    /// `text_ref → { locale → text }` map for translatable UI strings.
    #[serde(default)]
    pub localized: BTreeMap<String, BTreeMap<String, String>>,
}

fn default_version() -> u32 {
    CURRENT_VERSION
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

/// Read + JSON-parse the manifest file. Returns an error on
/// filesystem / JSON-syntax problems — semantic validation is
/// [`validate`] below.
pub fn read(path: &Path) -> Result<PolicyManifest> {
    if !path.is_file() {
        bail!("policy manifest not found: {}", path.display());
    }
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let manifest: PolicyManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {} as JSON", path.display()))?;
    Ok(manifest)
}

/// Read the raw bytes of the manifest. Used by `push` — the layer
/// shipped to the registry is the on-disk JSON verbatim, no
/// re-serialization (which could change key order and break
/// content-addressing reproducibility).
pub fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    if !path.is_file() {
        bail!("policy manifest not found: {}", path.display());
    }
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

/// Run all semantic checks. Mirrors engine's `load_manifest`
/// validation so any error here is also what the TEE would trap on.
pub fn validate(manifest: &PolicyManifest) -> Report {
    let mut r = Report::default();

    // --- schema version ---
    if manifest.version != CURRENT_VERSION {
        r.fail(format!(
            "version {} not supported (CLI knows version {CURRENT_VERSION}); \
             upgrade enclavid-cli if your polici targets a newer schema",
            manifest.version,
        ));
    }

    // --- disclosure_fields checks ---
    let mut seen_disclosure: std::collections::BTreeSet<&str> = Default::default();
    for key in &manifest.disclosure_fields {
        if !is_valid_text_ref(key) {
            r.fail(format!(
                "disclosure_fields entry '{key}' fails text-ref format \
                 (must be [a-z][a-z0-9_-]{{0,{}}})",
                MAX_KEY_LENGTH - 1,
            ));
            continue;
        }
        if !seen_disclosure.insert(key.as_str()) {
            r.fail(format!(
                "disclosure_fields entry '{key}' appears more than once"
            ));
        }
    }

    // --- localized checks ---
    for (key, translations) in &manifest.localized {
        if !is_valid_text_ref(key) {
            r.fail(format!(
                "localized key '{key}' fails text-ref format"
            ));
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

    // No disjointness check: a ref can legitimately appear in
    // both `disclosure_fields` (as field.key machine identifier)
    // AND `localized` (with a translation for use as label /
    // reason). Engine handles via union semantics.

    // --- total entries ---
    let total = manifest.disclosure_fields.len() + manifest.localized.len();
    if total > MAX_TEXT_ENTRIES {
        r.fail(format!(
            "{total} total entries (disclosure_fields ∪ localized), max is {MAX_TEXT_ENTRIES}"
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
