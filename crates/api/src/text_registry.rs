//! Per-policy registry of localized constants.
//!
//! Built once at policy load by parsing the `assets` layer
//! (`enclavid_engine::load_assets`) and caching the resulting
//! `TextRegistry` alongside the compiled `Component` in
//! `state.policies`. Immutable for the lifetime of the policy entry —
//! policy code can NEVER read back from it, only reference entries by
//! their declared `text-ref` keys at use sites (media labels, consent
//! reasons, custom field-key payloads).
//!
//! This is the invariant that closes the "browser extension scrapes
//! interpolated PII out of labels" channel: every string a policy
//! can show is enumerable at audit time and frozen for the session.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use enclavid_engine::TextDecls;

use crate::locale::Locale;

/// One translation row inside the registry. Internal storage — the
/// registry resolves to a single picked string at the API boundary
/// (`resolve_string`), so the wire never sees per-locale rows. Kept
/// as a struct instead of `(String, String)` only for readability at
/// the lookup sites.
struct LocalizedRow {
    language: String,
    text: String,
}

/// Resolved text dictionary keyed by the policy-declared `text-ref`.
/// Each entry holds every translation the polici declared. The flat
/// key set is cached as `Arc<HashSet<String>>` so the engine can
/// cheaply check membership at every text-ref use-site without taking
/// a dependency on this api-crate type.
#[derive(Default)]
pub struct TextRegistry {
    entries: HashMap<String, Vec<LocalizedRow>>,
    keys: Arc<HashSet<String>>,
}

impl TextRegistry {
    /// Build a registry from the polici's declarations, already
    /// validated by `enclavid_engine::load_assets` into pure
    /// identifiers and grouped localized blocks.
    ///
    ///   * `identifiers` populate `keys` only — these refs are
    ///     registered for membership-check but resolve to themselves
    ///     (their machine-key string) at view-construction time.
    ///   * `localized` carries one block per key with its full
    ///     translation set; each block populates `entries[key]` and
    ///     also contributes to `keys`.
    ///
    /// `keys` is the **union** of both sets — anything the engine
    /// asks "is this text-ref declared?" needs a yes for both
    /// classes.
    pub fn from_decls(decls: TextDecls) -> Self {
        let mut entries: HashMap<String, Vec<LocalizedRow>> = HashMap::new();
        let mut keys: HashSet<String> = HashSet::new();
        for key in decls.identifiers {
            keys.insert(key);
        }
        for block in decls.localized {
            keys.insert(block.key.clone());
            entries.insert(
                block.key,
                block
                    .translations
                    .into_iter()
                    .map(|(language, text)| LocalizedRow { language, text })
                    .collect(),
            );
        }
        Self {
            entries,
            keys: Arc::new(keys),
        }
    }

    /// Resolve a `text-ref` to a single string for the applicant's
    /// locale. Picking strategy:
    ///   1. Exact match (`ru-RU` ↔ `ru-RU`).
    ///   2. Language base (`ru-RU` ↔ `ru`).
    ///   3. `en` fallback (universal default).
    ///   4. First available translation.
    ///
    /// For identifier-only refs (no translation entries) and unknown
    /// refs (shouldn't happen — engine traps on missing at host fn
    /// entry), returns the raw key. Frontend renders identifiers as
    /// machine codes on the "custom field" UI; an unknown ref leaking
    /// here would still render as its key, degrading gracefully
    /// instead of producing an empty cell.
    ///
    /// Sanitisation happens here, not at manifest load — `load_manifest`
    /// stores translation values verbatim. We strip control / BIDI /
    /// zero-width / Unicode-tag chars on the picked value before
    /// returning it to the view layer (lazy validation strategy —
    /// see `engine::policy::load_manifest` docs).
    pub fn resolve_string(&self, key: &str, locale: &Locale) -> String {
        let picked = self.pick_translation(key, locale);
        enclavid_engine::sanitize_text_value(&picked)
    }

    fn pick_translation(&self, key: &str, locale: &Locale) -> String {
        let Some(translations) = self.entries.get(key) else {
            return key.to_string();
        };
        let tag = locale.as_str();
        // 1. Exact tag match.
        if let Some(row) = translations.iter().find(|r| r.language == tag) {
            return row.text.clone();
        }
        // 2. Language-base match (strip region/script subtag).
        if let Some((base, _)) = tag.split_once('-') {
            if let Some(row) = translations.iter().find(|r| r.language == base) {
                return row.text.clone();
            }
        }
        // 3. `en` fallback.
        if let Some(row) = translations.iter().find(|r| r.language == "en") {
            return row.text.clone();
        }
        // 4. First available.
        translations
            .first()
            .map(|r| r.text.clone())
            .unwrap_or_else(|| key.to_string())
    }

    /// Shared, immutable view of the full set of registered
    /// `text-ref` keys. Handed to the engine as `RunResources::
    /// registered_text_refs` so every text-ref use-site
    /// (`prompt-disclosure` field key/label, reason, media labels)
    /// can be membership-checked against the policy's frozen
    /// dictionary. This is the registration-before-`evaluate`
    /// guarantee: the set is frozen before policy ever sees per-
    /// session user input, so policy cannot craft a text-ref at
    /// runtime based on user attributes.
    pub fn registered_keys(&self) -> Arc<HashSet<String>> {
        self.keys.clone()
    }
}
