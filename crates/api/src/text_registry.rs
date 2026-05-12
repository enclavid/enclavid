//! Per-policy registry of localized constants.
//!
//! Built once at policy load by calling the component's
//! `prepare-localized-texts` export and caching the result alongside
//! the compiled `Component` in `state.policies`. The registry is
//! immutable for the lifetime of the policy entry — policy code can
//! NEVER read back from it, only reference entries by their declared
//! `text-ref` keys at use sites (media labels, consent reasons,
//! custom field-key payloads).
//!
//! This is the invariant that closes the "browser extension scrapes
//! interpolated PII out of labels" channel: every string a policy
//! can show is enumerable at audit time and frozen for the session.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use enclavid_engine::TextDecls;

use crate::dto::{LocalizedString, Translations};

/// Resolved text dictionary keyed by the policy-declared `text-ref`
/// key. Each entry holds every translation the policy declared. The
/// flat key set is also cached as an `Arc<HashSet<String>>` so the
/// engine can cheaply check membership at every text-ref use-site
/// without taking a dependency on this api-crate type.
#[derive(Default)]
pub struct TextRegistry {
    entries: HashMap<String, Vec<LocalizedString>>,
    keys: Arc<HashSet<String>>,
}

impl TextRegistry {
    /// Build a registry from the policy's `prepare-text-refs`
    /// declarations, already split by `Runner::extract_texts` into
    /// pure identifiers and grouped localized blocks.
    ///
    ///   * `identifiers` populate `keys` only — these refs are
    ///     registered for membership-check but never resolved.
    ///   * `localized` carries one block per key with its full
    ///     translation set; each block populates `entries[key]` and
    ///     also contributes to `keys`.
    ///
    /// `keys` is the **union** of both sets — anything the engine
    /// asks "is this text-ref declared?" needs a yes for both
    /// classes.
    pub fn from_decls(decls: TextDecls) -> Self {
        let mut entries: HashMap<String, Vec<LocalizedString>> = HashMap::new();
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
                    .map(|(language, text)| LocalizedString { language, text })
                    .collect(),
            );
        }
        Self {
            entries,
            keys: Arc::new(keys),
        }
    }

    /// Resolve a key to its full set of translations. Missing key
    /// returns an empty list — caller decides how to surface that
    /// (typically: it shouldn't happen if the policy is well-formed,
    /// and the engine traps before we get here for missing refs at
    /// `prompt-disclosure` invocation time).
    pub fn resolve(&self, key: &str) -> Translations {
        self.entries.get(key).cloned().unwrap_or_default()
    }

    /// Shared, immutable view of the full set of registered
    /// `text-ref` keys. Handed to the engine as `RunResources::
    /// registered_text_refs` so every text-ref use-site
    /// (`prompt-disclosure` field key/label, reason, media labels)
    /// can be membership-checked against the policy's pre-declared
    /// dictionary. This is the registration-before-`evaluate`
    /// guarantee: the set is frozen before policy ever sees per-
    /// session user input, so policy cannot craft a text-ref at
    /// runtime based on user attributes.
    pub fn registered_keys(&self) -> Arc<HashSet<String>> {
        self.keys.clone()
    }
}
