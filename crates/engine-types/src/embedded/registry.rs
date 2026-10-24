//! `enclavid:embedded/*` ref scoping: a component's texts from its own
//! catalog, disclosure fields from all of them.
//!
//! Two **public stores** on [`EmbeddedRegistry`], one per kind:
//!
//!   * [`DisclosureFieldsStore`] — machine identifiers consumed by
//!     the consumer SDK as `DisplayField.key`. The one kind that
//!     reaches the consumer.
//!   * [`LocalizedStore`] — the texts. Written out in the applicant's
//!     language inside the TEE before any wire send; consumer never sees
//!     refs or text.
//!
//! Icons have no store: their names are the host's own
//! ([`crate::icons`]), so no component declares any.
//!
//! A component's texts resolve against its own catalog alone
//! (`RefStore::resolve_strict`): it imports them through the slot its
//! catalog names, which the host serves from that catalog. Disclosure
//! fields resolve by **first match across every catalog** (composition
//! order, policy first, `RefStore::resolve_first_match`): one list the
//! policy declares, which the plugins' helpers name keys of.
//!
//! DF is not resolution-gated to the policy even though it reaches the
//! consumer: the policy chooses which `display-field`s it discloses
//! and the applicant consents to every `(key, label, value)` on
//! screen (the sole auditor). That is the bound on what leaks, not the
//! resolution slot. Each component's DF section is size-capped at
//! build time (`MAX_DECLARED_DISCLOSURE_FIELDS`).
//!
//! Both wrap the same private generic [`RefStore`](super::store::
//! RefStore) so the membership / get_token / lookup mechanics live in
//! one place.
//!
//! The registry is **immutable per run**: built once per round's process
//! from the catalogs the compile kept of every component, frozen, then
//! shared by `Arc` into the policy `HostState`. It is consulted only when
//! the host MINTS a ref resource; the resource then carries the resolved
//! data itself, so nothing downstream re-consults the registry.
//!
//! A catalog's texts travel as the component ships them, its i18n section's
//! own bytes, and are read here: what the compile hands on and what a worker
//! keeps are the section's size, not the larger size of what it reads into.

use std::collections::{HashMap, HashSet};

use super::store::{DisclosureFields, Localized, RefStore};

/// Type alias for the `enclavid:embedded/disclosure-fields` store.
/// `lookup` returns `Option<&String>` — the raw declared key, which
/// the consumer SDK dispatches on. Auto-deref to `&str` at call
/// sites when needed.
pub type DisclosureFieldsStore = RefStore<DisclosureFields>;

/// Type alias for the `enclavid:embedded/i18n` store. `lookup`
/// returns `Option<&Vec<Translation>>` — the full translation row
/// set; locale-picking is the consumer's call. Auto-deref to
/// `&[Translation]` covers most call sites.
pub type LocalizedStore = RefStore<Localized>;

/// One language's text of a declared key. Engine stores every language a
/// component declared — picking one is the reader's call.
pub use enclavid_embedded::text::Translation;

/// The embedded sections of a single component — the input the registry
/// builder accepts per catalog. Produced by `load_embedded` (in
/// `engine-compiler`) from a wasm component's `enclavid:embedded.*`
/// custom sections, which it checks in full.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComponentDecls {
    /// `enclavid:embedded.disclosure-fields.v1` — machine identifier
    /// list.
    pub disclosure_fields: HashSet<String>,
    /// `enclavid:embedded.i18n.v1` as the component ships it — each
    /// language's texts by key — or empty for a component with no texts.
    /// One byte string, so a catalog costs its section's length encoded and
    /// decoded alike.
    #[serde(with = "serde_bytes")]
    pub i18n: Vec<u8>,
}

/// A catalog's texts do not read: a bundle the compile did not make, since
/// the compile refuses a composition whose texts do not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogUnreadable(pub String);

impl std::fmt::Display for CatalogUnreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "a catalog's texts do not read: {}", self.0)
    }
}
impl std::error::Error for CatalogUnreadable {}

// ----- Top-level registry -----

/// Composition-wide registry of `enclavid:embedded/*` declarations.
/// One per `Executor::run` call; shared by `Arc` into every Store and into
/// the api view layer for ref-to-data projection.
///
/// Two fields, one per interface. Consumers call the store
/// matching the kind they're working with — there's no runtime kind
/// dispatch on this type, because every wire field's kind is known
/// at the call site (a `DisplayField.key` is always a disclosure-
/// field-ref, a `DisplayField.label` is always a localized-ref, etc.).
#[derive(Debug, Default)]
pub struct EmbeddedRegistry {
    pub disclosure_fields: DisclosureFieldsStore,
    pub localized: LocalizedStore,
}

impl EmbeddedRegistry {
    /// Begin building a registry. Consumers add one component per catalog
    /// in composition order (policy first), then call [`build`](
    /// EmbeddedRegistryBuilder::build) to populate the stores and freeze
    /// the structure.
    pub fn builder() -> EmbeddedRegistryBuilder {
        EmbeddedRegistryBuilder {
            components: Vec::new(),
        }
    }
}

// ----- Builder -----

/// Staging-area for [`EmbeddedRegistry`]. Add one component per
/// catalog in composition order (policy first), then `build()` to
/// freeze.
pub struct EmbeddedRegistryBuilder {
    /// `(content_hash, decls)` per component. The hash is the
    /// `catalog_hash` the caller computed from the component's raw
    /// embedded-section bytes — the same value the fuser routes that
    /// component's imports under.
    components: Vec<([u8; 32], ComponentDecls)>,
}

impl EmbeddedRegistryBuilder {
    /// Append a component's catalog under its content-hash. Order is
    /// composition order (policy first, then plugins as they appear in
    /// the `PluginInstance` list) and fixes the first-match order.
    pub fn add_component(&mut self, hash: [u8; 32], decls: ComponentDecls) {
        self.components.push((hash, decls));
    }

    /// Finalise: read every component's texts, and walk it into the two
    /// per-kind `key → data` stores keyed by catalog content-hash. After
    /// this returns the registry is immutable.
    pub fn build(self) -> Result<EmbeddedRegistry, CatalogUnreadable> {
        let n = self.components.len();
        let mut df: Vec<([u8; 32], Vec<(String, String)>)> = Vec::with_capacity(n);
        let mut loc: Vec<([u8; 32], Vec<(String, Vec<Translation>)>)> = Vec::with_capacity(n);
        for (hash, c) in self.components {
            df.push((
                hash,
                c.disclosure_fields
                    .into_iter()
                    .map(|k| (k.clone(), k))
                    .collect(),
            ));
            loc.push((hash, texts(&c.i18n)?.into_iter().collect()));
        }
        Ok(EmbeddedRegistry {
            disclosure_fields: RefStore::build_from(df),
            localized: RefStore::build_from(loc),
        })
    }
}

/// Each text of the i18n section `section`, in every language it has one in.
fn texts(section: &[u8]) -> Result<HashMap<String, Vec<Translation>>, CatalogUnreadable> {
    if section.is_empty() {
        return Ok(HashMap::new());
    }
    let catalog = enclavid_embedded::read_i18n(section).map_err(CatalogUnreadable)?;
    let mut texts: HashMap<String, Vec<Translation>> = HashMap::new();
    for (language, by_key) in catalog {
        for (key, text) in by_key {
            texts.entry(key).or_default().push(Translation {
                language: language.clone(),
                text,
            });
        }
    }
    Ok(texts)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A component declaring `df`, and `localized` as its texts: each key's
    /// text in each language.
    fn decls(df: &[&str], localized: &[(&str, &[(&str, &str)])]) -> ComponentDecls {
        let mut i18n = enclavid_embedded::I18nSection::default();
        for (key, rows) in localized {
            for (language, text) in *rows {
                i18n.languages
                    .entry(language.to_string())
                    .or_default()
                    .insert(key.to_string(), text.to_string());
            }
        }
        ComponentDecls {
            disclosure_fields: df.iter().map(|s| s.to_string()).collect(),
            i18n: serde_json::to_vec(&i18n).unwrap(),
        }
    }

    fn build(b: EmbeddedRegistryBuilder) -> EmbeddedRegistry {
        b.build().expect("the texts read")
    }

    fn text(translation: &Translation) -> &str {
        &translation.text
    }

    /// Distinct synthetic catalog hashes for tests. Production hashes
    /// come from `catalog_hash` over raw section bytes; the store only
    /// needs them distinct per catalog, so `[n; 32]` suffices here.
    fn h(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn empty_registry_resolve_misses() {
        let reg = EmbeddedRegistry::default();
        assert!(
            reg.disclosure_fields
                .resolve_strict(&h(0), "anything")
                .is_none()
        );
        assert!(reg.localized.resolve_strict(&h(0), "anything").is_none());
    }

    /// A catalog past the bounds a component's texts are held to fails the
    /// build rather than leaving its texts out.
    #[test]
    fn a_catalog_past_the_bounds_fails_the_build() {
        let mut b = EmbeddedRegistry::builder();
        b.add_component(h(0), decls(&[], &[("Broken", &[("en", "x")])]));
        assert!(b.build().is_err());
    }

    #[test]
    fn disclosure_field_resolves_to_its_key() {
        let mut b = EmbeddedRegistry::builder();
        b.add_component(h(0), decls(&["passport-number"], &[]));
        let reg = build(b);
        assert_eq!(
            reg.disclosure_fields
                .resolve_strict(&h(0), "passport-number")
                .map(String::as_str),
            Some("passport-number"),
        );
    }

    #[test]
    fn localized_resolves_to_translations() {
        let mut b = EmbeddedRegistry::builder();
        b.add_component(
            h(0),
            decls(
                &[],
                &[(
                    "consent-reason",
                    &[("en", "Verify identity"), ("ru", "Проверка")],
                )],
            ),
        );
        let reg = build(b);
        let ts = reg
            .localized
            .resolve_strict(&h(0), "consent-reason")
            .expect("resolves");
        assert_eq!(ts.len(), 2);
        assert!(
            ts.iter()
                .any(|t| t.language == "en" && text(t) == "Verify identity")
        );
        assert!(
            ts.iter()
                .any(|t| t.language == "ru" && text(t) == "Проверка")
        );
    }

    #[test]
    fn rejects_undeclared_key() {
        let mut b = EmbeddedRegistry::builder();
        b.add_component(h(0), decls(&["a"], &[("b", &[("en", "x")])]));
        let reg = build(b);
        assert!(
            reg.disclosure_fields
                .resolve_strict(&h(0), "missing")
                .is_none()
        );
        assert!(reg.localized.resolve_strict(&h(0), "missing").is_none());
    }

    #[test]
    fn rejects_cross_catalog_key() {
        // A key declared by one catalog does not resolve against
        // another's hash — strict per-catalog isolation.
        let mut b = EmbeddedRegistry::builder();
        b.add_component(h(0), decls(&["policy-only"], &[]));
        b.add_component(h(1), decls(&["plugin-only"], &[]));
        let reg = build(b);
        assert!(
            reg.disclosure_fields
                .resolve_strict(&h(0), "plugin-only")
                .is_none()
        );
        assert!(
            reg.disclosure_fields
                .resolve_strict(&h(1), "policy-only")
                .is_none()
        );
        assert!(
            reg.disclosure_fields
                .resolve_strict(&h(0), "policy-only")
                .is_some()
        );
        assert!(
            reg.disclosure_fields
                .resolve_strict(&h(1), "plugin-only")
                .is_some()
        );
    }

    #[test]
    fn distinct_declared_count_dedups_across_catalogs() {
        // The consent covert-channel bound: distinct DF keys across the
        // whole composition, deduped (a key in two catalogs counts once).
        let mut b = EmbeddedRegistry::builder();
        b.add_component(h(0), decls(&["a", "b"], &[]));
        b.add_component(h(1), decls(&["b", "c"], &[])); // 'b' duplicates
        let reg = build(b);
        assert_eq!(reg.disclosure_fields.distinct_declared_count(), 3);
    }

    #[test]
    fn unknown_catalog_misses() {
        let reg = build(EmbeddedRegistry::builder());
        assert!(reg.disclosure_fields.resolve_strict(&h(0), "x").is_none());
        assert!(reg.localized.resolve_strict(&h(0), "x").is_none());
    }

    // ---------- first-match resolution across merged catalogs ----------
    //
    // The merged path (DF) resolves a bare key by first match across every
    // catalog in composition order (policy first). Scoping / anti-forgery no
    // longer rides on a token — the ref is an unforgeable resource handle —
    // so these pin only the resolution order, which the store keeps for
    // either kind.

    /// A key any component declared resolves — including a plugin's, even
    /// when the policy has no such section: a plugin MAY declare DF keys
    /// of its own.
    #[test]
    fn first_match_resolves_from_any_catalog() {
        let mut b = EmbeddedRegistry::builder();
        b.add_component(h(0), ComponentDecls::default()); // policy, empty
        b.add_component(
            h(1),
            decls(&["passport_number"], &[("plugin_label", &[("en", "hi")])]),
        );
        let reg = build(b);
        assert!(
            reg.disclosure_fields
                .resolve_first_match("passport_number")
                .is_some(),
            "a DF key declared by the plugin resolves via first match"
        );
        assert!(
            reg.localized.resolve_first_match("plugin_label").is_some(),
            "a plugin's own i18n label resolves via first match"
        );
    }

    /// When two catalogs declare the same key, first match returns the
    /// EARLIER catalog's value (composition order, policy first).
    #[test]
    fn first_match_prefers_earlier_catalog() {
        let mut b = EmbeddedRegistry::builder();
        b.add_component(h(0), decls(&[], &[("dup", &[("en", "policy")])])); // policy
        b.add_component(h(1), decls(&[], &[("dup", &[("en", "plugin")])])); // plugin
        let reg = build(b);
        let ts = reg.localized.resolve_first_match("dup").expect("resolves");
        assert_eq!(
            text(&ts[0]),
            "policy",
            "first match resolves to the earliest catalog"
        );
    }

    /// A key no catalog declared misses under first match — the host fn
    /// turns this into the "no component declared key" trap.
    #[test]
    fn first_match_misses_undeclared_key() {
        let mut b = EmbeddedRegistry::builder();
        b.add_component(h(0), decls(&["allowed_key"], &[])); // policy
        b.add_component(h(1), ComponentDecls::default()); // plugin, empty
        let reg = build(b);
        assert!(
            reg.disclosure_fields
                .resolve_first_match("forbidden_key")
                .is_none(),
            "an undeclared key misses across every merged catalog"
        );
    }
}
