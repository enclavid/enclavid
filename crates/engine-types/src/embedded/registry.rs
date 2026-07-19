//! `enclavid:embedded/*` ref scoping — first match across catalogs.
//!
//! Three **public stores** on [`EmbeddedRegistry`], one per
//! `enclavid:embedded/*` interface:
//!
//!   * [`DisclosureFieldsStore`] — machine identifiers consumed by
//!     the consumer SDK as `DisplayField.key`. The one kind that
//!     reaches the consumer.
//!   * [`LocalizedStore`] — translation catalogs. Resolved to
//!     applicant-locale text inside the TEE before any wire send;
//!     consumer never sees refs or text.
//!   * [`IconStore`] — frontend dispatch names. Reach the applicant
//!     frontend, never the consumer envelope.
//!
//! Each component (policy at slot 0, plugins at slots 1..N) declares
//! its own keys per kind, and all three stores resolve a bare key by
//! **first match across the merged catalogs** (composition order,
//! policy first). This mirrors what wac single-store fusion does to
//! the imports: the per-component `enclavid:embedded/i18n` imports
//! unify into one host impl, so the host resolves without knowing
//! which component called. See the host resolvers in `engine-executor`
//! and `RefStore::resolve_first_match`.
//!
//! DF is not resolution-gated to the policy even though it reaches the
//! consumer: the policy chooses which `display-field`s it discloses
//! and the applicant consents to every `(key, label, value)` on
//! screen (the sole auditor). That is the bound on what leaks, not the
//! resolution slot. Each component's DF section is size-capped at
//! build time (`MAX_DECLARED_DISCLOSURE_FIELDS`).
//!
//! All three wrap the same private generic [`RefStore`](super::store::
//! RefStore) so the membership / get_token / lookup mechanics live in
//! one place.
//!
//! The registry is **immutable per run**: built once in `Executor::run`
//! (in `engine-executor`) from `load_embedded` output for every
//! component, frozen, then shared by `Arc` into the policy `HostState`.
//! It is consulted only when the host MINTS a ref resource; the resource
//! then carries the resolved data itself, so nothing downstream
//! re-consults the registry.

use std::collections::{HashMap, HashSet};

use super::store::{DisclosureFields, Icon, Localized, RefStore};

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

/// Type alias for the `enclavid:embedded/icons` store. `lookup`
/// returns `Option<&String>` — the declared icon name the applicant
/// frontend dispatches against its bundled SVG library.
pub type IconStore = RefStore<Icon>;

/// One `(language, text)` row inside a localized declaration. Engine
/// stores every translation a component declared verbatim — locale
/// picking is the consumer's call.
/// serde: part of the L2 cwasm-cache bundle — a component's parsed
/// catalog is stored beside its cwasm so a cache hit rebuilds the
/// embedded registry without re-pulling the artifact.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Translation {
    pub language: String,
    pub text: String,
}

/// Parsed embedded sections for a single component — the input the
/// registry builder accepts per slot. Produced by `load_embedded` (in
/// `engine-compiler`) from a wasm component's `enclavid:embedded.*`
/// custom sections.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComponentDecls {
    /// `enclavid:embedded.disclosure-fields.v1` — machine identifier
    /// list.
    pub disclosure_fields: HashSet<String>,
    /// `enclavid:embedded.i18n.v1` — `key → translations` catalog.
    pub localized: HashMap<String, Vec<Translation>>,
    /// `enclavid:embedded.icons.v1` — frontend-dispatched icon names.
    pub icons: HashSet<String>,
}

// ----- Top-level registry -----

/// Composition-wide registry of `enclavid:embedded/*` declarations.
/// One per `Executor::run` call; shared by `Arc` into every Store and into
/// the api view layer for ref-to-data projection.
///
/// Three fields, one per interface. Consumers call the store
/// matching the kind they're working with — there's no runtime kind
/// dispatch on this type, because every wire field's kind is known
/// at the call site (a `DisplayField.key` is always a disclosure-
/// field-ref, a `DisplayField.label` is always a localized-ref,
/// `CaptureStep.icon` is always an icon-ref, etc.).
#[derive(Debug, Default)]
pub struct EmbeddedRegistry {
    pub disclosure_fields: DisclosureFieldsStore,
    pub localized: LocalizedStore,
    pub icons: IconStore,
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

    /// Finalise: walk every component into the three per-kind
    /// `key → data` stores keyed by catalog content-hash. After this
    /// returns the registry is immutable.
    pub fn build(self) -> EmbeddedRegistry {
        let n = self.components.len();
        let mut df: Vec<([u8; 32], Vec<(String, String)>)> = Vec::with_capacity(n);
        let mut loc: Vec<([u8; 32], Vec<(String, Vec<Translation>)>)> = Vec::with_capacity(n);
        let mut icons: Vec<([u8; 32], Vec<(String, String)>)> = Vec::with_capacity(n);
        for (hash, c) in self.components {
            df.push((
                hash,
                c.disclosure_fields.into_iter().map(|k| (k.clone(), k)).collect(),
            ));
            loc.push((hash, c.localized.into_iter().collect()));
            icons.push((hash, c.icons.into_iter().map(|n| (n.clone(), n)).collect()));
        }
        EmbeddedRegistry {
            disclosure_fields: RefStore::build_from(df),
            localized: RefStore::build_from(loc),
            icons: RefStore::build_from(icons),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decls(df: &[&str], localized: &[(&str, &[(&str, &str)])]) -> ComponentDecls {
        ComponentDecls {
            disclosure_fields: df.iter().map(|s| s.to_string()).collect(),
            localized: localized
                .iter()
                .map(|(key, rows)| {
                    (
                        key.to_string(),
                        rows.iter()
                            .map(|(lang, text)| Translation {
                                language: lang.to_string(),
                                text: text.to_string(),
                            })
                            .collect(),
                    )
                })
                .collect(),
            icons: Default::default(),
        }
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
        assert!(reg.disclosure_fields.resolve_strict(&h(0), "anything").is_none());
        assert!(reg.localized.resolve_strict(&h(0), "anything").is_none());
    }

    #[test]
    fn disclosure_field_resolves_to_its_key() {
        let mut b = EmbeddedRegistry::builder();
        b.add_component(h(0), decls(&["passport-number"], &[]));
        let reg = b.build();
        assert_eq!(
            reg.disclosure_fields.resolve_strict(&h(0), "passport-number").map(String::as_str),
            Some("passport-number"),
        );
    }

    #[test]
    fn localized_resolves_to_translations() {
        let mut b = EmbeddedRegistry::builder();
        b.add_component(
            h(0),
            decls(&[], &[("consent-reason", &[("en", "Verify identity"), ("ru", "Проверка")])]),
        );
        let reg = b.build();
        let ts = reg.localized.resolve_strict(&h(0), "consent-reason").expect("resolves");
        assert_eq!(ts.len(), 2);
        assert!(ts.iter().any(|t| t.language == "en" && t.text == "Verify identity"));
        assert!(ts.iter().any(|t| t.language == "ru" && t.text == "Проверка"));
    }

    #[test]
    fn rejects_undeclared_key() {
        let mut b = EmbeddedRegistry::builder();
        b.add_component(h(0), decls(&["a"], &[("b", &[("en", "x")])]));
        let reg = b.build();
        assert!(reg.disclosure_fields.resolve_strict(&h(0), "missing").is_none());
        assert!(reg.localized.resolve_strict(&h(0), "missing").is_none());
    }

    #[test]
    fn rejects_cross_catalog_key() {
        // A key declared by one catalog does not resolve against
        // another's hash — strict per-catalog isolation.
        let mut b = EmbeddedRegistry::builder();
        b.add_component(h(0), decls(&["policy-only"], &[]));
        b.add_component(h(1), decls(&["plugin-only"], &[]));
        let reg = b.build();
        assert!(reg.disclosure_fields.resolve_strict(&h(0), "plugin-only").is_none());
        assert!(reg.disclosure_fields.resolve_strict(&h(1), "policy-only").is_none());
        assert!(reg.disclosure_fields.resolve_strict(&h(0), "policy-only").is_some());
        assert!(reg.disclosure_fields.resolve_strict(&h(1), "plugin-only").is_some());
    }

    #[test]
    fn distinct_declared_count_dedups_across_catalogs() {
        // The consent covert-channel bound: distinct DF keys across the
        // whole composition, deduped (a key in two catalogs counts once).
        let mut b = EmbeddedRegistry::builder();
        b.add_component(h(0), decls(&["a", "b"], &[]));
        b.add_component(h(1), decls(&["b", "c"], &[])); // 'b' duplicates
        let reg = b.build();
        assert_eq!(reg.disclosure_fields.distinct_declared_count(), 3);
    }

    #[test]
    fn unknown_catalog_misses() {
        let reg = EmbeddedRegistry::builder().build();
        assert!(reg.disclosure_fields.resolve_strict(&h(0), "x").is_none());
        assert!(reg.localized.resolve_strict(&h(0), "x").is_none());
    }

    // ---------- first-match resolution across merged catalogs ----------
    //
    // The merged path (DF always; i18n/icons when not strictly routed)
    // resolves a bare key by first match across every catalog in
    // composition order (policy first). Scoping / anti-forgery no longer
    // rides on a token — the ref is an unforgeable resource handle — so
    // these pin only the resolution order.

    /// A key any component declared resolves — including a plugin's, even
    /// when the policy has no such section. This is the well-known
    /// plugin's shape: it ships its own i18n / icons and (optionally) DF
    /// keys the policy never restated.
    #[test]
    fn first_match_resolves_from_any_catalog() {
        let mut b = EmbeddedRegistry::builder();
        b.add_component(h(0), ComponentDecls::default()); // policy, empty
        b.add_component(h(1), decls(&["passport_number"], &[("plugin_label", &[("en", "hi")])]));
        let reg = b.build();
        assert!(
            reg.disclosure_fields.resolve_first_match("passport_number").is_some(),
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
        let reg = b.build();
        let ts = reg.localized.resolve_first_match("dup").expect("resolves");
        assert_eq!(ts[0].text, "policy", "first match resolves to the earliest catalog");
    }

    /// A key no catalog declared misses under first match — the host fn
    /// turns this into the "no component declared key" trap.
    #[test]
    fn first_match_misses_undeclared_key() {
        let mut b = EmbeddedRegistry::builder();
        b.add_component(h(0), decls(&["allowed_key"], &[])); // policy
        b.add_component(h(1), ComponentDecls::default()); // plugin, empty
        let reg = b.build();
        assert!(
            reg.disclosure_fields.resolve_first_match("forbidden_key").is_none(),
            "an undeclared key misses across every merged catalog"
        );
    }
}
