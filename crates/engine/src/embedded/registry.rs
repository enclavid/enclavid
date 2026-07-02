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
//! which component called. See [`super::host`] and
//! [`RefStore::get_token_first_match`](super::store::RefStore::
//! get_token_first_match).
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
//! The registry is **immutable per run**: built once in
//! [`Runner::run`](crate::Runner::run) from `load_embedded` output for
//! every component, frozen, then shared by `Arc` into the policy
//! `HostState`.
//!
//! ## Token format
//!
//! Refs are `hex(BLAKE3-keyed(ref_key, slot_be ‖ tag ‖ ':' ‖ key))
//! [..32]` — opaque 32-character lowercase-hex strings. The
//! `ref_key` is TEE-only (derived per-policy from `tee_seal_key +
//! policy_ref` by the api crate), so a guest WASM component can't
//! synthesise a valid ref by guessing the format: it can't compute the
//! keyed hash. The reverse index in `by_token` then turns membership
//! into pure data — every declared `(slot, key)` sits in the map, and
//! first-match resolution mints the earliest-slot token whose entry is
//! present.

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Translation {
    pub language: String,
    pub text: String,
}

/// Parsed embedded sections for a single component — the input the
/// registry builder accepts per slot. Produced by
/// [`load_embedded`](super::decls::load_embedded) from a wasm
/// component's `enclavid:embedded.*` custom sections.
#[derive(Debug, Default, Clone)]
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
/// One per [`Runner::run`](crate::Runner::run) call; shared by `Arc`
/// into every Store and into the api view layer for ref-to-data
/// projection.
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
    /// Begin building a registry under `ref_key`. Consumers add one
    /// component per slot in slot order, then call [`build`](
    /// EmbeddedRegistryBuilder::build) to populate the stores and
    /// freeze the structure.
    ///
    /// `ref_key` is the BLAKE3-keyed-hash secret powering
    /// `compute_ref` (see [`super::store`]). Production callers
    /// derive it from `tee_seal_key + policy_ref` in the api crate;
    /// tests pass a fixed non-secret value.
    pub fn builder(ref_key: [u8; 32]) -> EmbeddedRegistryBuilder {
        EmbeddedRegistryBuilder {
            components: Vec::new(),
            ref_key,
        }
    }
}

// ----- Builder -----

/// Staging-area for [`EmbeddedRegistry`]. Add one component per
/// catalog in composition order (policy first), then `build()` to
/// freeze.
pub struct EmbeddedRegistryBuilder {
    /// `(content_hash, decls)` per component. The hash is the
    /// [`catalog_hash`](super::hash::catalog_hash) the caller computed
    /// from the component's raw embedded-section bytes — the same value
    /// the fuser routes that component's imports under.
    components: Vec<([u8; 32], ComponentDecls)>,
    ref_key: [u8; 32],
}

impl EmbeddedRegistryBuilder {
    /// Append a component's catalog under its content-hash. Order is
    /// composition order (policy first, then plugins as they appear in
    /// the `PluginInstance` list) and fixes the first-match order.
    pub fn add_component(&mut self, hash: [u8; 32], decls: ComponentDecls) {
        self.components.push((hash, decls));
    }

    /// Finalise: walk every component, compute every `(catalog_hash,
    /// kind, key)` token under the builder's `ref_key`, populate all
    /// three stores' `by_token` maps. After this returns the registry
    /// is immutable.
    pub fn build(self) -> EmbeddedRegistry {
        // Materialise the per-catalog iterables the generic
        // `RefStore::build_from` consumes. One walk over
        // `self.components`, destructuring each into the three per-kind
        // catalogs — each kind ends up with its own `RefStore`
        // populated independently under the same `ref_key`; kind
        // separation rides on the TAG byte fed into BLAKE3 inside
        // `compute_ref`.
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
            disclosure_fields: RefStore::build_from(df, self.ref_key),
            localized: RefStore::build_from(loc, self.ref_key),
            icons: RefStore::build_from(icons, self.ref_key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed test key — non-secret, identifiable in fixtures. Production
    /// callers derive `ref_key` from `tee_seal_key + policy_ref`; tests
    /// don't need that ceremony, only a stable value so token round-trips
    /// stay deterministic across runs.
    const TEST_REF_KEY: [u8; 32] = [7u8; 32];

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
    fn empty_registry_resolve_traps() {
        let reg = EmbeddedRegistry::default();
        assert!(reg.disclosure_fields.get_token(&h(0), "anything").is_none());
        assert!(reg.localized.get_token(&h(0), "anything").is_none());
    }

    #[test]
    fn disclosure_field_resolve_and_lookup() {
        let mut b = EmbeddedRegistry::builder(TEST_REF_KEY);
        b.add_component(h(0), decls(&["passport-number"], &[]));
        let reg = b.build();
        let token = reg.disclosure_fields.get_token(&h(0), "passport-number").unwrap();
        // Opaque 32-char hex digest. Stability via round-trip (lookup
        // returns the declared raw key), not via literal value.
        assert_eq!(token.len(), 32);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(
            reg.disclosure_fields.lookup(&token).map(String::as_str),
            Some("passport-number"),
        );
        assert!(reg.disclosure_fields.contains(&token));
        // Wrong store — localized.lookup misses the DF token (kind
        // separation rides on the TAG byte inside BLAKE3 input).
        assert!(reg.localized.lookup(&token).is_none());
    }

    #[test]
    fn localized_resolve_and_lookup_returns_translations() {
        let mut b = EmbeddedRegistry::builder(TEST_REF_KEY);
        b.add_component(
            h(0),
            decls(
                &[],
                &[("consent-reason", &[("en", "Verify identity"), ("ru", "Проверка")])],
            ),
        );
        let reg = b.build();
        let token = reg.localized.get_token(&h(0), "consent-reason").unwrap();
        assert_eq!(token.len(), 32);
        let ts = reg.localized.lookup(&token).expect("token resolves");
        assert_eq!(ts.len(), 2);
        assert!(ts.iter().any(|t| t.language == "en" && t.text == "Verify identity"));
        assert!(ts.iter().any(|t| t.language == "ru" && t.text == "Проверка"));
    }

    #[test]
    fn rejects_undeclared_key() {
        let mut b = EmbeddedRegistry::builder(TEST_REF_KEY);
        b.add_component(h(0), decls(&["a"], &[("b", &[("en", "x")])]));
        let reg = b.build();
        assert!(reg.disclosure_fields.get_token(&h(0), "missing").is_none());
        assert!(reg.localized.get_token(&h(0), "missing").is_none());
    }

    #[test]
    fn rejects_cross_catalog_key() {
        // A key declared by one catalog does not resolve against
        // another's hash — strict per-catalog isolation.
        let mut b = EmbeddedRegistry::builder(TEST_REF_KEY);
        b.add_component(h(0), decls(&["policy-only"], &[]));
        b.add_component(h(1), decls(&["plugin-only"], &[]));
        let reg = b.build();
        assert!(reg.disclosure_fields.get_token(&h(0), "plugin-only").is_none());
        assert!(reg.disclosure_fields.get_token(&h(1), "policy-only").is_none());
        assert!(reg.disclosure_fields.get_token(&h(0), "policy-only").is_some());
        assert!(reg.disclosure_fields.get_token(&h(1), "plugin-only").is_some());
    }

    #[test]
    fn same_key_in_both_stores_yields_distinct_tokens() {
        let mut b = EmbeddedRegistry::builder(TEST_REF_KEY);
        b.add_component(h(0), decls(&["shared"], &[("shared", &[("en", "x")])]));
        let reg = b.build();
        let df = reg.disclosure_fields.get_token(&h(0), "shared").unwrap();
        let l = reg.localized.get_token(&h(0), "shared").unwrap();
        assert_ne!(df, l);
        assert!(reg.localized.lookup(&df).is_none());
        assert!(reg.disclosure_fields.lookup(&l).is_none());
    }

    #[test]
    fn lookup_misses_unregistered_string() {
        let mut b = EmbeddedRegistry::builder(TEST_REF_KEY);
        b.add_component(h(0), decls(&["a"], &[]));
        let reg = b.build();
        assert!(reg.disclosure_fields.lookup("a").is_none());
        // Arbitrary non-token strings miss — nothing but a genuinely
        // issued opaque token is in the by_token map.
        assert!(reg.disclosure_fields.lookup("9:d:a").is_none());
        assert!(reg.disclosure_fields.lookup("0:x:a").is_none());
    }

    #[test]
    fn unknown_catalog_traps() {
        let reg = EmbeddedRegistry::builder(TEST_REF_KEY).build();
        assert!(reg.disclosure_fields.get_token(&h(0), "x").is_none());
        assert!(reg.localized.get_token(&h(0), "x").is_none());
    }

    #[test]
    fn different_ref_keys_produce_different_tokens() {
        // Forgery defence: same `(catalog_hash, key)` under two distinct
        // `ref_key`s produces two completely unrelated tokens — and
        // neither registry recognises the other's.
        let mut a = EmbeddedRegistry::builder([1u8; 32]);
        a.add_component(h(0), decls(&["passport-number"], &[]));
        let reg_a = a.build();
        let mut b = EmbeddedRegistry::builder([2u8; 32]);
        b.add_component(h(0), decls(&["passport-number"], &[]));
        let reg_b = b.build();
        let token_a = reg_a.disclosure_fields.get_token(&h(0), "passport-number").unwrap();
        let token_b = reg_b.disclosure_fields.get_token(&h(0), "passport-number").unwrap();
        assert_ne!(token_a, token_b);
        assert!(reg_a.disclosure_fields.lookup(&token_b).is_none());
        assert!(reg_b.disclosure_fields.lookup(&token_a).is_none());
    }

    // ---------- first-match resolution across merged catalogs ----------
    //
    // The merged path (DF always; i18n/icons when not strictly routed)
    // resolves a bare key by first match across every catalog in
    // composition order (policy first). The tests below pin the
    // `get_token_first_match` primitive. Scoping / anti-forgery rides on
    // catalog membership + the keyed-hash token (see the cross-registry
    // test above), not on a positional slot.

    /// A key any component declared resolves — including a plugin's,
    /// even when the policy has no such section. This is the well-known
    /// plugin's shape: it ships its own i18n / icons and (optionally) DF
    /// keys the policy never restated.
    #[test]
    fn first_match_resolves_from_any_catalog() {
        let mut b = EmbeddedRegistry::builder(TEST_REF_KEY);
        b.add_component(h(0), ComponentDecls::default()); // policy, empty
        b.add_component(h(1), decls(&["passport_number"], &[("plugin_label", &[("en", "hi")])]));
        let reg = b.build();

        assert!(
            reg.disclosure_fields
                .get_token_first_match("passport_number")
                .is_some(),
            "a DF key declared by the plugin resolves via first match"
        );
        assert!(
            reg.localized.get_token_first_match("plugin_label").is_some(),
            "a plugin's own i18n label resolves via first match"
        );
    }

    /// When two catalogs declare the same key, first match returns the
    /// EARLIER catalog's token (composition order, policy first) —
    /// deterministic and harmless for DF (identical keys; the policy
    /// chooses what it discloses / the applicant consents).
    #[test]
    fn first_match_prefers_earlier_catalog() {
        let mut b = EmbeddedRegistry::builder(TEST_REF_KEY);
        b.add_component(h(0), decls(&["dup"], &[])); // policy
        b.add_component(h(1), decls(&["dup"], &[])); // plugin
        let reg = b.build();

        let first = reg.disclosure_fields.get_token_first_match("dup").unwrap();
        let earliest = reg.disclosure_fields.get_token(&h(0), "dup").unwrap();
        assert_eq!(
            first, earliest,
            "first match resolves to the first catalog's token when both declare the key"
        );
    }

    /// A key no catalog declared misses under first match — the host
    /// fn turns this into the "no component declared key" trap.
    #[test]
    fn first_match_misses_undeclared_key() {
        let mut b = EmbeddedRegistry::builder(TEST_REF_KEY);
        b.add_component(h(0), decls(&["allowed_key"], &[])); // policy
        b.add_component(h(1), ComponentDecls::default()); // plugin, empty
        let reg = b.build();

        assert!(
            reg.disclosure_fields
                .get_token_first_match("forbidden_key")
                .is_none(),
            "an undeclared key misses across every merged catalog"
        );
    }
}
