//! Per-component `enclavid:embedded/*` ref scoping.
//!
//! Two **public stores** on [`EmbeddedRegistry`], one per
//! `enclavid:embedded/*` interface:
//!
//!   * [`DisclosureFieldsStore`] — machine identifiers. `lookup`
//!     returns the raw declared key (`&str`) — the literal the
//!     consumer SDK dispatches on.
//!   * [`LocalizedStore`] — translation catalogs. `lookup` returns
//!     the full `[Translation]` row set; locale-picking is the
//!     consumer's call.
//!
//! Both wrap the same private generic [`RefStore`](super::store::
//! RefStore) so the membership / get_token / lookup mechanics live
//! in one place. The public types are thin newtypes that pin a
//! typed `lookup` return — `&str` vs `&[Translation]` — at the API
//! boundary.
//!
//! The registry is **immutable per run**: built once in
//! [`Runner::run`](crate::Runner::run) from `load_embedded` output for
//! every component, frozen, then shared by `Arc` into every Store
//! (policy `HostState` + each plugin `PluginHostState`).
//!
//! ## Token format
//!
//! Refs are `hex(BLAKE3-keyed(ref_key, slot_be ‖ tag ‖ ':' ‖ key))
//! [..32]` — opaque 32-character lowercase-hex strings. The
//! `ref_key` is TEE-only (derived per-policy from `tee_seal_key +
//! policy_ref` by the api crate), so a guest WASM component can't
//! synthesise a foreign-slot ref by guessing the format. The
//! `get_token` path validates the token exists in `by_token` before
//! returning, and the only component that can produce a slot-X
//! token via host-fn is the one bound to slot X in the closure —
//! but even without that closure binding, the BLAKE3-keyed prefix
//! means assembling a foreign-slot ref from raw bytes is
//! cryptographically infeasible.

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

/// Slot index assigned to a participating component. Slot 0 is always
/// the policy; slots 1..N are plugins in `PluginInstance` list order.
pub type Slot = usize;

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

/// Staging-area for [`EmbeddedRegistry`]. Add one component per slot
/// in slot order, then `build()` to freeze.
pub struct EmbeddedRegistryBuilder {
    components: Vec<ComponentDecls>,
    ref_key: [u8; 32],
}

impl EmbeddedRegistryBuilder {
    /// Append a component at the next slot index. Order matters: the
    /// nth call to `add_component` becomes slot `n`. Caller is
    /// responsible for invoking in the slot order it intends (policy
    /// first, then plugins as they appear in `PluginInstance` list).
    pub fn add_component(&mut self, decls: ComponentDecls) -> Slot {
        let slot = self.components.len();
        self.components.push(decls);
        slot
    }

    /// Finalise: walk every component, compute every `(slot, kind,
    /// key)` token under the builder's `ref_key`, populate all three
    /// stores' `by_token` maps. After this returns the registry is
    /// immutable.
    pub fn build(self) -> EmbeddedRegistry {
        // Materialise the per-slot iterables the generic
        // `RefStore::build_from` consumes. One walk over
        // `self.components`, destructuring each into the three
        // per-kind slices — each kind ends up with its own
        // `RefStore` populated independently under the same
        // `ref_key`; kind separation rides on the TAG byte fed into
        // BLAKE3 inside `compute_ref`.
        let n = self.components.len();
        let mut df_slots: Vec<Vec<(String, String)>> = Vec::with_capacity(n);
        let mut l_slots: Vec<Vec<(String, Vec<Translation>)>> = Vec::with_capacity(n);
        let mut icon_slots: Vec<Vec<(String, String)>> = Vec::with_capacity(n);
        for c in self.components {
            df_slots.push(
                c.disclosure_fields
                    .into_iter()
                    .map(|k| (k.clone(), k))
                    .collect(),
            );
            l_slots.push(c.localized.into_iter().collect());
            icon_slots.push(c.icons.into_iter().map(|n| (n.clone(), n)).collect());
        }
        EmbeddedRegistry {
            disclosure_fields: RefStore::build_from(df_slots, self.ref_key),
            localized: RefStore::build_from(l_slots, self.ref_key),
            icons: RefStore::build_from(icon_slots, self.ref_key),
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

    #[test]
    fn empty_registry_mint_traps() {
        let reg = EmbeddedRegistry::default();
        assert!(reg.disclosure_fields.get_token(0, "anything").is_none());
        assert!(reg.localized.get_token(0, "anything").is_none());
    }

    #[test]
    fn disclosure_field_mint_and_lookup() {
        let mut b = EmbeddedRegistry::builder(TEST_REF_KEY);
        b.add_component(decls(&["passport-number"], &[]));
        let reg = b.build();
        let token = reg.disclosure_fields.get_token(0, "passport-number").unwrap();
        // Phase B: opaque 32-char hex digest. Stability via round-trip
        // (lookup returns the declared raw key), not via literal value.
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
    fn localized_mint_and_lookup_returns_translations() {
        let mut b = EmbeddedRegistry::builder(TEST_REF_KEY);
        b.add_component(decls(
            &[],
            &[("consent-reason", &[("en", "Verify identity"), ("ru", "Проверка")])],
        ));
        let reg = b.build();
        let token = reg.localized.get_token(0, "consent-reason").unwrap();
        assert_eq!(token.len(), 32);
        let ts = reg.localized.lookup(&token).expect("token resolves");
        assert_eq!(ts.len(), 2);
        assert!(ts.iter().any(|t| t.language == "en" && t.text == "Verify identity"));
        assert!(ts.iter().any(|t| t.language == "ru" && t.text == "Проверка"));
    }

    #[test]
    fn rejects_undeclared_key() {
        let mut b = EmbeddedRegistry::builder(TEST_REF_KEY);
        b.add_component(decls(&["a"], &[("b", &[("en", "x")])]));
        let reg = b.build();
        assert!(reg.disclosure_fields.get_token(0, "missing").is_none());
        assert!(reg.localized.get_token(0, "missing").is_none());
    }

    #[test]
    fn rejects_cross_slot_key() {
        let mut b = EmbeddedRegistry::builder(TEST_REF_KEY);
        b.add_component(decls(&["policy-only"], &[]));
        b.add_component(decls(&["plugin-only"], &[]));
        let reg = b.build();
        assert!(reg.disclosure_fields.get_token(0, "plugin-only").is_none());
        assert!(reg.disclosure_fields.get_token(1, "policy-only").is_none());
        assert!(reg.disclosure_fields.get_token(0, "policy-only").is_some());
        assert!(reg.disclosure_fields.get_token(1, "plugin-only").is_some());
    }

    #[test]
    fn same_key_in_both_stores_yields_distinct_tokens() {
        let mut b = EmbeddedRegistry::builder(TEST_REF_KEY);
        b.add_component(decls(&["shared"], &[("shared", &[("en", "x")])]));
        let reg = b.build();
        let df = reg.disclosure_fields.get_token(0, "shared").unwrap();
        let l = reg.localized.get_token(0, "shared").unwrap();
        assert_ne!(df, l);
        assert!(reg.localized.lookup(&df).is_none());
        assert!(reg.disclosure_fields.lookup(&l).is_none());
    }

    #[test]
    fn lookup_misses_unminted_string() {
        let mut b = EmbeddedRegistry::builder(TEST_REF_KEY);
        b.add_component(decls(&["a"], &[]));
        let reg = b.build();
        assert!(reg.disclosure_fields.lookup("a").is_none());
        // Phase A debug-format strings no longer collide with the
        // Phase B opaque hex tokens — neither is in the by_token map.
        assert!(reg.disclosure_fields.lookup("9:d:a").is_none());
        assert!(reg.disclosure_fields.lookup("0:x:a").is_none());
    }

    #[test]
    fn unknown_slot_traps() {
        let reg = EmbeddedRegistry::builder(TEST_REF_KEY).build();
        assert!(reg.disclosure_fields.get_token(0, "x").is_none());
        assert!(reg.localized.get_token(0, "x").is_none());
    }

    #[test]
    fn different_ref_keys_produce_different_tokens() {
        // Forgery defence: same `(slot, key)` under two distinct
        // `ref_key`s produces two completely unrelated tokens — and
        // neither registry recognises the other's.
        let mut a = EmbeddedRegistry::builder([1u8; 32]);
        a.add_component(decls(&["passport-number"], &[]));
        let reg_a = a.build();
        let mut b = EmbeddedRegistry::builder([2u8; 32]);
        b.add_component(decls(&["passport-number"], &[]));
        let reg_b = b.build();
        let token_a = reg_a.disclosure_fields.get_token(0, "passport-number").unwrap();
        let token_b = reg_b.disclosure_fields.get_token(0, "passport-number").unwrap();
        assert_ne!(token_a, token_b);
        assert!(reg_a.disclosure_fields.lookup(&token_b).is_none());
        assert!(reg_b.disclosure_fields.lookup(&token_a).is_none());
    }
}
