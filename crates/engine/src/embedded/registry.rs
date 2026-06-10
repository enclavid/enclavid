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
//! ## Phase A — debuggable refs
//!
//! Refs are `"{slot}:{kind_tag}:{key}"` (e.g. `"1:d:passport-number"`
//! for a disclosure-field, `"0:l:consent-reason"` for a localized
//! ref). Inspectable in logs, easy to reason about during the
//! plumbing migration. **Not** a forgery-resistance boundary on its
//! own — refs are unforgeable only because the get_token path
//! validates the token exists in `by_token` before returning, and
//! the only component that can produce a slot-X token is the one
//! bound to slot X in the host-fn closure. Phase B (HMAC) makes
//! the format itself opaque.
//!
//! ## Phase B — HMAC opaque refs (future)
//!
//! `compute_ref` becomes `hex(HMAC(session_secret, slot ‖ tag ‖
//! key))[..16]`. Reverse-index built identically; the registry is
//! the only thing that knows every (slot, kind, key) triple, so
//! it's also the only thing that can populate `by_token`. Outside
//! the TEE — or inside a malicious component — assembling a
//! foreign-slot ref is cryptographically infeasible.

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
}

// ----- Top-level registry -----

/// Composition-wide registry of `enclavid:embedded/*` declarations.
/// One per [`Runner::run`](crate::Runner::run) call; shared by `Arc`
/// into every Store and into the api view layer for ref-to-data
/// projection.
///
/// Two fields, one per interface. Consumers call the store matching
/// the kind they're working with — there's no runtime kind dispatch
/// on this type, because every wire field's kind is known at the
/// call site (a `DisplayField.key` is always a disclosure-field-ref,
/// a `DisplayField.label` is always a localized-ref, etc.).
#[derive(Debug, Default)]
pub struct EmbeddedRegistry {
    pub disclosure_fields: DisclosureFieldsStore,
    pub localized: LocalizedStore,
}

impl EmbeddedRegistry {
    /// Begin building a registry. Consumers add one component per
    /// slot in slot order, then call [`finish`](
    /// EmbeddedRegistryBuilder::finish) to populate the stores and
    /// freeze the structure.
    pub fn builder() -> EmbeddedRegistryBuilder {
        EmbeddedRegistryBuilder::default()
    }
}

// ----- Builder -----

/// Staging-area for [`EmbeddedRegistry`]. Add one component per slot
/// in slot order, then `finish()` to freeze.
#[derive(Default)]
pub struct EmbeddedRegistryBuilder {
    components: Vec<ComponentDecls>,
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
    /// key)` token, populate both stores' `by_token` maps. After
    /// this returns the registry is immutable.
    pub fn finish(self) -> EmbeddedRegistry {
        // Materialise the per-slot iterables the generic
        // `RefStore::build_from` consumes. We split the parsed
        // component bundle into the disclosure-field slice and the
        // localized slice — each kind ends up with its own
        // `RefStore` populated independently, but the slot count
        // matches.
        let df_slots: Vec<Vec<(String, String)>> = self
            .components
            .iter()
            .map(|c| {
                c.disclosure_fields
                    .iter()
                    .map(|k| (k.clone(), k.clone()))
                    .collect()
            })
            .collect();
        let l_slots: Vec<Vec<(String, Vec<Translation>)>> = self
            .components
            .into_iter()
            .map(|c| c.localized.into_iter().collect())
            .collect();
        EmbeddedRegistry {
            disclosure_fields: RefStore::build_from(df_slots),
            localized: RefStore::build_from(l_slots),
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
        let mut b = EmbeddedRegistry::builder();
        b.add_component(decls(&["passport-number"], &[]));
        let reg = b.finish();
        let token = reg.disclosure_fields.get_token(0, "passport-number").unwrap();
        assert_eq!(token, "0:d:passport-number");
        assert_eq!(
            reg.disclosure_fields.lookup(&token).map(String::as_str),
            Some("passport-number"),
        );
        assert!(reg.disclosure_fields.contains(&token));
        // Wrong store — localized.lookup misses the DF token.
        assert!(reg.localized.lookup(&token).is_none());
    }

    #[test]
    fn localized_mint_and_lookup_returns_translations() {
        let mut b = EmbeddedRegistry::builder();
        b.add_component(decls(
            &[],
            &[("consent-reason", &[("en", "Verify identity"), ("ru", "Проверка")])],
        ));
        let reg = b.finish();
        let token = reg.localized.get_token(0, "consent-reason").unwrap();
        assert_eq!(token, "0:l:consent-reason");
        let ts = reg.localized.lookup(&token).expect("token resolves");
        assert_eq!(ts.len(), 2);
        assert!(ts.iter().any(|t| t.language == "en" && t.text == "Verify identity"));
        assert!(ts.iter().any(|t| t.language == "ru" && t.text == "Проверка"));
    }

    #[test]
    fn rejects_undeclared_key() {
        let mut b = EmbeddedRegistry::builder();
        b.add_component(decls(&["a"], &[("b", &[("en", "x")])]));
        let reg = b.finish();
        assert!(reg.disclosure_fields.get_token(0, "missing").is_none());
        assert!(reg.localized.get_token(0, "missing").is_none());
    }

    #[test]
    fn rejects_cross_slot_key() {
        let mut b = EmbeddedRegistry::builder();
        b.add_component(decls(&["policy-only"], &[]));
        b.add_component(decls(&["plugin-only"], &[]));
        let reg = b.finish();
        assert!(reg.disclosure_fields.get_token(0, "plugin-only").is_none());
        assert!(reg.disclosure_fields.get_token(1, "policy-only").is_none());
        assert!(reg.disclosure_fields.get_token(0, "policy-only").is_some());
        assert!(reg.disclosure_fields.get_token(1, "plugin-only").is_some());
    }

    #[test]
    fn same_key_in_both_stores_yields_distinct_tokens() {
        let mut b = EmbeddedRegistry::builder();
        b.add_component(decls(&["shared"], &[("shared", &[("en", "x")])]));
        let reg = b.finish();
        let df = reg.disclosure_fields.get_token(0, "shared").unwrap();
        let l = reg.localized.get_token(0, "shared").unwrap();
        assert_ne!(df, l);
        assert!(reg.localized.lookup(&df).is_none());
        assert!(reg.disclosure_fields.lookup(&l).is_none());
    }

    #[test]
    fn lookup_misses_unminted_string() {
        let mut b = EmbeddedRegistry::builder();
        b.add_component(decls(&["a"], &[]));
        let reg = b.finish();
        assert!(reg.disclosure_fields.lookup("a").is_none());
        assert!(reg.disclosure_fields.lookup("9:d:a").is_none());
        assert!(reg.disclosure_fields.lookup("0:x:a").is_none());
    }

    #[test]
    fn unknown_slot_traps() {
        let reg = EmbeddedRegistry::builder().finish();
        assert!(reg.disclosure_fields.get_token(0, "x").is_none());
        assert!(reg.localized.get_token(0, "x").is_none());
    }
}
