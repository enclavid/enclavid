//! Generic backing for the three public embedded stores. Each
//! `enclavid:host/embedded-*` interface gets its own `RefStore<K>`
//! instantiation, exposed via type aliases in
//! [`registry`](super::registry).
//!
//! ## Refs are resources, not tokens
//!
//! A component never sees a ref VALUE — `localized`/`icon`/
//! `disclosure-field` return an opaque WIT `resource` handle it cannot
//! forge (wasmtime owns the handle table). So the store carries no
//! keyed-hash / reverse-index: membership is a plain `key → data`
//! lookup, and the host mints a resource whose rep IS the resolved data
//! ([`LocalizedRef`] / [`IconRef`] / [`DisclosureFieldRef`]). The engine
//! dereferences that rep at the action boundary, so the resolved data
//! is self-contained (no registry needed to render it later).
//!
//! Catalogs are identified by their **content-hash**
//! ([`catalog_hash`](super::hash::catalog_hash)), which survives wac
//! fusion. `resolve_strict` answers against ONE bound catalog (the
//! strict per-component path — i18n / icons routed to a distinct twin);
//! `resolve_first_match` walks catalogs in composition order (the merged
//! path — disclosure-fields always, and i18n / icons for a lone unfused
//! policy).

use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;

use super::registry::Translation;

/// Static description of one embedded interface. The marker types below
/// ([`DisclosureFields`], [`Localized`], [`Icon`]) pick the per-kind
/// `NAME` (for trap messages) and `Stored` type.
pub trait RefKind {
    /// Human-readable name for trap messages — matches the
    /// `enclavid:host/embedded-*` interface a misuse came from.
    const NAME: &'static str;
    /// What the store keeps per declared key. The key itself for
    /// [`DisclosureFields`] / [`Icon`]; the translation list for
    /// [`Localized`].
    type Stored;
}

/// Marker for `enclavid:host/embedded-disclosure-fields` refs.
pub enum DisclosureFields {}

impl RefKind for DisclosureFields {
    const NAME: &'static str = "disclosure-field";
    type Stored = String;
}

/// Marker for `enclavid:host/embedded-i18n` refs.
pub enum Localized {}

impl RefKind for Localized {
    const NAME: &'static str = "localized";
    type Stored = Vec<Translation>;
}

/// Marker for `enclavid:host/embedded-icons` refs.
pub enum Icon {}

impl RefKind for Icon {
    const NAME: &'static str = "icon";
    type Stored = String;
}

// ---------------------------------------------------------------------
// Resource reps — the host-owned backing of each WIT ref resource. Carry
// the RESOLVED data (mint-time resolution) so the engine's boundary
// deref is self-contained. `bindgen!`'s `with` maps each WIT resource to
// the matching type here.
// ---------------------------------------------------------------------

/// Backing rep of `enclavid:host/types.localized-ref` — the full
/// translation set the applicant-locale text is later picked from.
pub struct LocalizedRef(pub Vec<Translation>);
/// Backing rep of `enclavid:host/types.icon-ref` — the resolved icon
/// name the applicant frontend dispatches.
pub struct IconRef(pub String);
/// Backing rep of `enclavid:host/types.disclosure-field-ref` — the
/// resolved machine `display-field.key` the consumer receives.
pub struct DisclosureFieldRef(pub String);

/// Per-kind `key → data` store, keyed by catalog content-hash. Built
/// once per [`Runner::run`](crate::Runner::run) from every component's
/// declarations, then frozen.
pub struct RefStore<K: RefKind> {
    /// Contributing catalog hashes in composition order (policy first) —
    /// fixes the first-match order for [`resolve_first_match`](Self::
    /// resolve_first_match).
    catalogs: Vec<[u8; 32]>,
    /// `catalog_hash → (key → data)`.
    by_catalog: HashMap<[u8; 32], HashMap<String, K::Stored>>,
    _marker: PhantomData<fn() -> K>,
}

impl<K: RefKind> Default for RefStore<K> {
    fn default() -> Self {
        Self {
            catalogs: Vec::new(),
            by_catalog: HashMap::new(),
            _marker: PhantomData,
        }
    }
}

impl<K: RefKind> std::fmt::Debug for RefStore<K>
where
    K::Stored: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefStore")
            .field("kind", &K::NAME)
            .field("catalog_count", &self.catalogs.len())
            .field("by_catalog", &self.by_catalog)
            .finish()
    }
}

impl<K: RefKind> RefStore<K> {
    /// Build from per-catalog iterables. Each catalog is a
    /// `(content_hash, items)` pair; outer order is composition order
    /// (policy first) and fixes the first-match order. Byte-identical
    /// catalogs (same hash) coalesce.
    pub(crate) fn build_from<I, S>(catalogs: I) -> Self
    where
        I: IntoIterator<Item = ([u8; 32], S)>,
        S: IntoIterator<Item = (String, K::Stored)>,
    {
        let mut by_catalog: HashMap<[u8; 32], HashMap<String, K::Stored>> = HashMap::new();
        let mut order: Vec<[u8; 32]> = Vec::new();
        for (hash, items) in catalogs {
            if !order.contains(&hash) {
                order.push(hash);
            }
            let entry = by_catalog.entry(hash).or_default();
            for (key, stored) in items {
                entry.insert(key, stored);
            }
        }
        Self {
            catalogs: order,
            by_catalog,
            _marker: PhantomData,
        }
    }

    /// Resolve `key` against ONE specific catalog (strict per-component
    /// path). `None` if that catalog didn't declare `key` — the host fn
    /// turns it into a trap.
    pub fn resolve_strict(&self, catalog_hash: &[u8; 32], key: &str) -> Option<&K::Stored> {
        self.by_catalog.get(catalog_hash)?.get(key)
    }

    /// Resolve `key` against the FIRST catalog (composition order, policy
    /// first) that declared it — the merged path. `None` if no catalog
    /// did.
    pub fn resolve_first_match(&self, key: &str) -> Option<&K::Stored> {
        self.catalogs
            .iter()
            .find_map(|hash| self.resolve_strict(hash, key))
    }

    /// Every declared value across all catalogs (dups possible when two
    /// catalogs declare the same key). The DF drill-down / audit view
    /// dedups.
    pub fn declared(&self) -> impl Iterator<Item = &K::Stored> {
        self.by_catalog.values().flat_map(|m| m.values())
    }

    /// Number of DISTINCT declared keys across the whole composition
    /// (deduped). Surfaced to the applicant as the consent screen's
    /// covert-channel bound (`total_declared`): the composition can
    /// encode at most `log2(distinct_declared_count)` bits per ref
    /// position.
    pub fn distinct_declared_count(&self) -> usize {
        let keys: HashSet<&String> = self.by_catalog.values().flat_map(|m| m.keys()).collect();
        keys.len()
    }
}
