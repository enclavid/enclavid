//! Generic backing for the two public embedded stores. Each
//! [`enclavid:embedded/*`](super) interface gets its own
//! `RefStore<K>` instantiation, exposed via type aliases in
//! [`registry`](super::registry):
//!
//!   * `type DisclosureFieldsStore = RefStore<DisclosureFields>`
//!   * `type LocalizedStore = RefStore<Localized>`
//!
//! Both kinds share the same membership / get_token / lookup
//! mechanics — only the per-kind `TAG`, `NAME`, and `Stored` type
//! differ, all carried by the [`RefKind`] marker.
//!
//! Naming: `RefStore` rather than `Store` so consumers reading the
//! engine crate can't confuse it with `wasmtime::Store`. Within this
//! crate the two are never both in scope on the same line, but the
//! cognitive cost of shadowing is real.

use std::collections::HashMap;
use std::marker::PhantomData;

use super::registry::Slot;

/// Static description of one `enclavid:embedded/*` interface. Picked
/// per-kind by the marker types below ([`DisclosureFields`],
/// [`Localized`]) so the generic [`RefStore`] can produce
/// kind-specific tokens and trap messages without runtime dispatch.
pub trait RefKind {
    /// One-character tag used in the Phase A debug format and as a
    /// fixed-length namespace byte in the Phase B HMAC input. Picked
    /// per-kind so the two namespaces don't collide.
    const TAG: &'static str;
    /// Human-readable name for trap / log messages — matches the
    /// `enclavid:embedded/*` interface a misuse came from.
    const NAME: &'static str;
    /// What the store keeps in its reverse index. The declared key
    /// itself for [`DisclosureFields`]; the translation list for
    /// [`Localized`]. The public wrappers narrow this to a borrowed
    /// view (`&str`, `&[Translation]`) at the API boundary.
    type Stored;
}

/// Marker for `enclavid:embedded/disclosure-fields` refs.
pub enum DisclosureFields {}

impl RefKind for DisclosureFields {
    const TAG: &'static str = "d";
    const NAME: &'static str = "disclosure-field";
    type Stored = String;
}

/// Marker for `enclavid:embedded/i18n` refs.
pub enum Localized {}

impl RefKind for Localized {
    const TAG: &'static str = "l";
    const NAME: &'static str = "localized";
    type Stored = Vec<super::registry::Translation>;
}

/// Generic backing store: per-kind reverse index over Phase A debug
/// tokens. Carries enough to answer the two questions the host fn
/// and the consumer ever ask:
///
///   * get_token: given `(slot, key)`, does this slot own `key`
///     under this kind? If yes, return the ref token.
///   * lookup: given a ref token, what data did the slot that
///     issued it declare?
///
/// `slot_count` is the only piece of slot-shape state — it lets
/// [`get_token`](Self::get_token) surface a clean "slot X has no
/// registered component" error before the cheaper `by_token` miss
/// path. The membership itself rides on `by_token`: a slot-X token
/// is in the map iff some component at slot X declared the key
/// under this kind, so a single `contains_key` answers both
/// "key declared?" and "issued by the right slot?".
pub struct RefStore<K: RefKind> {
    slot_count: usize,
    by_token: HashMap<String, K::Stored>,
    _marker: PhantomData<fn() -> K>,
}

impl<K: RefKind> Default for RefStore<K> {
    fn default() -> Self {
        Self {
            slot_count: 0,
            by_token: HashMap::new(),
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
            .field("slot_count", &self.slot_count)
            .field("by_token", &self.by_token)
            .finish()
    }
}

impl<K: RefKind> RefStore<K> {
    /// Build a store from per-slot iterables. Each slot's
    /// `(key, stored)` pairs are walked once, each producing one
    /// `by_token` entry under the computed token. Slot order in the
    /// outer iterator determines slot indices (0, 1, ...).
    pub(crate) fn build_from<I, S>(slots: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: IntoIterator<Item = (String, K::Stored)>,
    {
        let mut by_token: HashMap<String, K::Stored> = HashMap::new();
        let mut slot_count = 0usize;
        for items in slots {
            let slot = slot_count;
            for (key, stored) in items {
                let token = compute_ref::<K>(slot, &key);
                by_token.insert(token, stored);
            }
            slot_count += 1;
        }
        Self {
            slot_count,
            by_token,
            _marker: PhantomData,
        }
    }

    /// Compute the ref token for `(slot, key)` if the pair is
    /// declared in this store. Returns `None` when:
    ///
    ///   * `slot` is outside the composition (host-side wiring bug;
    ///     unreachable from a well-formed runner).
    ///   * The component at `slot` never declared `key` for this
    ///     store's kind (the expected guest-side miss).
    ///
    /// Pure data-layer Option — turning a `None` into a wasm trap is
    /// the host fn's responsibility (see [`embedded::host`](super::
    /// host)), so this type never depends on wasmtime.
    ///
    /// Dispatched per-kind from two places:
    ///
    ///   * Policy slot 0: the bindgen-generated `Host` trait impls
    ///     on [`HostState`](crate::state::HostState) in
    ///     [`embedded::host`](super::host).
    ///   * Plugin slots ≥ 1: the closures registered by
    ///     [`embedded::host::register_for_slot`](super::host::
    ///     register_for_slot) on each plugin's Linker, with `slot`
    ///     captured.
    ///
    /// `slot` is set by the host, never read from the guest — that's
    /// the per-component scoping mechanism. A guest invoking
    /// `disclosure_field("x")` has no say in which slot the
    /// closure attributes the call to.
    pub fn get_token(&self, slot: Slot, key: &str) -> Option<String> {
        if slot >= self.slot_count {
            return None;
        }
        let token = compute_ref::<K>(slot, key);
        self.by_token.contains_key(&token).then_some(token)
    }

    /// Resolve a ref token to the stored data the slot that issued
    /// it declared. `None` for tokens that no slot in this store
    /// issued — either a raw component-crafted string (covert
    /// channel attempt) or a stale ref from a previous run.
    pub fn lookup(&self, token: &str) -> Option<&K::Stored> {
        self.by_token.get(token)
    }

    /// `true` if the ref token was issued by some slot in this
    /// store. Use-site validation pivot — see
    /// [`sanitize`](crate::sanitize).
    pub fn contains(&self, token: &str) -> bool {
        self.by_token.contains_key(token)
    }
}

/// Phase A debug format: `"{slot}:{tag}:{key}"`. Inspectable in
/// logs; the membership check inside [`RefStore::get_token`] is what
/// makes refs unforgeable across slots (the prefix alone is just a
/// label). Phase B swaps this for a TEE-keyed HMAC.
fn compute_ref<K: RefKind>(slot: Slot, key: &str) -> String {
    format!("{slot}:{}:{key}", K::TAG)
}
