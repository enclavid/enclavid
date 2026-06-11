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

/// Marker for `enclavid:embedded/icons` refs.
pub enum Icon {}

impl RefKind for Icon {
    const TAG: &'static str = "i";
    const NAME: &'static str = "icon";
    type Stored = String;
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
    /// BLAKE3 keyed-hash secret used by [`compute_ref`]. Same value
    /// across all three stores in one `EmbeddedRegistry` — kind
    /// domain separation lives in the [`RefKind::TAG`] byte fed into
    /// the hash input, not in the key itself. Production callers
    /// derive this from `tee_seal_key + policy_ref` so it's stable
    /// per-policy and unguessable from outside the TEE.
    ref_key: [u8; 32],
    _marker: PhantomData<fn() -> K>,
}

impl<K: RefKind> Default for RefStore<K> {
    fn default() -> Self {
        Self {
            slot_count: 0,
            by_token: HashMap::new(),
            ref_key: [0u8; 32],
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
    pub(crate) fn build_from<I, S>(slots: I, ref_key: [u8; 32]) -> Self
    where
        I: IntoIterator<Item = S>,
        S: IntoIterator<Item = (String, K::Stored)>,
    {
        let mut by_token: HashMap<String, K::Stored> = HashMap::new();
        let mut slot_count = 0usize;
        for items in slots {
            let slot = slot_count;
            for (key, stored) in items {
                let token = compute_ref::<K>(slot, &key, &ref_key);
                by_token.insert(token, stored);
            }
            slot_count += 1;
        }
        Self {
            slot_count,
            by_token,
            ref_key,
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
        let token = compute_ref::<K>(slot, key, &self.ref_key);
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

    /// Number of distinct refs this store can issue across the whole
    /// composition (sum over slots). Surfaced to the applicant in
    /// the consent screen so the user can audit the policy's covert-
    /// channel bandwidth — `log2(declared_count)` bits per ref
    /// position is the theoretical bound, the actual leak hinges on
    /// how many ref positions a single call uses.
    pub fn declared_count(&self) -> usize {
        self.by_token.len()
    }

    /// Iterate over every declared `Stored` value across all slots.
    /// Order is unspecified — caller sorts if a canonical view is
    /// needed (consent-screen drill-down sorts by the key for stable
    /// display).
    pub fn declared(&self) -> impl Iterator<Item = &K::Stored> {
        self.by_token.values()
    }
}

/// Phase B token: `hex(BLAKE3-keyed(ref_key, slot_be ‖ tag ‖ ':' ‖
/// key))[..32]` — 128 bits of forge resistance. The `ref_key` is
/// TEE-only (derived per-policy from `tee_seal_key + policy_ref` in
/// the api crate), so a guest WASM component can't synthesise a
/// foreign-slot ref by guessing the format: it doesn't have the key
/// to compute valid BLAKE3-keyed output for any `(slot, key)` pair.
///
/// The reverse-index in [`RefStore::by_token`] then turns the
/// membership check into pure data — every minted token sits in the
/// map, and any opaque string a guest synthesises misses with
/// overwhelming probability.
///
/// Domain separation across kinds rides on the TAG byte fed into the
/// hash input; the same `ref_key` powers all three stores in one
/// registry. Slot is encoded big-endian as 8 bytes so the input is
/// unambiguous (a `:` literal between tag and key keeps tag/key
/// concatenation collision-free with a similarly-tagged sibling
/// kind).
fn compute_ref<K: RefKind>(slot: Slot, key: &str, ref_key: &[u8; 32]) -> String {
    let mut input = Vec::with_capacity(9 + K::TAG.len() + key.len());
    input.extend_from_slice(&(slot as u64).to_be_bytes());
    input.extend_from_slice(K::TAG.as_bytes());
    input.push(b':');
    input.extend_from_slice(key.as_bytes());
    let hash = blake3::keyed_hash(ref_key, &input);
    // 16 bytes = 128-bit forge resistance, 32 hex chars on wire —
    // tight enough for the format-validator's MAX_KEY_LENGTH headroom
    // and comfortably under any disclosure-envelope size cap.
    let bytes = &hash.as_bytes()[..16];
    let mut s = String::with_capacity(32);
    use std::fmt::Write;
    for b in bytes {
        write!(s, "{b:02x}").expect("write into String never fails");
    }
    s
}
