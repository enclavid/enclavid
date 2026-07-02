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

/// Generic backing store: per-kind reverse index over ref tokens.
/// Carries enough to answer the two questions the host fn and the
/// consumer ever ask:
///
///   * get_token: given `(catalog_hash, key)`, did that catalog
///     declare `key` under this kind? If yes, return the ref token.
///   * lookup: given a ref token, what data did the catalog that
///     issued it declare?
///
/// Catalogs are identified by their **content-hash**
/// ([`catalog_hash`](super::hash::catalog_hash)), not a positional
/// slot — the hash survives wac fusion (which scrambles nesting order)
/// so a token minted at compose time still resolves at run time. The
/// membership itself rides on `by_token`: a token for `(hash, key)` is
/// in the map iff the catalog with that hash declared the key, so a
/// single `contains_key` answers "key declared by this catalog?".
/// `catalogs` is the ordered list of contributing hashes (composition
/// order, policy first) that [`get_token_first_match`](Self::
/// get_token_first_match) walks.
pub struct RefStore<K: RefKind> {
    catalogs: Vec<[u8; 32]>,
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
            catalogs: Vec::new(),
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
            .field("catalog_count", &self.catalogs.len())
            .field("by_token", &self.by_token)
            .finish()
    }
}

impl<K: RefKind> RefStore<K> {
    /// Build a store from per-catalog iterables. Each catalog is a
    /// `(content_hash, items)` pair; every `(key, stored)` produces one
    /// `by_token` entry under `compute_ref(content_hash, key)`. Catalog
    /// order in the outer iterator is composition order (policy first)
    /// and fixes the first-match order. Byte-identical catalogs (same
    /// hash) coalesce — recorded once, their tokens collide harmlessly.
    pub(crate) fn build_from<I, S>(catalogs: I, ref_key: [u8; 32]) -> Self
    where
        I: IntoIterator<Item = ([u8; 32], S)>,
        S: IntoIterator<Item = (String, K::Stored)>,
    {
        let mut by_token: HashMap<String, K::Stored> = HashMap::new();
        let mut catalog_hashes: Vec<[u8; 32]> = Vec::new();
        for (hash, items) in catalogs {
            for (key, stored) in items {
                let token = compute_ref::<K>(&hash, &key, &ref_key);
                by_token.insert(token, stored);
            }
            if !catalog_hashes.contains(&hash) {
                catalog_hashes.push(hash);
            }
        }
        Self {
            catalogs: catalog_hashes,
            by_token,
            ref_key,
            _marker: PhantomData,
        }
    }

    /// Compute the ref token for `(catalog_hash, key)` if that catalog
    /// declared `key` under this kind, else `None` (the expected
    /// guest-side miss for a key nobody declared).
    ///
    /// Pure data-layer Option — turning a `None` into a wasm trap is
    /// the host fn's responsibility (see [`embedded::host`](super::
    /// host)), so this type never depends on wasmtime.
    ///
    /// Under strict per-component routing the host resolves at a
    /// SPECIFIC catalog (the one bound to the calling component's
    /// import); under the merged path it drives
    /// [`get_token_first_match`](Self::get_token_first_match). Either
    /// way `catalog_hash` is host-side data, never read from the guest.
    pub fn get_token(&self, catalog_hash: &[u8; 32], key: &str) -> Option<String> {
        let token = compute_ref::<K>(catalog_hash, key, &self.ref_key);
        self.by_token.contains_key(&token).then_some(token)
    }

    /// Compute the ref token for the FIRST catalog (composition order,
    /// policy first) that declared `key`, or `None` if none did.
    ///
    /// The resolution mode for the MERGED path: DF always (option B —
    /// a key any catalog declared is disclosable, bounded by the
    /// visible static-set size + consent), and i18n / icons whenever a
    /// component's import wasn't routed to a distinct per-catalog slot
    /// (plain fusion). Collisions (same key, different stored value in
    /// two catalogs) resolve by composition order; that only matters
    /// for i18n, whose stored value is the per-component translation
    /// set — for DF and icons the stored value IS the key, so first
    /// match is always value-correct whichever catalog answered.
    pub fn get_token_first_match(&self, key: &str) -> Option<String> {
        self.catalogs.iter().find_map(|hash| self.get_token(hash, key))
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

/// Ref token: `hex(BLAKE3-keyed(ref_key, catalog_hash ‖ tag ‖ ':' ‖
/// key))[..32]` — 128 bits of forge resistance. The `ref_key` is
/// TEE-only (derived per-policy from `tee_seal_key + policy_ref` in
/// the api crate), so a guest WASM component can't synthesise a ref
/// for a key nobody declared: it doesn't have the key to compute valid
/// BLAKE3-keyed output for any `(catalog_hash, key)` pair.
///
/// The reverse-index in [`RefStore::by_token`] then turns the
/// membership check into pure data — every issued token sits in the
/// map, and any opaque string a guest synthesises misses with
/// overwhelming probability.
///
/// `catalog_hash` (32 bytes) identifies the issuing catalog by content,
/// not position, so the token survives fusion. Domain separation across
/// kinds rides on the TAG byte; the `:` literal between tag and key
/// keeps tag/key concatenation collision-free with a similarly-tagged
/// sibling kind.
fn compute_ref<K: RefKind>(catalog_hash: &[u8; 32], key: &str, ref_key: &[u8; 32]) -> String {
    let mut input = Vec::with_capacity(32 + K::TAG.len() + 1 + key.len());
    input.extend_from_slice(catalog_hash);
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
