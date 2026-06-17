//! Type-level wrappers for values crossing the TEE ↔ host trust
//! boundary. Two dual markers, one per direction. Previously its
//! own crate (`enclavid-untrusted`); folded into `broker-client` as
//! `boundary::sentinel` so the type definitions live in the same
//! crate as the channel-specific [`inbound`](super::inbound) and
//! [`outbound`](super::outbound) facades that own the construction
//! sites — keeps "the perimeter" inspectable in one place.
//!
//! `Untrusted<T, S>` — INBOUND. Carries a tuple-typed scope `S`
//! listing the open trust concerns for the value (authenticity,
//! authorization, replay-resistance). The inner `T` cannot be
//! inspected until the caller addresses every concern via
//! `trust_unchecked::<X>()` (blanket-accept) or
//! `trust::<X>(predicate)` (verify), each peeling one concern off
//! `S`. After all concerns are addressed (`S = ()`) the caller
//! reaches the inner value via `into_inner`. Reviewers grep for
//! `trust_unchecked::<` / `trust::<` to see every gate; the
//! turbofish marker says which concern was accepted.
//!
//! `Exposed<T, S>` — OUTBOUND. Mirror of `Untrusted`: tuple-typed
//! scope `S` lists the open concerns for a value being released to
//! the host (cryptographic confidentiality to the intended
//! recipient, application-level authorization to release, hidden-
//! bandwidth closure). The inner `T` is reachable only via
//! `into_inner` after every concern has been peeled with
//! `vouch_unchecked::<X>()` / `vouch::<X>(predicate)`. Both wrappers
//! share the [`Remove`] machinery and the `reason!` macro — the
//! direction is carried by the wrapper type, not by the peel API.
//! Reviewers grep for `Exposed::new` to find every release point
//! and `vouch_unchecked::<` to see how each concern was addressed.

use std::marker::PhantomData;

// =====================================================================
// Reason token + `reason!` macro.
//
// `trust_unchecked` requires a `Reason` argument so every blanket
// accept must go through the `reason!("...")` macro. The macro
// matches a string literal at parse time but does not include it in
// the expansion — the explanatory text is captured in source (for
// audit / `grep`) and never reaches compiled output.
//
// `Reason` is a ZST whose only field is private; the only way to
// construct it from outside this crate is the macro, which calls the
// `#[doc(hidden)]` constructor. Direct use of the constructor is
// possible but conspicuous (loud name) and rejected at code review.
// =====================================================================

/// Audit-trail token — proves the caller wrote a `reason!("...")`
/// alongside their `trust_unchecked` peel or `Untrusted::new`
/// construction. ZST; carries no runtime data. The explanation
/// lives in source code only.
///
/// `Copy + Clone` so a single `reason!(...)` token can be reused
/// across multiple call sites in the same expression — typical
/// when a `decode` method has two return paths (e.g., `None`
/// versus `Some(value)`) sharing the same scope rationale.
#[derive(Debug, Clone, Copy)]
pub struct Reason(());

impl Reason {
    #[doc(hidden)]
    pub const fn __reason_macro_internal_do_not_call_directly() -> Self {
        Self(())
    }
}

/// Build a [`Reason`] token, recording the rationale for a
/// `trust_unchecked` peel. The string literal is parsed by the macro
/// but never appears in the macro expansion — it is discarded at
/// compile time, so the binary contains neither the bytes nor a
/// pointer to them.
///
/// ```ignore
/// value
///     .trust_unchecked::<AuthN, _>(reason!("AEAD-binding via session_id"))
///     .trust_unchecked::<Replay, _>(reason!("idempotent retry handles stale"))
///     .into_inner();
/// ```
#[macro_export]
macro_rules! reason {
    ($explanation:literal) => {
        $crate::Reason::__reason_macro_internal_do_not_call_directly()
    };
}

// =====================================================================
// Concern markers — three axes that any TEE-ingested value can be
// untrusted on. Add a new marker here when introducing a fourth axis.
// =====================================================================

/// Authenticity concern: bytes might have been fabricated or
/// substituted by an untrusted source. Cleared by cryptographic
/// verification (AEAD decrypt under a TEE-side key, signature check,
/// digest match against an expected value, etc.) — or explicitly
/// blanket-accepted via `trust_unchecked::<AuthN>()`.
pub struct AuthN;

/// Authorization concern: the principal who made this request might
/// not be allowed to access this resource. Cleared by an
/// application-level predicate (e.g., principal match against the
/// authenticated caller). Not a cryptographic property — it is
/// always handled at the application layer.
pub struct AuthZ;

/// Replay-resistance concern: bytes are authentic but might be a
/// stale snapshot the source served instead of the latest version.
/// Crypto-authenticated payloads have this open by default unless
/// freshness is established separately (e.g., a monotonic counter or
/// CAS guard). Often blanket-accepted via
/// `accept_replay`-style call where the application path (e.g., an
/// idempotent retry on /init or a CAS guard at write time) bounds
/// the practical impact to DoS / UX regression rather than data
/// leak.
pub struct Replay;

/// Covert-channel concern: outbound data might carry policy-controlled
/// bandwidth disguised as legitimate structure (field order, count,
/// content). Cleared by sanitisation passes (shuffle, fixed-order,
/// cardinality cap, value scrubbing) — or explicitly blanket-vouched
/// via `vouch_unchecked::<Covert>()` when the data is sealed under a
/// key the host can't read (so the bandwidth never reaches a leak
/// destination) or has bounded cardinality by construction.
///
/// Outbound-only axis: inbound data isn't a covert-channel concern
/// because we're not on the encoding side. `Exposed<T, S>` is where
/// `Covert` appears in `S`.
pub struct Covert;

// =====================================================================
// Position markers — used to disambiguate `Remove<X, I>` impls when
// the same type appears at different tuple positions. Caller never
// names these; type inference picks the right one.
// =====================================================================

pub struct P0;
pub struct P1;
pub struct P2;
pub struct P3;

// =====================================================================
// Type-level "remove X from a tuple of concerns" trait. One impl per
// (arity, position) pair; the `I` type parameter is the position
// marker the compiler infers.
// =====================================================================

/// Remove the type `X` from a tuple `Self` (of concern markers),
/// producing `Self::Rest`. The `I` type parameter disambiguates
/// which position `X` sits in — the compiler infers it.
pub trait Remove<X, I> {
    type Rest;
}

// 1-tuple: only position P0.
impl<X> Remove<X, P0> for (X,) {
    type Rest = ();
}

// 2-tuple: P0, P1.
impl<X, B> Remove<X, P0> for (X, B) {
    type Rest = (B,);
}
impl<A, X> Remove<X, P1> for (A, X) {
    type Rest = (A,);
}

// 3-tuple: P0, P1, P2.
impl<X, B, C> Remove<X, P0> for (X, B, C) {
    type Rest = (B, C);
}
impl<A, X, C> Remove<X, P1> for (A, X, C) {
    type Rest = (A, C);
}
impl<A, B, X> Remove<X, P2> for (A, B, X) {
    type Rest = (A, B);
}

// 4-tuple: P0, P1, P2, P3 — headroom for one more concern axis
// without crate-level migration.
impl<X, B, C, D> Remove<X, P0> for (X, B, C, D) {
    type Rest = (B, C, D);
}
impl<A, X, C, D> Remove<X, P1> for (A, X, C, D) {
    type Rest = (A, C, D);
}
impl<A, B, X, D> Remove<X, P2> for (A, B, X, D) {
    type Rest = (A, B, D);
}
impl<A, B, C, X> Remove<X, P3> for (A, B, C, X) {
    type Rest = (A, B, C);
}

// =====================================================================
// Untrusted<T, S> — inbound wrapper.
// =====================================================================

/// Inbound wrapper. `S` is a tuple of concern markers; methods peel
/// one concern at a time until `S = ()`, after which the inner `T`
/// is reachable via `into_inner`.
#[derive(Debug)]
pub struct Untrusted<T, S = ()> {
    value: T,
    _marker: PhantomData<S>,
}

impl<T, S> Untrusted<T, S> {
    /// Wrap a value with an explicit initial scope. The caller picks
    /// `S` to match what concerns are genuinely open at the
    /// construction site (e.g., a host-plaintext field starts with
    /// `(AuthN, Replay)` open; an AEAD-decrypted field starts with
    /// `(AuthZ, Replay)`).
    ///
    /// Requires a [`Reason`] token built via [`reason!`] explaining
    /// **why** this particular scope (and not a wider or narrower
    /// one). Symmetric with `trust_unchecked` — the construction
    /// site is where scope is set, the peel site is where scope
    /// shrinks; both warrant explicit documentation. The token is a
    /// ZST and the reason text is discarded at compile time, so this
    /// is free at runtime.
    ///
    /// `pub(crate)` by design: external callers route through
    /// [`crate::boundary::inbound::from_untrusted`] so every wire crossing
    /// is grep-anchored. Inside this crate, the boundary fn and a
    /// handful of synthesis sites (absent-blob `None` wraps) are the
    /// only direct callers.
    pub(crate) fn new(value: T) -> Self {
        Self {
            value,
            _marker: PhantomData,
        }
    }

    /// Blanket-accept concern `X` without verification. Requires a
    /// [`Reason`] token built via [`reason!`] — the macro forces
    /// every call site to embed an explanation in source for audit.
    /// The token is a ZST and the macro discards the explanatory
    /// text at compile time, so this is free at runtime.
    pub fn trust_unchecked<X, I>(self, _reason: Reason) -> Untrusted<T, S::Rest>
    where
        S: Remove<X, I>,
    {
        Untrusted {
            value: self.value,
            _marker: PhantomData,
        }
    }

    /// Close concern `X` by performing the work that addresses it
    /// (cryptographic verify, decrypt-and-decode, predicate check
    /// returning the same value). The closure receives ownership of
    /// the wrapped value and produces a (possibly transformed) new
    /// value `U` — e.g. AEAD-open turns ciphertext bytes into
    /// plaintext; a parse step turns bytes into a typed record.
    ///
    /// Predicate-only verification fits this signature too: return
    /// `Ok(value)` to keep the value unchanged, `Err(e)` to fail.
    ///
    /// On success the scope shrinks by `X`; on failure the scope is
    /// unchanged but the wrapper is dropped.
    pub fn trust<X, I, U, F, E>(self, work: F) -> Result<Untrusted<U, S::Rest>, E>
    where
        S: Remove<X, I>,
        F: FnOnce(T) -> Result<U, E>,
    {
        let new_value = work(self.value)?;
        Ok(Untrusted {
            value: new_value,
            _marker: PhantomData,
        })
    }

    /// Project the inner value while preserving the scope. Use when
    /// you need to transform `T` to `U` (e.g., extract a sub-field)
    /// without addressing any concerns yet — the wrapped value
    /// becomes `Untrusted<U, S>` with the same open concerns.
    pub fn map<U, F>(self, f: F) -> Untrusted<U, S>
    where
        F: FnOnce(T) -> U,
    {
        Untrusted {
            value: f(self.value),
            _marker: PhantomData,
        }
    }
}

impl<T> Untrusted<T, ()> {
    /// Reach the inner value once every concern has been addressed.
    /// Only available when `S = ()`, so the type system enforces
    /// that consumers exhaustively peel.
    pub fn into_inner(self) -> T {
        self.value
    }
}

// =====================================================================
// Exposed<T, S> — outbound wrapper. Mirror of Untrusted.
// =====================================================================

/// Outbound wrapper. `S` is a tuple of concern markers; methods peel
/// one concern at a time until `S = ()`, after which the inner `T`
/// is reachable via `into_inner`.
///
/// Concerns are addressed by *vouching* — the caller asserts that
/// the concern has been handled upstream (sealing, sanitisation,
/// authorization-gate) and records why with a [`Reason`] token.
/// Symmetric with `Untrusted`'s *trust* peel (we're not receiving
/// data we have to trust the producer of; we're emitting data and
/// vouching that we've cleared its risk surfaces).
#[derive(Debug)]
pub struct Exposed<T, S = ()> {
    value: T,
    _marker: PhantomData<S>,
}

impl<T: Clone, S> Clone for Exposed<T, S> {
    /// Manual `Clone` impl — derive can't synthesise it when the
    /// scope `S` may not be `Clone` (it never is, the markers are
    /// phantom). Preserves scope.
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            _marker: PhantomData,
        }
    }
}

impl<T, S> Exposed<T, S> {
    /// Wrap a value being released to the host with an explicit
    /// initial scope. Caller picks `S` to match the concerns
    /// genuinely open at the construction site (e.g., a fresh
    /// disclosure envelope starts with `(AuthN, AuthZ, Covert)` open;
    /// a public-by-design status byte starts with `(AuthN, AuthZ,
    /// Covert)` too but each gets peeled with a "by design observable
    /// to host" rationale).
    ///
    /// Requires a [`Reason`] token built via [`reason!`] explaining
    /// **why** this particular scope (and not a wider or narrower
    /// one). Symmetric with `Untrusted::new`.
    ///
    /// `pub(crate)` by design: external callers route through
    /// [`crate::boundary::outbound::to_untrusted`] so every wire release
    /// is grep-anchored.
    pub(crate) fn new(value: T) -> Self {
        Self {
            value,
            _marker: PhantomData,
        }
    }

    /// Vouch (blanket-accept) that concern `X` has been addressed
    /// upstream. Requires a [`Reason`] token built via [`reason!`] —
    /// the macro forces every call site to embed an explanation in
    /// source for audit. Mirror of `Untrusted::trust_unchecked`; same
    /// position-marker inference machinery (`I`) lets callers peel in
    /// any order.
    pub fn vouch_unchecked<X, I>(self, _reason: Reason) -> Exposed<T, S::Rest>
    where
        S: Remove<X, I>,
    {
        Exposed {
            value: self.value,
            _marker: PhantomData,
        }
    }

    /// Close concern `X` by performing the work that addresses it
    /// (AEAD-seal, shuffle, sanitise, predicate check returning the
    /// same value). The closure receives ownership of the wrapped
    /// value and produces a (possibly transformed) new value `U` —
    /// e.g. AEAD-seal turns plaintext bytes into ciphertext;
    /// `shuffle_fields` permutes a typed list; an identity-on-success
    /// predicate is just `|v| { check(&v)?; Ok(v) }`.
    ///
    /// Symmetric to `Untrusted::trust`: inbound trusts WORK that
    /// verifies authenticity (decrypt), outbound vouches WORK that
    /// establishes confidentiality (encrypt). Both sides close their
    /// concern by performing the transformation, not just attesting
    /// to it.
    ///
    /// On success the scope shrinks by `X`; on failure the scope is
    /// unchanged but the wrapper is dropped.
    pub fn vouch<X, I, U, F, E>(self, work: F) -> Result<Exposed<U, S::Rest>, E>
    where
        S: Remove<X, I>,
        F: FnOnce(T) -> Result<U, E>,
    {
        let new_value = work(self.value)?;
        Ok(Exposed {
            value: new_value,
            _marker: PhantomData,
        })
    }

    /// Project the inner value while preserving the scope. Use when
    /// you need to transform `T` to `U` (e.g., wrap sealed bytes
    /// into a typed `Op`) without addressing any concerns.
    pub fn map<U, F>(self, f: F) -> Exposed<U, S>
    where
        F: FnOnce(T) -> U,
    {
        Exposed {
            value: f(self.value),
            _marker: PhantomData,
        }
    }
}

/// Transpose a homogeneous batch of same-scope exposures into one
/// exposure of the batch: `Vec<Exposed<T, S>>` → `Exposed<Vec<T>, S>`.
///
/// **No `Reason`, sound by construction:** every element already
/// addressed exactly the concerns in `S` (each earned its scope through
/// its own peel chain), so the batch has too — the scope is *derived*
/// from the parts, never re-asserted. The uniform `S` is enforced by
/// the `Vec`'s homogeneous element type.
///
/// Use to assemble a request body from per-field vouched values (e.g.
/// the ops of a session write) and thread the `Exposed` through, instead
/// of `into_inner`-ing each part and then rubber-stamping the envelope
/// with a blanket `vouch_unchecked`. Pair with [`Exposed::map`] to fold
/// in non-secret envelope fields (a version counter, …) at the same
/// preserved scope.
impl<T, S> From<Vec<Exposed<T, S>>> for Exposed<Vec<T>, S> {
    fn from(items: Vec<Exposed<T, S>>) -> Self {
        Exposed {
            value: items.into_iter().map(|e| e.value).collect(),
            _marker: PhantomData,
        }
    }
}

/// Distribute one exposure of a tuple into a tuple of exposures, each
/// component carrying the SAME scope `S`:
/// `Exposed<(A, B, C), S>` → `(Exposed<A, S>, Exposed<B, S>, Exposed<C, S>)`.
///
/// The **dual** of the `From<Vec<Exposed<T, S>>>` transpose: that joins
/// homogeneous parts into a whole; this splits a whole into its parts.
///
/// **No `Reason`, sound by construction:** whatever concerns are still
/// open for the tuple are open for each of its components, so each part's
/// scope is *derived* from the whole, never re-asserted. The split is
/// independent — closing `S` on one component does not touch the others.
///
/// Note on honesty: distributing only moves the wrapper; it does not make
/// a tuple-level blanket `vouch_unchecked` any more honest than it was.
/// Bundle into a tuple-then-vouch ONLY when one reason genuinely covers
/// every component (e.g. same-provenance scalars). For heterogeneous
/// members that close a concern differently (per-field AEAD vs age-seal
/// vs plaintext), keep them as separate per-member exposures instead.
macro_rules! impl_exposed_distribute {
    ($($T:ident),+) => {
        impl<$($T,)+ S> Exposed<($($T,)+), S> {
            #[allow(non_snake_case)]
            pub fn distribute(self) -> ($(Exposed<$T, S>,)+) {
                let ($($T,)+) = self.value;
                ($(Exposed { value: $T, _marker: PhantomData },)+)
            }
        }
    };
}

impl_exposed_distribute!(T0, T1);
impl_exposed_distribute!(T0, T1, T2);
impl_exposed_distribute!(T0, T1, T2, T3);
impl_exposed_distribute!(T0, T1, T2, T3, T4);
impl_exposed_distribute!(T0, T1, T2, T3, T4, T5);
impl_exposed_distribute!(T0, T1, T2, T3, T4, T5, T6);
impl_exposed_distribute!(T0, T1, T2, T3, T4, T5, T6, T7);

impl<T> Exposed<T, ()> {
    /// Reach the inner value once every concern has been vouched
    /// for. Only available when `S = ()`, so the type system
    /// enforces that consumers exhaustively peel before the value
    /// hits the wire.
    pub fn into_inner(self) -> T {
        self.value
    }

    /// Borrow the inner value once every concern has been vouched
    /// for. Same `S = ()` gate as [`into_inner`](Self::into_inner) —
    /// usable when the caller needs read-only access (e.g. to feed
    /// the bytes through a chained hash) before later releasing the
    /// value to wire. Reviewers grep for `into_inner` *and*
    /// `as_inner` to find every release point.
    pub fn as_inner(&self) -> &T {
        &self.value
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct Meta {
        owner: String,
        version: u32,
    }

    #[test]
    fn peel_in_natural_order() {
        let raw: Untrusted<Meta, (AuthN, AuthZ, Replay)> = Untrusted::new(Meta {
            owner: "alice".into(),
            version: 1,
        });
        let after_authn = raw.trust_unchecked::<AuthN, _>(reason!("test fixture"));
        let after_authz = after_authn
            .trust::<AuthZ, _, _, _, _>(|m| {
                if m.owner == "alice" {
                    Ok(m)
                } else {
                    Err("wrong owner")
                }
            })
            .unwrap();
        let m = after_authz
            .trust_unchecked::<Replay, _>(reason!("test fixture"))
            .into_inner();
        assert_eq!(
            m,
            Meta {
                owner: "alice".into(),
                version: 1
            }
        );
    }

    #[test]
    fn peel_in_arbitrary_order() {
        // Same scope, peeled in different order — type inference
        // picks the matching position marker each time.
        let raw: Untrusted<u32, (AuthN, AuthZ, Replay)> = Untrusted::new(42);
        let v = raw
            .trust_unchecked::<Replay, _>(reason!("test fixture"))
            .trust_unchecked::<AuthN, _>(reason!("test fixture"))
            .trust_unchecked::<AuthZ, _>(reason!("test fixture"))
            .into_inner();
        assert_eq!(v, 42);
    }

    #[test]
    fn trust_predicate_style_propagates_error() {
        // Predicate-on-success: keep the value unchanged, fail on
        // bad input. Same shape as a real authorization check.
        let raw: Untrusted<&'static str, (AuthZ,)> = Untrusted::new("mallory");
        let err = raw
            .trust::<AuthZ, _, _, _, _>(|s| {
                if s == "alice" {
                    Ok(s)
                } else {
                    Err("not alice")
                }
            })
            .unwrap_err();
        assert_eq!(err, "not alice");
    }

    #[test]
    fn trust_transforming_changes_type_on_success() {
        // Real inbound shape: bytes-on-wire → typed value after
        // AEAD-open + decode. We model with a string-to-length
        // transform to keep the test focused on the type shift.
        let raw: Untrusted<&'static str, (AuthN,)> = Untrusted::new("hello");
        let len: Untrusted<usize, ()> = raw
            .trust::<AuthN, _, _, _, _>(|s| Ok::<_, ()>(s.len()))
            .unwrap();
        assert_eq!(len.into_inner(), 5);
    }

    #[test]
    fn map_preserves_scope() {
        let raw: Untrusted<Meta, (Replay,)> = Untrusted::new(Meta {
            owner: "alice".into(),
            version: 7,
        });
        let projected: Untrusted<u32, (Replay,)> = raw.map(|m| m.version);
        let v = projected
            .trust_unchecked::<Replay, _>(reason!("test fixture"))
            .into_inner();
        assert_eq!(v, 7);
    }

    #[test]
    fn empty_scope_constructs_directly_into_inner() {
        // For values where no concerns apply (rare, but possible at
        // boundaries we generate ourselves), `Untrusted<T, ()>` is
        // directly consumable.
        let u: Untrusted<u32, ()> = Untrusted::new(99);
        assert_eq!(u.into_inner(), 99);
    }

    #[test]
    fn reason_token_is_zst() {
        // Sanity check that the audit-trail token has zero runtime
        // size — passing it as a method argument is free.
        assert_eq!(std::mem::size_of::<Reason>(), 0);
    }

    #[test]
    fn exposed_round_trips_empty_scope() {
        let e: Exposed<Vec<u8>, ()> = Exposed::new(vec![1u8, 2, 3]);
        assert_eq!(e.into_inner(), vec![1, 2, 3]);
    }

    #[test]
    fn exposed_vouch_peels_concerns_in_any_order() {
        let raw: Exposed<u32, (AuthN, AuthZ, Covert)> = Exposed::new(42);
        let v = raw
            .vouch_unchecked::<Covert, _>(reason!("test fixture"))
            .vouch_unchecked::<AuthN, _>(reason!("test fixture"))
            .vouch_unchecked::<AuthZ, _>(reason!("test fixture"))
            .into_inner();
        assert_eq!(v, 42);
    }

    #[test]
    fn exposed_vouch_predicate_style_propagates_error() {
        let raw: Exposed<&'static str, (Covert,)> = Exposed::new("encoded:bits");
        let err = raw
            .vouch::<Covert, _, _, _, _>(|s| {
                if s.contains(':') {
                    Err("looks like encoded data")
                } else {
                    Ok(s)
                }
            })
            .unwrap_err();
        assert_eq!(err, "looks like encoded data");
    }

    #[test]
    fn exposed_vouch_transforming_changes_type_on_success() {
        // Real outbound shape: plaintext value → ciphertext bytes
        // after AEAD-seal. We model with a serialise-to-bytes step.
        let raw: Exposed<&'static str, (AuthN,)> = Exposed::new("hello");
        let bytes: Exposed<Vec<u8>, ()> = raw
            .vouch::<AuthN, _, _, _, _>(|s| Ok::<_, ()>(s.as_bytes().to_vec()))
            .unwrap();
        assert_eq!(bytes.into_inner(), b"hello".to_vec());
    }

    #[test]
    fn exposed_map_preserves_scope() {
        let raw: Exposed<Meta, (AuthN, Covert)> = Exposed::new(Meta {
            owner: "alice".into(),
            version: 7,
        });
        let projected: Exposed<u32, (AuthN, Covert)> = raw.map(|m| m.version);
        let v = projected
            .vouch_unchecked::<AuthN, _>(reason!("test fixture"))
            .vouch_unchecked::<Covert, _>(reason!("test fixture"))
            .into_inner();
        assert_eq!(v, 7);
    }

    // === Compile-fail expectations ===
    //
    // These cases would not compile:
    //
    //   raw.trust_unchecked::<AuthZ, _>(reason!("..."));  // scope lacks AuthZ
    //   raw.trust_unchecked::<AuthN, _>();                // missing reason token
    //   raw.trust_unchecked::<AuthN, _>(Reason(()));      // private field
    //   raw.into_inner();                                 // scope is non-empty
    //
    //   exposed.vouch_unchecked::<Replay, _>(reason!()); // wrong direction
    //   exposed.into_inner();                            // scope is non-empty
    //
    // We rely on the type system + macro hygiene to reject these.
}
