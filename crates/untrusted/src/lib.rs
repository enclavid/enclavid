//! Type-level markers for values crossing the TEE ↔ host trust
//! boundary. Two dual wrappers, one per direction.
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
//! `Exposed<T>` — OUTBOUND. Marker for a sealed bytes-payload that
//! is being released to the host. Constructed via
//! `Exposed::expose(value)`; transport unwraps via `release()` only
//! at the wire boundary. Sealing (encryption) happens upstream;
//! `Exposed<T>` is documentary, not cryptographic. Reviewers grep
//! for `Exposed::expose` to find every release point.

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
/// application-level predicate (e.g., workspace_id match against the
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
    pub fn new(value: T, _scope_reason: Reason) -> Self {
        Self { value, _marker: PhantomData }
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
        Untrusted { value: self.value, _marker: PhantomData }
    }

    /// Address concern `X` via a predicate. On `Ok(())` returns a
    /// new `Untrusted` with `X` removed from the scope; on `Err(e)`
    /// propagates the error and the scope is unchanged.
    pub fn trust<X, I, F, E>(self, check: F) -> Result<Untrusted<T, S::Rest>, E>
    where
        S: Remove<X, I>,
        F: FnOnce(&T) -> Result<(), E>,
    {
        check(&self.value)?;
        Ok(Untrusted { value: self.value, _marker: PhantomData })
    }

    /// Project the inner value while preserving the scope. Use when
    /// you need to transform `T` to `U` (e.g., extract a sub-field)
    /// without addressing any concerns yet — the wrapped value
    /// becomes `Untrusted<U, S>` with the same open concerns.
    pub fn map<U, F>(self, f: F) -> Untrusted<U, S>
    where
        F: FnOnce(T) -> U,
    {
        Untrusted { value: f(self.value), _marker: PhantomData }
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
// Exposed<T> — outbound wrapper. (Unchanged from the prior API.)
// =====================================================================

/// Outbound wrapper. Constructed at call sites that release a
/// (typically already-sealed) value to the host. The wrap is the
/// audit trail — `Exposed::expose` markers grep to every TEE → host
/// data release.
#[derive(Debug)]
pub struct Exposed<T>(T);

impl<T> Exposed<T> {
    /// Wrap a value being released to the host. Sealing (encryption,
    /// integrity protection) must already have happened upstream —
    /// `Exposed<T>` is documentary, not cryptographic.
    pub fn expose(value: T) -> Self {
        Self(value)
    }

    /// Unwrap at the point of handing to the wire. Used inside the
    /// transport layer right before the gRPC send.
    pub fn release(self) -> T {
        self.0
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
        let raw: Untrusted<Meta, (AuthN, AuthZ, Replay)> = Untrusted::new(
            Meta { owner: "alice".into(), version: 1 },
            reason!("test fixture"),
        );
        let after_authn = raw.trust_unchecked::<AuthN, _>(reason!("test fixture"));
        let after_authz = after_authn
            .trust::<AuthZ, _, _, _>(|m| {
                if m.owner == "alice" { Ok(()) } else { Err("wrong owner") }
            })
            .unwrap();
        let m = after_authz
            .trust_unchecked::<Replay, _>(reason!("test fixture"))
            .into_inner();
        assert_eq!(
            m,
            Meta { owner: "alice".into(), version: 1 }
        );
    }

    #[test]
    fn peel_in_arbitrary_order() {
        // Same scope, peeled in different order — type inference
        // picks the matching position marker each time.
        let raw: Untrusted<u32, (AuthN, AuthZ, Replay)> =
            Untrusted::new(42, reason!("test fixture"));
        let v = raw
            .trust_unchecked::<Replay, _>(reason!("test fixture"))
            .trust_unchecked::<AuthN, _>(reason!("test fixture"))
            .trust_unchecked::<AuthZ, _>(reason!("test fixture"))
            .into_inner();
        assert_eq!(v, 42);
    }

    #[test]
    fn trust_predicate_propagates_error() {
        let raw: Untrusted<&'static str, (AuthZ,)> =
            Untrusted::new("mallory", reason!("test fixture"));
        let err = raw
            .trust::<AuthZ, _, _, _>(|s| {
                if *s == "alice" { Ok(()) } else { Err("not alice") }
            })
            .unwrap_err();
        assert_eq!(err, "not alice");
    }

    #[test]
    fn map_preserves_scope() {
        let raw: Untrusted<Meta, (Replay,)> = Untrusted::new(
            Meta { owner: "alice".into(), version: 7 },
            reason!("test fixture"),
        );
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
        let u: Untrusted<u32, ()> = Untrusted::new(99, reason!("test fixture"));
        assert_eq!(u.into_inner(), 99);
    }

    #[test]
    fn reason_token_is_zst() {
        // Sanity check that the audit-trail token has zero runtime
        // size — passing it as a method argument is free.
        assert_eq!(std::mem::size_of::<Reason>(), 0);
    }

    #[test]
    fn exposed_round_trips() {
        let e = Exposed::expose(vec![1u8, 2, 3]);
        assert_eq!(e.release(), vec![1, 2, 3]);
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
    // We rely on the type system + macro hygiene to reject these.
}
