//! Type-level wrappers for values crossing a trust boundary. Two dual
//! wrappers, one per direction, and the vocabulary they are written in.
//!
//! It has lived in two places. On its own as `enclavid-untrusted`, then folded
//! into `hatch-client` so the definitions sat beside the facades that construct
//! them. Out again, because the TEE grew a second way to speak: the serial port
//! that `safe-logger` writes to. Two channels with nothing in common but this
//! vocabulary, so the vocabulary belongs below both. The mints stay with the
//! channels — a leg's in the declarations of its ends — and `safe-logger`, which
//! opens its channel before anything else in a role exists, depends on the
//! vocabulary without depending on a wire client.
//!
//! `Untrusted<T, S, B>` — INBOUND. `S` is a tuple of the concerns still open on
//! the value; what each one asks is written on the marker itself ([`AuthN`],
//! [`AuthZ`], [`Replay`], [`Asserted`], [`Covert`]) and nowhere else. The inner
//! `T` is reachable through `into_inner` only once every concern has been
//! answered and `S` is `()`.
//!
//! `Exposed<T, S, B>` — OUTBOUND, the mirror: the concerns still open on a value
//! being released, answered before `into_inner` lets it go.
//!
//! ## Answering a concern
//!
//! Every marker lists the legal ways to answer it as constants of its own type
//! — `AuthN::Verified`, `AuthZ::NoSecret`, `Asserted::AcceptedRisk` — and each is
//! classed by what answering with it takes. The class decides which method takes
//! it, so the form of a peel says what backs it:
//!
//!   * `trust(reason!(K, "…"))` / `vouch(…)` — an [`Argued`] kind: its own
//!     argument is the answer, and no work at the peel is needed for it to hold.
//!   * `trust_with(K, |v| …)` / `vouch_with(…)` — the work in the closure is the
//!     answer. A [`Work`] kind is taken here and nowhere else, so it cannot be
//!     claimed without the work in front of the reader; an argued kind may be
//!     backed by work too.
//!   * `trust_accept_risk(reason!(M::AcceptedRisk, "…"))` / `vouch_accept_risk(…)`
//!     — no kind fits, and the site says so. A [`Risk`] is taken here alone, so
//!     the standing risks are one grep away.
//!
//! The marker is inferred from the kind, so a peel names no type parameter, and a
//! reason that names no kind does not compile against any of them.
//!
//! ## The end
//!
//! `B` is the end of a boundary the value crossed, as the role holding that end
//! judges it. A declared end — a type `boundary!` from `enclavid-boundary-macros`
//! writes — states, for each type crossing it, which concerns its direction
//! opens and which the declaration answers once for every value of that type;
//! [`outbound`] and [`inbound`] wrap a value at such an end with exactly what is
//! left. A value that arrives where nothing declares the end carries
//! [`Undeclared`], and its scope is whatever its mint opened. Nothing leaves
//! there: every value released leaves a declared end.
//!
//! Scope and end are part of the type, so a receipt — `Exposed<_, (), B>` —
//! records which end it was answered for, and a door that names its end takes
//! no other.

use std::marker::PhantomData;

// =====================================================================
// Kinds — the legal answers, as constants of each marker — and the
// classes that say what answering with one takes.
// =====================================================================

/// An answer that is work done on the value at the peel: a check over its
/// bytes, a transformation of its encoding. Taken by `trust_with` / `vouch_with`
/// and nothing else.
pub struct Work;

/// An answer that is the kind's own argument: no work at the peel is needed for
/// it to hold. Taken by `trust` / `vouch` with a reason, and by `trust_with` /
/// `vouch_with` where work backs it anyway.
pub struct Argued;

/// No kind fits, and the site says so. Taken by `trust_accept_risk` /
/// `vouch_accept_risk` alone.
pub struct Risk;

mod backs_sealed {
    pub trait Sealed {}
    impl Sealed for super::Work {}
    impl Sealed for super::Argued {}
}

/// The classes work can stand behind: a [`Work`] kind, or an [`Argued`] one whose
/// argument the work makes concrete. Never [`Risk`] — a risk with a check in front
/// of it is not a risk, and should name the kind the check establishes.
pub trait Backs: backs_sealed::Sealed {}
impl Backs for Work {}
impl Backs for Argued {}

/// One legal way to answer concern `M`, of class `By`. Defined as a constant of
/// the marker it belongs to — the list there is the whole list.
pub struct Kind<M, By>(PhantomData<fn() -> (M, By)>);

impl<M, By> Kind<M, By> {
    /// `pub` and `doc(hidden)`, for the reason `Untrusted::new` is: a marker
    /// defined in another crate defines its kinds with it, and nothing else
    /// should. A kind made anywhere but next to its marker is a kind no reviewer
    /// will find on the list.
    #[doc(hidden)]
    pub const fn __define() -> Self {
        Self(PhantomData)
    }
}

impl<M, By> Clone for Kind<M, By> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<M, By> Copy for Kind<M, By> {}

// =====================================================================
// Reason token + `reason!` macro.
// =====================================================================

/// Audit-trail token — proves the caller wrote a `reason!(...)` beside what it
/// justifies. A ZST; the explanation lives in source code only.
///
/// `Reason<M, By>` justifies an answer to concern `M` with a kind of class `By`:
/// that is the form every argued peel and every accepted risk takes. The bare
/// `Reason` justifies a line on the serial port (`safe-logger`), which answers
/// no marker — and, being a different type, can stand behind no peel.
///
/// `Copy + Clone` so a single `reason!(...)` can be reused across sites in one
/// expression — a `decode` with two return paths sharing a rationale.
pub struct Reason<M = (), By = ()>(PhantomData<fn() -> (M, By)>);

impl Reason {
    #[doc(hidden)]
    pub const fn __reason_macro_internal_do_not_call_directly() -> Self {
        Self(PhantomData)
    }
}

impl<M, By> Reason<M, By> {
    #[doc(hidden)]
    pub const fn __reason_macro_internal_for_kind(_kind: Kind<M, By>) -> Self {
        Self(PhantomData)
    }
}

impl<M, By> Clone for Reason<M, By> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<M, By> Copy for Reason<M, By> {}

impl<M, By> std::fmt::Debug for Reason<M, By> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Reason")
    }
}

/// Build a [`Reason`]. The string literal is parsed by the macro but never
/// appears in its expansion — it is discarded at compile time, so the binary
/// contains neither the bytes nor a pointer to them.
///
/// Two forms. With a kind, it justifies answering that kind's marker, and the
/// marker is inferred from it:
///
/// ```ignore
/// value
///     .trust(reason!(AuthZ::NoPrincipal, "the return value of a read this side made"))
///     .trust(reason!(Replay::Harmless, "a stale copy only makes the next write refuse"))
///     .into_inner();
/// ```
///
/// With the text alone, it justifies a log line (`safe-logger`), and no peel
/// takes it.
#[macro_export]
macro_rules! reason {
    ($explanation:literal) => {
        $crate::Reason::<(), ()>::__reason_macro_internal_do_not_call_directly()
    };
    ($kind:path, $explanation:literal) => {
        $crate::Reason::__reason_macro_internal_for_kind($kind)
    };
}

// =====================================================================
// Concern markers — what a scope is made of. One file, because the
// question each one asks is the only thing here that is not machinery.
// =====================================================================

mod markers;
pub use markers::{Asserted, AuthN, AuthZ, Covert, Replay};

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

mod remove_sealed {
    /// Implemented beside each of this crate's own `Remove` impls, and nowhere
    /// else.
    pub trait Sealed<X, I> {}
}

/// Remove the type `X` from a tuple `Self` (of concern markers),
/// producing `Self::Rest`. The `I` type parameter disambiguates
/// which position `X` sits in — the compiler infers it.
///
/// Sealed: every impl is one position of one tuple, so a peel takes exactly one
/// concern off. An impl elsewhere could take several off in one:
///
/// ```compile_fail
/// use enclavid_boundary::{AuthZ, Covert, Remove};
/// pub struct Both;
/// impl Remove<AuthZ, Both> for (AuthZ, Covert) {
///     type Rest = ();
/// }
/// ```
pub trait Remove<X, I>: remove_sealed::Sealed<X, I> {
    type Rest;
}

// 1-tuple: only position P0.
impl<X> remove_sealed::Sealed<X, P0> for (X,) {}
impl<X> Remove<X, P0> for (X,) {
    type Rest = ();
}

// 2-tuple: P0, P1.
impl<X, B> remove_sealed::Sealed<X, P0> for (X, B) {}
impl<X, B> Remove<X, P0> for (X, B) {
    type Rest = (B,);
}
impl<A, X> remove_sealed::Sealed<X, P1> for (A, X) {}
impl<A, X> Remove<X, P1> for (A, X) {
    type Rest = (A,);
}

// 3-tuple: P0, P1, P2.
impl<X, B, C> remove_sealed::Sealed<X, P0> for (X, B, C) {}
impl<X, B, C> Remove<X, P0> for (X, B, C) {
    type Rest = (B, C);
}
impl<A, X, C> remove_sealed::Sealed<X, P1> for (A, X, C) {}
impl<A, X, C> Remove<X, P1> for (A, X, C) {
    type Rest = (A, C);
}
impl<A, B, X> remove_sealed::Sealed<X, P2> for (A, B, X) {}
impl<A, B, X> Remove<X, P2> for (A, B, X) {
    type Rest = (A, B);
}

// 4-tuple: P0, P1, P2, P3 — headroom for one more concern axis
// without crate-level migration.
impl<X, B, C, D> remove_sealed::Sealed<X, P0> for (X, B, C, D) {}
impl<X, B, C, D> Remove<X, P0> for (X, B, C, D) {
    type Rest = (B, C, D);
}
impl<A, X, C, D> remove_sealed::Sealed<X, P1> for (A, X, C, D) {}
impl<A, X, C, D> Remove<X, P1> for (A, X, C, D) {
    type Rest = (A, C, D);
}
impl<A, B, X, D> remove_sealed::Sealed<X, P2> for (A, B, X, D) {}
impl<A, B, X, D> Remove<X, P2> for (A, B, X, D) {
    type Rest = (A, B, D);
}
impl<A, B, C, X> remove_sealed::Sealed<X, P3> for (A, B, C, X) {}
impl<A, B, C, X> Remove<X, P3> for (A, B, C, X) {
    type Rest = (A, B, C);
}

// =====================================================================
// Open — a scope with something still to answer.
// =====================================================================

mod sealed {
    pub trait Sealed {}
}

/// A scope with at least one concern still open.
///
/// Implemented for every non-empty marker tuple and NEVER for `()`, which is the
/// whole point. `Untrusted<T, ()>` and `Exposed<T, (), B>` mean "every concern
/// was answered", and both release their inner value on that basis — so a mint
/// able to produce one directly would let a caller assert the answer without
/// ever having given it.
///
/// [`Untrusted::new`] is the one mint whose scope its caller picks, and it takes
/// this bound: the concerns a crossing raises are the caller's to name, but it
/// cannot name none, so an empty scope is somewhere you arrive —
///
/// ```compile_fail
/// use enclavid_boundary::Untrusted;
/// let _: Untrusted<u32, ()> = Untrusted::new(7);
/// ```
///
/// — while a non-empty one still constructs:
///
/// ```
/// use enclavid_boundary::{Replay, Untrusted};
/// let _: Untrusted<u32, (Replay,)> = Untrusted::new(7);
/// ```
///
/// [`outbound_builder`] takes it too, on what its end left open on the type it
/// builds: a type its declaration answered in full has no work to be built in.
///
/// The one way to `()` without a peel is a declaration: [`outbound`] and
/// [`inbound`] give a value the scope its end's declaration left open, and where
/// the declaration answered everything about that type, that is `()`. The answers
/// are written there, once, in the place a reviewer reads them.
///
/// **A receipt is for the type it was answered for.** An `Exposed` is opened only
/// at a declared end, through its declaration. The work in
/// [`Exposed::vouch_with`] keeps the value's type, and a value built in the work
/// leaves through an [`ExposedBuilder`], whose one way out is a value of the type
/// whose declaration it was opened under. Nothing carries an outbound scope onto
/// a different value.
///
/// **What this bound does NOT give you.** `((),)` is a non-empty tuple, so it is
/// `Open`, and its single "marker" is the unit type — nothing prevents a scope
/// that asks nothing. The accident the bound catches is the quiet one: with a
/// bare value in hand where a signature wants `Untrusted<_, ()>`,
/// `Untrusted::new(v)` is the natural thing to type and would otherwise compile
/// in silence. So a scope of `()` is evidence that the mint was walked, not proof
/// that it was: the guard lives in the same repository as what it guards, and it
/// stops a wrong turn, not an author who means it.
pub trait Open: sealed::Sealed {}

macro_rules! impl_open {
    ($($T:ident),+) => {
        impl<$($T),+> sealed::Sealed for ($($T,)+) {}
        impl<$($T),+> Open for ($($T,)+) {}
    };
}
impl_open!(T0);
impl_open!(T0, T1);
impl_open!(T0, T1, T2);
impl_open!(T0, T1, T2, T3);
impl_open!(T0, T1, T2, T3, T4);
impl_open!(T0, T1, T2, T3, T4, T5);
impl_open!(T0, T1, T2, T3, T4, T5, T6);
impl_open!(T0, T1, T2, T3, T4, T5, T6, T7);

// =====================================================================
// Direction — which scopes a marker may stand in.
// =====================================================================

/// A concern a value ARRIVING may carry: a marker an `in` block of a declaration
/// may open. Direction is part of a marker's meaning — a marker implements this
/// only if its question can be asked of a value this side receives.
pub trait InboundConcern {}

/// A concern a value LEAVING may carry: a marker an `out` block of a declaration
/// may open.
pub trait OutboundConcern {}

// =====================================================================
// Ends — what a `boundary!` declaration writes, and the two mints that
// read it.
// =====================================================================

/// One end of a boundary, as the role that holds it judges what crosses.
///
/// `boundary!` (`enclavid-boundary-macros`) declares one: a type that implements
/// this, plus a [`Sends`] or [`Receives`] impl for every type crossing it.
pub trait Boundary {}

/// This end sends `T`, and `Open` is what is still open on a `T` once the
/// declaration has answered what it answers for every value of it.
///
/// Implemented on the END rather than on `T`, so that what a protocol requires
/// of an end can be its supertraits — `B: RemoteExecutorCalls` then brings
/// every `Sends` / `Receives` it lists along, where a bound on `T` would have to
/// be restated at every use.
pub trait Sends<T>: Boundary {
    type Open;
}

/// This end receives `T`, and `Open` is what is still open on a `T` once the
/// declaration has answered what it answers for every value of it.
pub trait Receives<T>: Boundary {
    type Open;
}

/// The end of an arrival nothing has declared. Its scope is whatever the mint
/// opened, and no declaration answers any of it. Nothing leaves at it.
pub struct Undeclared;

/// Open `value` to leave end `B`: open on exactly what `B`'s declaration left
/// open for this type — `()` where the declaration answered everything.
pub fn outbound<B: Sends<T>, T>(value: T) -> Exposed<T, B::Open, B> {
    Exposed {
        value,
        _marker: PhantomData,
    }
}

/// [`outbound`] for a value that becomes the `W` that crosses only in the work
/// that answers it — the parts a request is framed from, say. The builder opens
/// what `B` left open on a `W`, whatever it holds on the way, and the one way out
/// of an [`ExposedBuilder`] is [`build`](ExposedBuilder::build), once it holds a
/// `W` and nothing is open — so the receipt is for a `W` and for nothing else.
///
/// What `B` left open on `W` must not be empty: a `W` its declaration answered in
/// full has no work to be built in, and is opened with [`outbound`] once it exists.
pub fn outbound_builder<B, W, T>(value: T) -> ExposedBuilder<T, W, B::Open, B>
where
    B: Sends<W>,
    B::Open: Open,
{
    ExposedBuilder {
        value,
        _builds: PhantomData,
        _marker: PhantomData,
    }
}

/// Wrap `value` as it arrives at end `B`: open on exactly what `B`'s declaration
/// left open for this type — `()` where the declaration answered everything.
pub fn inbound<B: Receives<T>, T>(value: T) -> Untrusted<T, B::Open, B> {
    Untrusted {
        value,
        _marker: PhantomData,
    }
}

// =====================================================================
// Untrusted<T, S, B> — inbound wrapper.
// =====================================================================

/// Inbound wrapper. `S` is a tuple of concern markers; methods answer one
/// concern at a time until `S = ()`, after which the inner `T` is reachable via
/// `into_inner`. `B` is the end it arrived at.
pub struct Untrusted<T, S = (), B = Undeclared> {
    value: T,
    _marker: PhantomData<fn() -> (S, B)>,
}

impl<T: std::fmt::Debug, S, B> std::fmt::Debug for Untrusted<T, S, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Untrusted").field(&self.value).finish()
    }
}

impl<T, S> Untrusted<T, S, Undeclared> {
    /// Wrap a value with an explicit initial scope. The caller picks `S` to match
    /// what concerns are genuinely open at the construction site.
    ///
    /// `S: Open`, so the scope cannot be `()`: a wrapper with nothing left to
    /// answer is something a peel or a declaration produces, never something a
    /// caller declares. And only at [`Undeclared`]: a declared end's scope is its
    /// declaration's, so a value arriving there is wrapped by [`inbound`].
    ///
    /// `pub` and `doc(hidden)`. It has to be public — the sites that call it
    /// live in other crates, and this one is a dependency-free leaf, so there is
    /// no `pub(crate)` that could span them. Hidden because nothing else should
    /// ever find it: the guard here is against a wrong turn, not against someone
    /// with commit access, and the named entry points are what a reviewer greps.
    #[doc(hidden)]
    pub fn new(value: T) -> Self
    where
        S: Open,
    {
        Self {
            value,
            _marker: PhantomData,
        }
    }
}

impl<T, S, B> Untrusted<T, S, B> {
    /// Answer concern `M` with an argued kind: the kind's argument is the answer,
    /// and the [`reason!`] says why it holds here.
    pub fn trust<M, I>(self, _reason: Reason<M, Argued>) -> Untrusted<T, S::Rest, B>
    where
        S: Remove<M, I>,
    {
        Untrusted {
            value: self.value,
            _marker: PhantomData,
        }
    }

    /// Answer concern `M` with the work in `work`: a check over the value, an
    /// open, a decode. The closure takes the value and gives back a (possibly
    /// transformed) one — AEAD-open turns ciphertext into plaintext; a predicate
    /// that only checks returns its input.
    ///
    /// On success the scope shrinks by `M`; on failure the wrapper is dropped.
    pub fn trust_with<M, I, K, U, F, E>(
        self,
        _kind: Kind<M, K>,
        work: F,
    ) -> Result<Untrusted<U, S::Rest, B>, E>
    where
        S: Remove<M, I>,
        K: Backs,
        F: FnOnce(T) -> Result<U, E>,
    {
        let value = work(self.value)?;
        Ok(Untrusted {
            value,
            _marker: PhantomData,
        })
    }

    /// Take concern `M` off with no kind that fits: a standing accepted risk,
    /// and the [`reason!`] says what limits it.
    pub fn trust_accept_risk<M, I>(self, _reason: Reason<M, Risk>) -> Untrusted<T, S::Rest, B>
    where
        S: Remove<M, I>,
    {
        Untrusted {
            value: self.value,
            _marker: PhantomData,
        }
    }

    /// Project the inner value while preserving the scope. Use when you need to
    /// transform `T` to `U` (e.g., extract a sub-field) without answering any
    /// concern yet.
    pub fn map<U, F>(self, f: F) -> Untrusted<U, S, B>
    where
        F: FnOnce(T) -> U,
    {
        Untrusted {
            value: f(self.value),
            _marker: PhantomData,
        }
    }

    /// [`map`](Self::map) for a projection that can fail — unframing, say. It
    /// answers nothing: what comes out is open on everything the input was, the
    /// error as much as the value, since a projection's error can carry the
    /// sender's bytes as well.
    pub fn try_map<U, E, F>(self, f: F) -> Result<Untrusted<U, S, B>, Untrusted<E, S, B>>
    where
        F: FnOnce(T) -> Result<U, E>,
    {
        match f(self.value) {
            Ok(value) => Ok(Untrusted {
                value,
                _marker: PhantomData,
            }),
            Err(error) => Err(Untrusted {
                value: error,
                _marker: PhantomData,
            }),
        }
    }

    /// Take a two-way value apart, each half open on everything the whole was:
    /// the variants of a reply that lead to different paths, each judged on its
    /// own grounds. It answers nothing.
    pub fn split<L, R, F>(self, f: F) -> Result<Untrusted<L, S, B>, Untrusted<R, S, B>>
    where
        F: FnOnce(T) -> Result<L, R>,
    {
        match f(self.value) {
            Ok(l) => Ok(Untrusted {
                value: l,
                _marker: PhantomData,
            }),
            Err(r) => Err(Untrusted {
                value: r,
                _marker: PhantomData,
            }),
        }
    }
}

impl<T, B> Untrusted<T, (), B> {
    /// Reach the inner value once every concern has been answered. Only
    /// available when `S = ()`, so the type system enforces that consumers
    /// answer exhaustively.
    pub fn into_inner(self) -> T {
        self.value
    }
}

// =====================================================================
// Exposed<T, S, B> — outbound wrapper. Mirror of Untrusted.
// =====================================================================

/// Outbound wrapper. `S` is a tuple of concern markers; methods answer one
/// concern at a time until `S = ()`, after which the inner `T` is reachable via
/// `into_inner`. `B` is the declared end it leaves, which opened it
/// ([`outbound`], [`outbound_builder`]).
pub struct Exposed<T, S, B> {
    value: T,
    _marker: PhantomData<fn() -> (S, B)>,
}

impl<T: std::fmt::Debug, S, B> std::fmt::Debug for Exposed<T, S, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Exposed").field(&self.value).finish()
    }
}

impl<T: Clone, S, B> Clone for Exposed<T, S, B> {
    /// Manual `Clone` impl — derive can't synthesise it when the scope may not be
    /// `Clone` (it never is, the markers are phantom). Preserves scope and end.
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            _marker: PhantomData,
        }
    }
}

impl<T, S, B> Exposed<T, S, B> {
    /// Answer concern `M` with an argued kind: the kind's argument is the answer,
    /// and the [`reason!`] says why it holds here.
    pub fn vouch<M, I>(self, _reason: Reason<M, Argued>) -> Exposed<T, S::Rest, B>
    where
        S: Remove<M, I>,
    {
        Exposed {
            value: self.value,
            _marker: PhantomData,
        }
    }

    /// Take concern `M` off with no kind that fits: a standing accepted risk,
    /// and the [`reason!`] says what limits it.
    pub fn vouch_accept_risk<M, I>(self, _reason: Reason<M, Risk>) -> Exposed<T, S::Rest, B>
    where
        S: Remove<M, I>,
    {
        Exposed {
            value: self.value,
            _marker: PhantomData,
        }
    }

    /// Answer concern `M` with the work in `work`, which checks the value or
    /// rewrites it in place — a scrub, say — and gives back the same type: a
    /// receipt is for the type its declaration was read for. Work that builds
    /// the value that crosses starts from an [`ExposedBuilder`]
    /// ([`outbound_builder`]).
    ///
    /// Symmetric to [`Untrusted::trust_with`]: inbound work verifies, outbound
    /// work establishes. Both close their concern by performing the work, not by
    /// attesting to it.
    ///
    /// On success the scope shrinks by `M`; on failure the wrapper is dropped.
    pub fn vouch_with<M, I, K, F, E>(
        self,
        _kind: Kind<M, K>,
        work: F,
    ) -> Result<Exposed<T, S::Rest, B>, E>
    where
        S: Remove<M, I>,
        K: Backs,
        F: FnOnce(T) -> Result<T, E>,
    {
        let value = work(self.value)?;
        Ok(Exposed {
            value,
            _marker: PhantomData,
        })
    }
}

// =====================================================================
// ExposedBuilder<T, W, S, B> — a `W` being built, on its way out of `B`.
// =====================================================================

/// A `W` being built to leave end `B`, open on what `B`'s declaration left open
/// on a `W` ([`outbound_builder`]) whatever it holds on the way. Each answer takes
/// one concern off, and the work in [`vouch_with`](Self::vouch_with) may turn
/// what it holds into something else — a padded encoding, then its seal. Nothing
/// leaves it but [`build`](Self::build), which takes a builder holding a `W` with
/// nothing open, so the receipt is for a `W` and for nothing else.
pub struct ExposedBuilder<T, W, S, B> {
    value: T,
    /// What the builder builds.
    _builds: PhantomData<fn() -> W>,
    _marker: PhantomData<fn() -> (S, B)>,
}

impl<T: Clone, W, S, B> Clone for ExposedBuilder<T, W, S, B> {
    /// Preserves what it holds, what it builds, its scope and its end.
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            _builds: PhantomData,
            _marker: PhantomData,
        }
    }
}

impl<T, W, S, B> ExposedBuilder<T, W, S, B> {
    /// Answer concern `M` with an argued kind, as [`Exposed::vouch`] does.
    pub fn vouch<M, I>(self, _reason: Reason<M, Argued>) -> ExposedBuilder<T, W, S::Rest, B>
    where
        S: Remove<M, I>,
    {
        ExposedBuilder {
            value: self.value,
            _builds: PhantomData,
            _marker: PhantomData,
        }
    }

    /// Take concern `M` off as a standing risk, as [`Exposed::vouch_accept_risk`]
    /// does.
    pub fn vouch_accept_risk<M, I>(
        self,
        _reason: Reason<M, Risk>,
    ) -> ExposedBuilder<T, W, S::Rest, B>
    where
        S: Remove<M, I>,
    {
        ExposedBuilder {
            value: self.value,
            _builds: PhantomData,
            _marker: PhantomData,
        }
    }

    /// Answer concern `M` with the work in `work`, which may turn what the
    /// builder holds into something else. What comes back is still a builder of
    /// the `W` it was opened for: the concerns left are the `W`'s, whatever it
    /// holds now.
    ///
    /// On success the scope shrinks by `M`; on failure the builder is dropped.
    pub fn vouch_with<M, I, K, U, F, E>(
        self,
        _kind: Kind<M, K>,
        work: F,
    ) -> Result<ExposedBuilder<U, W, S::Rest, B>, E>
    where
        S: Remove<M, I>,
        K: Backs,
        F: FnOnce(T) -> Result<U, E>,
    {
        let value = work(self.value)?;
        Ok(ExposedBuilder {
            value,
            _builds: PhantomData,
            _marker: PhantomData,
        })
    }
}

impl<W, B> ExposedBuilder<W, W, (), B> {
    /// The `W` the builder was opened for, every concern answered: the one way
    /// out of it. Only a builder that holds a `W` and has nothing open has this.
    pub fn build(self) -> Exposed<W, (), B> {
        Exposed {
            value: self.value,
            _marker: PhantomData,
        }
    }
}

impl<T, B> Exposed<T, (), B> {
    /// Reach the inner value once every concern has been answered. Only
    /// available when `S = ()`, so the type system enforces that consumers
    /// answer exhaustively before the value hits the wire.
    pub fn into_inner(self) -> T {
        self.value
    }

    /// Borrow the inner value once every concern has been answered. Same
    /// `S = ()` gate as [`into_inner`](Self::into_inner) — usable when the
    /// caller needs read-only access (e.g. to feed the bytes through a chained
    /// hash) before later releasing the value to wire. Reviewers grep for
    /// `into_inner` *and* `as_inner` to find every release point.
    pub fn as_inner(&self) -> &T {
        &self.value
    }
}

// =====================================================================
// What a declaration says, as data.
// =====================================================================

/// What a `boundary!` declaration says, as plain data a test can render: each
/// declared end carries one as `DECLARATION`, in its own crate's test build.
pub mod declaration {
    /// One declared end.
    pub struct End {
        /// The end's type name.
        pub name: &'static str,
        /// The declaration's own doc.
        pub doc: &'static str,
        /// Who sees the bytes on the way.
        pub observer: &'static str,
        /// The protocols this end calls.
        pub calls: &'static [Protocol],
        /// The protocols this end serves.
        pub serves: &'static [Protocol],
        pub crossings: &'static [Crossing],
    }

    /// One protocol, as an end holding it sees it: what crosses for each method,
    /// as `#[protocol]` read the contract, and at a calling end what each
    /// method's door takes and hands back, as `#[calls]` read the doors. Its name
    /// is what pairs an end that calls it with one that serves it.
    pub struct Protocol {
        /// The contract's name.
        pub name: &'static str,
        pub methods: &'static [Method],
    }

    /// One method of a protocol, and the types that cross for it.
    pub struct Method {
        pub name: &'static str,
        /// Its arguments, in order; a capability handed over is not one.
        pub args: &'static [&'static str],
        pub reply: &'static str,
        pub error: &'static str,
        /// What the calling end's door for it takes and hands back, at a calling
        /// end; `None` at a serving end, which holds what crosses.
        pub door: Option<Door>,
    }

    /// What a calling end's door takes and hands back, `Self` being that end.
    pub struct Door {
        /// What it takes, answered at the end; and what its `where` says it
        /// builds what crosses as, answered in full.
        pub sends: &'static [&'static str],
        /// What it receives: each type whose declaration leaves open what the
        /// door hands back, which may be that value or what it is taken from.
        pub receives: &'static [&'static str],
    }

    impl End {
        /// What this end declares but never holds: a type that crosses for a
        /// protocol it calls only where a door builds it, or takes it apart. No
        /// line about such a type governs anything, so a sound end has none.
        /// Types are compared as spelled, less the paths they are named by.
        pub fn unheld(&self) -> Vec<&'static str> {
            let as_this_end = |part: &str| bare(&as_end(part, self.name));
            let (mut crossing, mut held) = ((Vec::new(), Vec::new()), (Vec::new(), Vec::new()));
            for method in self.calls.iter().flat_map(|p| p.methods) {
                let args = method.args.iter().map(|a| bare(a));
                crossing.0.extend(args.clone());
                crossing.1.push(bare(method.reply));
                match &method.door {
                    None => {
                        held.0.extend(args);
                        held.1.push(bare(method.reply));
                    }
                    Some(door) => {
                        held.0.extend(door.sends.iter().map(|s| as_this_end(s)));
                        held.1.extend(door.receives.iter().map(|r| as_this_end(r)));
                    }
                }
            }
            self.crossings
                .iter()
                .filter(|c| {
                    let (crossing, held) = match c.direction {
                        Direction::Out => (&crossing.0, &held.0),
                        Direction::In => (&crossing.1, &held.1),
                    };
                    let ty = bare(c.ty);
                    crossing.contains(&ty) && !held.contains(&ty)
                })
                .map(|c| c.ty)
                .collect()
        }
    }

    fn is_word(c: char) -> bool {
        c.is_alphanumeric() || c == '_'
    }

    /// `ty` with the word `Self` in it read as `end`, and no other word touched.
    fn as_end(ty: &str, end: &str) -> String {
        let mut out = String::new();
        let mut rest = ty;
        while let Some(at) = rest.find("Self") {
            let before = rest[..at].chars().next_back();
            let after = rest[at + 4..].chars().next();
            let in_a_word = before.is_some_and(is_word) || after.is_some_and(is_word);
            out.push_str(&rest[..at]);
            out.push_str(if in_a_word { "Self" } else { end });
            rest = &rest[at + 4..];
        }
        out.push_str(rest);
        out
    }

    /// `ty` with every path it names a type by left out:
    /// `storage_rpc::Fields<crate::Slot>` is `Fields<Slot>`. A `::` with no
    /// name of a path before it — after a `>`, say — stays.
    fn bare(ty: &str) -> String {
        let mut out = String::new();
        let mut rest = ty;
        while let Some(at) = rest.find("::") {
            let before = &rest[..at];
            let qualifier = before.trim_end_matches(is_word);
            if qualifier.len() == before.len() && !before.is_empty() {
                out.push_str(before);
                out.push_str("::");
            } else {
                out.push_str(qualifier);
            }
            rest = &rest[at + 2..];
        }
        out.push_str(rest);
        out
    }

    #[cfg(test)]
    mod tests {
        use super::{as_end, bare};

        /// Paths go, and every name stays.
        #[test]
        fn bare_leaves_out_paths_and_nothing_else() {
            assert_eq!(bare("storage_rpc::Fields<crate::Slot>"), "Fields<Slot>");
            assert_eq!(bare("::wire::Done"), "Done");
            assert_eq!(bare("Option<a::b::C>"), "Option<C>");
            assert_eq!(bare("&'static crate::Name"), "&'static Name");
            assert_eq!(bare("<T as Trait>::Assoc"), "<T as Trait>::Assoc");
        }

        /// `Self` is read as the end where it is a word of its own, and only there.
        #[test]
        fn self_is_the_end_only_as_a_word() {
            assert_eq!(as_end("Fields<Self>", "Storage"), "Fields<Storage>");
            assert_eq!(as_end("Selfie<Self>", "End"), "Selfie<End>");
            assert_eq!(as_end("MySelf", "End"), "MySelf");
        }
    }

    /// Which way a type crosses this end.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Direction {
        Out,
        In,
    }

    /// One type crossing one end.
    pub struct Crossing {
        pub direction: Direction,
        pub ty: &'static str,
        /// The concerns its direction opens on it.
        pub opens: &'static [&'static str],
        /// What the declaration answers, once, for every value of it.
        pub answers: &'static [Answer],
        /// What is left for the site that holds a value of it.
        pub left: &'static [&'static str],
    }

    /// One answer a declaration gives.
    pub struct Answer {
        pub marker: &'static str,
        pub kind: &'static str,
        /// The reason, from the doc above the answer.
        pub doc: &'static str,
        /// Given with `_`, for every type in its block, rather than on this type's
        /// own line.
        pub every_type: bool,
    }
}

// =====================================================================
// What the compiler refuses — as doctests, since a refusal is a build that fails.
// =====================================================================

/// The class of a kind decides the method, and that is checked by the compiler,
/// not by review.
///
/// A work kind cannot be argued:
///
/// ```compile_fail
/// use enclavid_boundary::{AuthN, Untrusted, reason};
/// let v: Untrusted<u8, (AuthN,)> = Untrusted::new(1);
/// let _ = v.trust(reason!(AuthN::Verified, "claimed, not done"));
/// ```
///
/// A risk cannot be argued:
///
/// ```compile_fail
/// use enclavid_boundary::{Asserted, Untrusted, reason};
/// let v: Untrusted<u8, (Asserted,)> = Untrusted::new(1);
/// let _ = v.trust(reason!(Asserted::AcceptedRisk, "a risk, written as an answer"));
/// ```
///
/// A reason that names no kind answers no concern:
///
/// ```compile_fail
/// use enclavid_boundary::{AuthZ, Untrusted, reason};
/// let v: Untrusted<u8, (AuthZ,)> = Untrusted::new(1);
/// let _ = v.trust(reason!("no kind named"));
/// ```
///
/// A kind answers its own marker and no other:
///
/// ```compile_fail
/// use enclavid_boundary::{AuthN, AuthZ, Untrusted, reason};
/// let v: Untrusted<u8, (AuthZ,)> = Untrusted::new(1);
/// let _ = v.trust(reason!(AuthN::Indifferent, "the wrong question"));
/// ```
///
/// And a receipt is for the end it was answered for:
///
/// ```compile_fail
/// use enclavid_boundary::{Boundary, Exposed, Sends, outbound};
/// struct A;
/// struct B;
/// impl Boundary for A {}
/// impl Boundary for B {}
/// impl Sends<u8> for A { type Open = (); }
/// fn door(_: Exposed<u8, (), B>) {}
/// door(outbound::<A, _>(1));
/// ```
///
/// What leaves is opened through a declaration and nowhere else:
///
/// ```compile_fail
/// use enclavid_boundary::{Boundary, Covert, Exposed};
/// struct A;
/// impl Boundary for A {}
/// let _ = Exposed::<u8, (Covert,), A>::new(1);
/// ```
///
/// The work keeps the value's type:
///
/// ```compile_fail
/// use enclavid_boundary::{Boundary, Covert, Sends, outbound};
/// struct A;
/// impl Boundary for A {}
/// impl Sends<u8> for A { type Open = (Covert,); }
/// let _ = outbound::<A, _>(1u8).vouch_with(Covert::Transformed, |b| Ok::<_, ()>(u16::from(b)));
/// ```
///
/// A builder leaves only as the value it was opened for. The control first:
///
/// ```
/// use enclavid_boundary::{Boundary, Covert, Exposed, Sends, outbound_builder};
/// struct A;
/// impl Boundary for A {}
/// impl Sends<u8> for A { type Open = (Covert,); }
/// let _: Exposed<u8, (), A> = outbound_builder::<A, u8, _>("x")
///     .vouch_with(Covert::Transformed, |s| Ok::<_, ()>(s.len() as u8))
///     .unwrap()
///     .build();
/// ```
///
/// Holding something else, it does not build:
///
/// ```compile_fail
/// use enclavid_boundary::{Boundary, Covert, Sends, outbound_builder};
/// struct A;
/// impl Boundary for A {}
/// impl Sends<u8> for A { type Open = (Covert,); }
/// let _ = outbound_builder::<A, u8, _>("x")
///     .vouch_with(Covert::Transformed, |s| Ok::<_, ()>(s.len()))
///     .unwrap()
///     .build();
/// ```
///
/// Nor with a concern still open, even holding a value of the type:
///
/// ```compile_fail
/// use enclavid_boundary::{Boundary, Covert, Sends, outbound_builder};
/// struct A;
/// impl Boundary for A {}
/// impl Sends<u8> for A { type Open = (Covert,); }
/// let _ = outbound_builder::<A, u8, _>(1u8).build();
/// ```
///
/// A value its declaration answered in full lends its scope to no builder:
///
/// ```compile_fail
/// use enclavid_boundary::{Boundary, Sends, outbound_builder};
/// struct A;
/// impl Boundary for A {}
/// impl Sends<u8> for A { type Open = (); }
/// let _ = outbound_builder::<A, u8, _>("x");
/// ```
///
/// A projection's error comes out open:
///
/// ```compile_fail
/// use enclavid_boundary::{Asserted, Untrusted};
/// let v: Untrusted<u8, (Asserted,)> = Untrusted::new(1);
/// let _: u8 = v.try_map(|b| Err::<(), _>(b)).unwrap_err().into_inner();
/// ```
///
/// A declaration's blocks open only markers of their own direction, and only
/// markers. The control first:
///
/// ```
/// use enclavid_boundary::{Asserted, Covert};
/// use enclavid_boundary_macros::boundary;
/// pub struct Req;
/// pub struct Rep;
/// boundary! {
///     End { observer: Test }
///     in (Asserted,) { #[doc = "test fixture"] Req: Asserted::Bounded }
///     out (Covert,) { #[doc = "test fixture"] Rep: Covert::Bounded }
/// }
/// ```
///
/// ```compile_fail
/// use enclavid_boundary::Covert;
/// use enclavid_boundary_macros::boundary;
/// pub struct Req;
/// boundary! {
///     End { observer: Test }
///     in (Covert,) { #[doc = "test fixture"] Req: Covert::Bounded }
/// }
/// ```
///
/// ```compile_fail
/// use enclavid_boundary::Asserted;
/// use enclavid_boundary_macros::boundary;
/// pub struct Rep;
/// boundary! {
///     End { observer: Test }
///     out (Asserted,) { #[doc = "test fixture"] Rep: Asserted::Bounded }
/// }
/// ```
///
/// ```compile_fail
/// use enclavid_boundary_macros::boundary;
/// pub struct Req;
/// boundary! {
///     End { observer: Test }
///     in (u8,) { Req }
/// }
/// ```
///
/// And a declaration does no work, nor accepts a risk: its answers are argued.
///
/// ```compile_fail
/// use enclavid_boundary::Covert;
/// use enclavid_boundary_macros::boundary;
/// pub struct Rep;
/// boundary! {
///     End { observer: Test }
///     out (Covert,) { #[doc = "test fixture"] Rep: Covert::Transformed }
/// }
/// ```
///
/// ```compile_fail
/// use enclavid_boundary::Covert;
/// use enclavid_boundary_macros::boundary;
/// pub struct Rep;
/// boundary! {
///     End { observer: Test }
///     out (Covert,) { #[doc = "test fixture"] Rep: Covert::AcceptedRisk }
/// }
/// ```
///
/// A contract's every crossing is a type of its own, and `()` under another name
/// is still `()`. The control first:
///
/// ```
/// pub struct Error;
/// pub struct Req;
/// #[enclavid_boundary_macros::protocol]
/// pub trait Contract {
///     async fn op(&self, req: Req) -> Result<Req, Error>;
/// }
/// ```
///
/// ```compile_fail
/// pub struct Error;
/// pub struct Req;
/// pub type Unit = ();
/// #[enclavid_boundary_macros::protocol]
/// pub trait Contract {
///     async fn op(&self, req: Req) -> Result<Unit, Error>;
/// }
/// ```
///
/// An end that calls a contract declares what its doors take and hand back — the
/// end named `B` there — and not what crosses. The control first:
///
/// ```
/// use enclavid_boundary::{AuthN, Exposed, Receives, Untrusted};
/// use enclavid_boundary_macros::boundary;
/// pub struct Error;
/// pub struct Req;
/// pub struct Rep;
/// pub struct Part<B>(std::marker::PhantomData<B>);
/// #[enclavid_boundary_macros::protocol]
/// pub trait Contract {
///     async fn op(&self, req: Req) -> Result<Rep, Error>;
/// }
/// pub struct Leg<B>(std::marker::PhantomData<B>);
/// #[enclavid_boundary_macros::calls(Contract)]
/// impl<B> Leg<B> {
///     pub async fn op(
///         &self,
///         part: Exposed<Part<B>, (), B>,
///     ) -> Result<Untrusted<Rep, <B as Receives<Rep>>::Open, B>, Error> {
///         unimplemented!()
///     }
/// }
/// boundary! {
///     Caller { calls: [Contract], observer: Test }
///     out (AuthN,) { Part<Caller> }
///     in (AuthN,) { Rep, #[doc = "test fixture"] Error: AuthN::Indifferent }
/// }
/// ```
///
/// Declaring what crosses in place of what the door takes does not do:
///
/// ```compile_fail
/// use enclavid_boundary::{AuthN, Exposed, Receives, Untrusted};
/// use enclavid_boundary_macros::boundary;
/// pub struct Error;
/// pub struct Req;
/// pub struct Rep;
/// pub struct Part<B>(std::marker::PhantomData<B>);
/// #[enclavid_boundary_macros::protocol]
/// pub trait Contract {
///     async fn op(&self, req: Req) -> Result<Rep, Error>;
/// }
/// pub struct Leg<B>(std::marker::PhantomData<B>);
/// #[enclavid_boundary_macros::calls(Contract)]
/// impl<B> Leg<B> {
///     pub async fn op(
///         &self,
///         part: Exposed<Part<B>, (), B>,
///     ) -> Result<Untrusted<Rep, <B as Receives<Rep>>::Open, B>, Error> {
///         unimplemented!()
///     }
/// }
/// boundary! {
///     Caller { calls: [Contract], observer: Test }
///     out (AuthN,) { Req }
///     in (AuthN,) { Rep, #[doc = "test fixture"] Error: AuthN::Indifferent }
/// }
/// ```
///
/// A door named for no method of its contract is refused:
///
/// ```compile_fail
/// use enclavid_boundary::{Exposed, Receives, Untrusted};
/// pub struct Error;
/// pub struct Req;
/// pub struct Rep;
/// #[enclavid_boundary_macros::protocol]
/// pub trait Contract {
///     async fn op(&self, req: Req) -> Result<Rep, Error>;
/// }
/// pub struct Leg<B>(std::marker::PhantomData<B>);
/// #[enclavid_boundary_macros::calls(Contract)]
/// impl<B> Leg<B> {
///     pub async fn other(
///         &self,
///         req: Exposed<Req, (), B>,
///     ) -> Result<Untrusted<Rep, <B as Receives<Rep>>::Open, B>, Error> {
///         unimplemented!()
///     }
/// }
/// ```
///
/// A door that builds what crosses from a value of its own says so in its
/// `where`, and the end declares what it builds answered in full. The control
/// first:
///
/// ```
/// use enclavid_boundary::{AuthN, Receives, Sends, Untrusted};
/// use enclavid_boundary_macros::boundary;
/// pub struct Error;
/// pub struct Req;
/// pub struct Rep;
/// pub struct Source;
/// #[enclavid_boundary_macros::protocol]
/// pub trait Contract {
///     async fn op(&self, req: Req) -> Result<Rep, Error>;
/// }
/// pub struct Leg<B>(std::marker::PhantomData<B>);
/// #[enclavid_boundary_macros::calls(Contract)]
/// impl<B> Leg<B> {
///     pub async fn op(
///         &self,
///         source: Source,
///     ) -> Result<Untrusted<Rep, <B as Receives<Rep>>::Open, B>, Error>
///     where
///         B: Sends<Req, Open = ()>,
///     {
///         unimplemented!()
///     }
/// }
/// boundary! {
///     Caller { calls: [Contract], observer: Test }
///     out (AuthN,) { #[doc = "test fixture"] Req: AuthN::Indifferent }
///     in (AuthN,) { Rep, #[doc = "test fixture"] Error: AuthN::Indifferent }
/// }
/// ```
///
/// An end that leaves something open on it does not do:
///
/// ```compile_fail
/// use enclavid_boundary::{AuthN, Receives, Sends, Untrusted};
/// use enclavid_boundary_macros::boundary;
/// pub struct Error;
/// pub struct Req;
/// pub struct Rep;
/// pub struct Source;
/// #[enclavid_boundary_macros::protocol]
/// pub trait Contract {
///     async fn op(&self, req: Req) -> Result<Rep, Error>;
/// }
/// pub struct Leg<B>(std::marker::PhantomData<B>);
/// #[enclavid_boundary_macros::calls(Contract)]
/// impl<B> Leg<B> {
///     pub async fn op(
///         &self,
///         source: Source,
///     ) -> Result<Untrusted<Rep, <B as Receives<Rep>>::Open, B>, Error>
///     where
///         B: Sends<Req, Open = ()>,
///     {
///         unimplemented!()
///     }
/// }
/// boundary! {
///     Caller { calls: [Contract], observer: Test }
///     out (AuthN,) { Req }
///     in (AuthN,) { Rep, #[doc = "test fixture"] Error: AuthN::Indifferent }
/// }
/// ```
///
/// And a method left without a door is refused:
///
/// ```compile_fail
/// use enclavid_boundary::{Exposed, Receives, Untrusted};
/// pub struct Error;
/// pub struct Req;
/// pub struct Rep;
/// #[enclavid_boundary_macros::protocol]
/// pub trait Contract {
///     async fn op(&self, req: Req) -> Result<Rep, Error>;
///     async fn more(&self, req: Req) -> Result<Rep, Error>;
/// }
/// pub struct Leg<B>(std::marker::PhantomData<B>);
/// #[enclavid_boundary_macros::calls(Contract)]
/// impl<B> Leg<B> {
///     pub async fn op(
///         &self,
///         req: Exposed<Req, (), B>,
///     ) -> Result<Untrusted<Rep, <B as Receives<Rep>>::Open, B>, Error> {
///         unimplemented!()
///     }
/// }
/// ```
#[allow(dead_code)]
fn compile_checks() {}

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
    fn answers_in_natural_order() {
        let raw: Untrusted<Meta, (AuthN, AuthZ, Replay)> = Untrusted::new(Meta {
            owner: "alice".into(),
            version: 1,
        });
        let m = raw
            .trust(reason!(AuthN::SelfProduced, "test fixture"))
            .trust_with(AuthZ::Matched, |m: Meta| {
                if m.owner == "alice" {
                    Ok(m)
                } else {
                    Err("wrong owner")
                }
            })
            .unwrap()
            .trust(reason!(Replay::Harmless, "test fixture"))
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
    fn answers_in_any_order() {
        // Same scope, answered in different order — type inference picks the
        // matching position marker each time, and the marker from the kind.
        let raw: Untrusted<u32, (AuthN, AuthZ, Replay)> = Untrusted::new(42);
        let v = raw
            .trust(reason!(Replay::Idempotent, "test fixture"))
            .trust(reason!(AuthN::Indifferent, "test fixture"))
            .trust(reason!(AuthZ::NoPrincipal, "test fixture"))
            .into_inner();
        assert_eq!(v, 42);
    }

    #[test]
    fn work_propagates_its_error() {
        let raw: Untrusted<&'static str, (AuthZ,)> = Untrusted::new("mallory");
        let err = raw
            .trust_with(AuthZ::Matched, |s| {
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
    fn work_may_change_the_type() {
        // Real inbound shape: bytes-on-wire → typed value after AEAD-open +
        // decode, modelled with a string-to-length transform.
        let raw: Untrusted<&'static str, (AuthN,)> = Untrusted::new("hello");
        let len: Untrusted<usize, ()> = raw
            .trust_with(AuthN::Verified, |s| Ok::<_, ()>(s.len()))
            .unwrap();
        assert_eq!(len.into_inner(), 5);
    }

    #[test]
    fn an_accepted_risk_takes_its_concern_off() {
        let raw: Untrusted<u8, (Asserted,)> = Untrusted::new(3);
        let v = raw
            .trust_accept_risk(reason!(Asserted::AcceptedRisk, "test fixture"))
            .into_inner();
        assert_eq!(v, 3);
    }

    #[test]
    fn projections_answer_nothing() {
        let raw: Untrusted<Meta, (Replay,)> = Untrusted::new(Meta {
            owner: "alice".into(),
            version: 7,
        });
        let projected: Untrusted<u32, (Replay,)> = raw.map(|m| m.version);
        let doubled: Untrusted<u32, (Replay,)> =
            projected.try_map(|v| v.checked_mul(2).ok_or(())).unwrap();
        let halves: Result<Untrusted<u32, (Replay,)>, Untrusted<u32, (Replay,)>> =
            doubled.split(|v| if v > 10 { Ok(v) } else { Err(v) });
        let v = halves
            .unwrap()
            .trust(reason!(Replay::Harmless, "test fixture"))
            .into_inner();
        assert_eq!(v, 14);
    }

    #[test]
    fn reason_token_is_zst() {
        assert_eq!(std::mem::size_of::<Reason>(), 0);
        assert_eq!(std::mem::size_of::<Reason<AuthN, Argued>>(), 0);
    }

    #[test]
    fn exposed_answers_in_any_order() {
        let raw: Exposed<i64, (AuthN, AuthZ, Covert), End> = outbound::<End, _>(42);
        let v = raw
            .vouch(reason!(Covert::Bounded, "test fixture"))
            .vouch(reason!(AuthN::SelfProduced, "test fixture"))
            .vouch(reason!(AuthZ::NoSecret, "test fixture"))
            .into_inner();
        assert_eq!(v, 42);
    }

    #[test]
    fn exposed_work_propagates_its_error() {
        let err = outbound::<End, _>(5u32)
            .vouch_with(Covert::Transformed, |v| {
                if v <= 4 { Ok(v) } else { Err("over the frame") }
            })
            .unwrap_err();
        assert_eq!(err, "over the frame");
    }

    #[test]
    fn exposed_takes_an_accepted_risk() {
        let v = outbound::<End, _>(3u32)
            .vouch_accept_risk(reason!(Covert::AcceptedRisk, "test fixture"))
            .into_inner();
        assert_eq!(v, 3);
    }

    /// A projection's error is the sender's as much as its value is, so it comes
    /// out open on the same scope.
    #[test]
    fn a_projection_error_stays_open() {
        let raw: Untrusted<&'static str, (Asserted,)> = Untrusted::new("the peer's own text");
        let err: Untrusted<&'static str, (Asserted,)> = raw.try_map(Err::<u8, _>).unwrap_err();
        let text = err
            .trust_accept_risk(reason!(Asserted::AcceptedRisk, "test fixture"))
            .into_inner();
        assert_eq!(text, "the peer's own text");
    }

    struct End;
    impl Boundary for End {}
    impl Sends<u32> for End {
        type Open = (Covert,);
    }
    impl Sends<i64> for End {
        type Open = (AuthN, AuthZ, Covert);
    }
    impl Sends<u64> for End {
        type Open = (AuthZ, Covert);
    }
    impl Sends<u8> for End {
        type Open = ();
    }
    impl Receives<u16> for End {
        type Open = ();
    }

    /// A builder takes argued answers as they are, and leaves only as the value
    /// the work builds.
    #[test]
    fn a_builder_leaves_as_what_it_builds() {
        let framed: Exposed<u64, (), End> = outbound_builder::<End, u64, _>(7u8)
            .vouch(reason!(AuthZ::NoSecret, "test fixture"))
            .vouch_with(Covert::Transformed, |b| Ok::<_, ()>(u64::from(b) << 8))
            .unwrap()
            .build();
        assert_eq!(framed.into_inner(), 7 << 8);
    }

    /// Each work may turn what a builder holds into something else, and only
    /// the last needs to hold what it builds.
    #[test]
    fn a_builder_takes_work_after_work() {
        let built: Exposed<u64, (), End> = outbound_builder::<End, u64, _>(7u8)
            .vouch_with(Covert::Transformed, |b| Ok::<_, ()>(u16::from(b) << 4))
            .unwrap()
            .vouch_with(AuthZ::NoSecret, |w| Ok::<_, ()>(u64::from(w) << 4))
            .unwrap()
            .build();
        assert_eq!(built.into_inner(), 7 << 8);
    }

    /// At a declared end the work keeps the value's type.
    #[test]
    fn declared_work_keeps_the_type() {
        let checked: Exposed<u32, (), End> = outbound::<End, _>(9u32)
            .vouch_with(Covert::Transformed, |v| Ok::<_, ()>(v.rotate_left(8)))
            .unwrap();
        assert_eq!(checked.into_inner(), 9u32.rotate_left(8));
    }

    /// A type that crosses only where a door builds it, or takes it apart, is
    /// one the calling end never holds: declaring it is found out, and declaring
    /// the door's parts — its own end named as `Self` — is not.
    #[test]
    fn what_only_a_door_holds_is_unheld() {
        use declaration::{Crossing, Direction, Door, End, Method, Protocol};
        const fn crossing(direction: Direction, ty: &'static str) -> Crossing {
            Crossing {
                direction,
                ty,
                opens: &[],
                answers: &[],
                left: &[],
            }
        }
        const CALLS: &[Protocol] = &[Protocol {
            name: "Contract",
            methods: &[
                Method {
                    name: "built",
                    args: &["Name", "Request"],
                    reply: "Response",
                    error: "Error",
                    door: Some(Door {
                        sends: &["Name", "Part<Self>"],
                        receives: &["Slot"],
                    }),
                },
                Method {
                    name: "plain",
                    args: &["Name"],
                    reply: "Done",
                    error: "Error",
                    door: None,
                },
            ],
        }];
        const SOUND: &[Crossing] = &[
            crossing(Direction::Out, "Name"),
            crossing(Direction::Out, "Part<Caller>"),
            crossing(Direction::In, "Slot"),
            crossing(Direction::In, "Done"),
            crossing(Direction::In, "Error"),
        ];
        const WITH_THE_WIRE: &[Crossing] = &[
            crossing(Direction::Out, "Name"),
            crossing(Direction::Out, "Request"),
            crossing(Direction::In, "crate::Response"),
            crossing(Direction::In, "::wire::Done"),
        ];
        let caller = |crossings| End {
            name: "Caller",
            doc: "",
            observer: "",
            calls: CALLS,
            serves: &[],
            crossings,
        };
        assert!(caller(SOUND).unheld().is_empty());
        assert_eq!(
            caller(WITH_THE_WIRE).unheld(),
            ["Request", "crate::Response"]
        );
    }

    /// A declaration decides the scope a value starts with at its end, and where
    /// it answered everything, the value starts answered.
    #[test]
    fn an_end_opens_what_its_declaration_left() {
        let open: Exposed<u32, (Covert,), End> = outbound::<End, _>(5);
        assert_eq!(
            open.vouch(reason!(Covert::Bounded, "test fixture"))
                .into_inner(),
            5
        );
        let answered: Exposed<u8, (), End> = outbound::<End, _>(6);
        assert_eq!(answered.into_inner(), 6);
        let arrived: Untrusted<u16, (), End> = inbound::<End, _>(7);
        assert_eq!(arrived.into_inner(), 7);
        // A builder of a `u32` opens what the `u32` does, and becomes one in the work.
        let framed: Exposed<u32, (), End> = outbound_builder::<End, u32, _>((2u16, 3u16))
            .vouch_with(Covert::Transformed, |(a, b)| {
                Ok::<_, ()>(u32::from(a) * u32::from(b))
            })
            .unwrap()
            .build();
        assert_eq!(framed.into_inner(), 6);
    }
}
