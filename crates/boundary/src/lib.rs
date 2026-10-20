//! Type-level wrappers for values crossing a trust boundary. Two dual
//! wrappers, one per direction, and the vocabulary they are written in.
//!
//! It has lived in two places. On its own as `enclavid-untrusted`, then folded
//! into `hatch-client` so the definitions sat beside the facades that construct
//! them. Out again, because the TEE grew a second way to speak: the serial port
//! that `safe-logger` writes to. Two channels with nothing in common but this
//! vocabulary, so the vocabulary belongs below both. The facades stay with the
//! clients that cross, and `safe-logger`, which opens its channel before
//! anything else in a role exists, depends on the vocabulary without depending on
//! a wire client.
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
//! left. A value whose end nothing declares carries [`Undeclared`], and its scope
//! is whatever its mint opened.
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
// Open — a scope with something still to answer.
// =====================================================================

mod sealed {
    pub trait Sealed {}
}

/// A scope with at least one concern still open.
///
/// Implemented for every non-empty marker tuple and NEVER for `()`, which is the
/// whole point. `Untrusted<T, ()>` and `Exposed<T, ()>` mean "every concern was
/// answered", and both release their inner value on that basis — so a constructor
/// able to produce one directly would let a caller assert the answer without ever
/// having given it. A door that demands `Exposed<_, ()>` is only worth something
/// if `()` cannot be conjured, and this bound is what makes that true:
/// `Exposed::new(req)` where `Exposed<Req, ()>` is wanted stops compiling.
///
/// It restricts WHAT a mint may produce, not WHO may mint. Whoever calls a
/// constructor still chooses the scope, which is right — the concerns a crossing
/// raises are the caller's to name — but they cannot choose to name none.
/// DECLARING a fully-answered wrapper is a type error, in both directions — `new`
/// cannot mint at `()`, so an empty scope is somewhere you arrive:
///
/// ```compile_fail
/// use enclavid_boundary::Exposed;
/// let _: Exposed<u32, ()> = Exposed::new(7);
/// ```
///
/// ```compile_fail
/// use enclavid_boundary::Untrusted;
/// let _: Untrusted<u32, ()> = Untrusted::new(7);
/// ```
///
/// And a non-empty scope still constructs, so the bound narrows what a mint may
/// produce without restricting who may mint:
///
/// ```
/// use enclavid_boundary::{Covert, Exposed};
/// let _: Exposed<u32, (Covert,)> = Exposed::new(7);
/// ```
///
/// The one other way to `()` without a peel is a declaration: [`outbound`] and
/// [`inbound`] give a value the scope its end's declaration left open, and where
/// the declaration answered everything about that type, that is `()`. The answers
/// are written there, once, in the place a reviewer reads them.
///
/// **At a declared end, a receipt is for the type it was answered for.** `new`
/// exists only at [`Undeclared`], so a declared end mints through its declaration
/// alone. The work in `vouch_with` keeps the value's type there, and a value built
/// in the work leaves through [`Parts`], whose one way out builds the type whose
/// declaration it was opened under. What carries a scope onto a different value —
/// [`Exposed::map`], the `Vec` transpose, `distribute` — exists only at
/// [`Undeclared`] as well.
///
/// **What this bound does NOT give you** at an undeclared end, and the facades
/// should not be read as if it did. Two routes reach `()` without a peel there,
/// and both are deliberate features that happen to compose badly:
///
///   * the `Vec` transpose joins a batch at its elements' scope, and an EMPTY batch
///     satisfies "every element addressed `S`" vacuously, for any `S`;
///   * [`Exposed::map`] carries a scope onto a different value.
///
/// Chained, they mint `Exposed<Anything, ()>` from nothing, and a third soft spot
/// sits beside them: `((),)` is a non-empty tuple, so it is `Open`, and its single
/// "marker" is the unit type — nothing prevents a scope that asks nothing.
///
/// None of that is an argument for removing the bound, and none of it is an
/// argument for chasing the rest. What it settles is what the bound is FOR. The
/// accident it catches is the quiet one: at a call site whose signature wants
/// `Exposed<_, ()>`, with a bare value in hand, `Exposed::new(v)` is the natural
/// thing to type and would otherwise compile in silence, skipping the mint with no
/// signal at all. The routes above are the loud ones — an empty-batch transpose or
/// a discarding `map` is conspicuous in a diff in a way one constructor call is not.
///
/// So: a scope of `()` is evidence that the mint was walked, not proof that it was.
/// The guard lives in the same repository as what it guards, which is true of every
/// private field and every `pub(crate)` here; it stops a wrong turn, not an author
/// who means it.
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

/// The end of a crossing nothing has declared. Its scope is whatever the mint
/// opened, and no declaration answers any of it.
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
/// that answers it — the parts a request is framed from, say. The parts open what
/// `B` left open on a `W`, and the one way out of [`Parts`] is work that builds a
/// `W`, so the receipt is for a `W` and for nothing else.
///
/// What `B` left open on `W` must not be empty: a `W` its declaration answered in
/// full has no work to be built in, and is opened with [`outbound`] once it exists.
pub fn outbound_as<B, W, T>(value: T) -> Parts<T, W, B::Open, B>
where
    B: Sends<W>,
    B::Open: Open,
{
    Parts {
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
    /// `pub` and `doc(hidden)`. It has to be public — the facades that call it
    /// live in other crates, and this one is a dependency-free leaf, so there is
    /// no `pub(crate)` that could span them. Hidden because nothing outside those
    /// facades should ever find it: the guard here is against a wrong turn, not
    /// against someone with commit access, and the named entry points are what a
    /// reviewer greps.
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
/// `into_inner`. `B` is the end it leaves.
pub struct Exposed<T, S = (), B = Undeclared> {
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
}

/// At an end nothing declares, the value is whatever its mint made it, and work
/// may turn it into what crosses.
impl<T, S> Exposed<T, S, Undeclared> {
    /// Wrap a value being released with an explicit initial scope. The caller
    /// picks `S` to match the concerns genuinely open at the construction site.
    ///
    /// `S: Open`, so the scope cannot be `()`. That is what makes a door demanding
    /// `Exposed<_, ()>` mean anything: the only ways to that type are answering
    /// every concern the mint opened, or a declaration that answered them, so the
    /// receipt records answers actually given rather than an assertion that none
    /// were needed. And only at [`Undeclared`]: a declared end's scope is its
    /// declaration's, so a value leaving there is opened by [`outbound`].
    ///
    /// `pub` and `doc(hidden)`, for the reason given on `Untrusted::new`.
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

    /// Answer concern `M` with the work in `work`: AEAD-seal turns plaintext into
    /// ciphertext; `Padded::seal` makes an encoding one constant size; a predicate
    /// that only checks returns its input.
    ///
    /// Symmetric to [`Untrusted::trust_with`]: inbound work verifies, outbound
    /// work establishes. Both close their concern by performing the
    /// transformation, not by attesting to it.
    ///
    /// On success the scope shrinks by `M`; on failure the wrapper is dropped.
    pub fn vouch_with<M, I, K, U, F, E>(
        self,
        _kind: Kind<M, K>,
        work: F,
    ) -> Result<Exposed<U, S::Rest, Undeclared>, E>
    where
        S: Remove<M, I>,
        K: Backs,
        F: FnOnce(T) -> Result<U, E>,
    {
        let value = work(self.value)?;
        Ok(Exposed {
            value,
            _marker: PhantomData,
        })
    }

    /// Project the inner value while preserving the scope. Use when you need to
    /// transform `T` to `U` (e.g., wrap sealed bytes into a typed `Op`) without
    /// answering any concern.
    ///
    /// It carries the scope onto a DIFFERENT value, and at `S = ()` that means
    /// carrying a completed receipt. Sound where the closure embeds its input, which
    /// is every use here; a closure that discarded it would leave a receipt
    /// describing something no longer present. Nothing in the type system separates
    /// the two — see [`Open`] for what that costs and what it does not.
    pub fn map<U, F>(self, f: F) -> Exposed<U, S, Undeclared>
    where
        F: FnOnce(T) -> U,
    {
        Exposed {
            value: f(self.value),
            _marker: PhantomData,
        }
    }
}

/// At a declared end, a receipt is for the type its declaration was read for, so
/// the work here keeps the value's type. Work that builds the value that crosses
/// starts from [`Parts`] ([`outbound_as`]).
impl<T, S, B: Boundary> Exposed<T, S, B> {
    /// Answer concern `M` with the work in `work`, which checks the value or
    /// rewrites it in place — a scrub, say — and gives back the same type.
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
// Parts<T, W, S, B> — what a `W` is built from, on its way out of `B`.
// =====================================================================

/// The parts a `W` is built from, open on what end `B`'s declaration left open
/// on a `W` ([`outbound_as`]). Argued answers come off as they do on
/// [`Exposed`]; the one way out is [`vouch_with`](Self::vouch_with), the work
/// that builds the `W`.
pub struct Parts<T, W, S, B> {
    value: T,
    /// What the work builds the parts into.
    _builds: PhantomData<fn() -> W>,
    _marker: PhantomData<fn() -> (S, B)>,
}

impl<T, W, S, B> Parts<T, W, S, B> {
    /// Answer concern `M` with an argued kind, as [`Exposed::vouch`] does.
    pub fn vouch<M, I>(self, _reason: Reason<M, Argued>) -> Parts<T, W, S::Rest, B>
    where
        S: Remove<M, I>,
    {
        Parts {
            value: self.value,
            _builds: PhantomData,
            _marker: PhantomData,
        }
    }

    /// Take concern `M` off as a standing risk, as [`Exposed::vouch_accept_risk`]
    /// does.
    pub fn vouch_accept_risk<M, I>(self, _reason: Reason<M, Risk>) -> Parts<T, W, S::Rest, B>
    where
        S: Remove<M, I>,
    {
        Parts {
            value: self.value,
            _builds: PhantomData,
            _marker: PhantomData,
        }
    }

    /// Answer concern `M` with the work that builds the `W` from the parts — the
    /// only way a `W` leaves from them. The work's codomain is the `W` the parts
    /// were opened as, so what this releases is that and nothing else.
    pub fn vouch_with<M, I, K, F, E>(
        self,
        _kind: Kind<M, K>,
        work: F,
    ) -> Result<Exposed<W, S::Rest, B>, E>
    where
        S: Remove<M, I>,
        K: Backs,
        F: FnOnce(T) -> Result<W, E>,
    {
        let value = work(self.value)?;
        Ok(Exposed {
            value,
            _marker: PhantomData,
        })
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
/// of `into_inner`-ing each part and then rubber-stamping the envelope.
/// Pair with [`Exposed::map`] to fold in non-secret envelope fields (a
/// version counter, …) at the same preserved scope.
///
/// Only at [`Undeclared`]: a `Vec<T>` is not a type a declaration answered for
/// because it answered for `T`.
impl<T, S> From<Vec<Exposed<T, S, Undeclared>>> for Exposed<Vec<T>, S, Undeclared> {
    fn from(items: Vec<Exposed<T, S, Undeclared>>) -> Self {
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
/// a tuple-level argued answer any more honest than it was. Bundle into a
/// tuple-then-answer ONLY when one reason genuinely covers every component
/// (e.g. same-provenance scalars). For heterogeneous members that close a
/// concern differently (per-field AEAD vs sealing to a recipient vs
/// plaintext), keep them as separate per-member exposures instead.
///
/// Only at [`Undeclared`], for the reason the transpose is.
macro_rules! impl_exposed_distribute {
    ($($T:ident),+) => {
        impl<$($T,)+ S> Exposed<($($T,)+), S, Undeclared> {
            #[allow(non_snake_case)]
            pub fn distribute(self) -> ($(Exposed<$T, S, Undeclared>,)+) {
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
        pub calls: &'static [&'static str],
        /// The protocols this end serves.
        pub serves: &'static [&'static str],
        pub crossings: &'static [Crossing],
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
/// A declared end mints through its declaration and nowhere else:
///
/// ```compile_fail
/// use enclavid_boundary::{Boundary, Covert, Exposed};
/// struct A;
/// impl Boundary for A {}
/// let _ = Exposed::<u8, (Covert,), A>::new(1);
/// ```
///
/// At a declared end, the work keeps the value's type:
///
/// ```compile_fail
/// use enclavid_boundary::{Boundary, Covert, Sends, outbound};
/// struct A;
/// impl Boundary for A {}
/// impl Sends<u8> for A { type Open = (Covert,); }
/// let _ = outbound::<A, _>(1u8).vouch_with(Covert::Transformed, |b| Ok::<_, ()>(u16::from(b)));
/// ```
///
/// Parts leave only as the value they were opened as:
///
/// ```compile_fail
/// use enclavid_boundary::{Boundary, Covert, Sends, outbound_as};
/// struct A;
/// impl Boundary for A {}
/// impl Sends<u8> for A { type Open = (Covert,); }
/// let _ = outbound_as::<A, u8, _>("x").vouch_with(Covert::Transformed, |s| Ok::<_, ()>(s.len()));
/// ```
///
/// A value its declaration answered in full lends its scope to no parts:
///
/// ```compile_fail
/// use enclavid_boundary::{Boundary, Sends, outbound_as};
/// struct A;
/// impl Boundary for A {}
/// impl Sends<u8> for A { type Open = (); }
/// let _ = outbound_as::<A, u8, _>("x");
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
        let raw: Exposed<u32, (AuthN, AuthZ, Covert)> = Exposed::new(42);
        let v = raw
            .vouch(reason!(Covert::Bounded, "test fixture"))
            .vouch(reason!(AuthN::SelfProduced, "test fixture"))
            .vouch(reason!(AuthZ::NoSecret, "test fixture"))
            .into_inner();
        assert_eq!(v, 42);
    }

    #[test]
    fn exposed_work_propagates_its_error() {
        let raw: Exposed<&'static str, (Covert,)> = Exposed::new("past its frame");
        let err = raw
            .vouch_with(Covert::Transformed, |s| {
                if s.len() <= 4 {
                    Ok(s)
                } else {
                    Err("over the frame")
                }
            })
            .unwrap_err();
        assert_eq!(err, "over the frame");
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

    #[test]
    fn exposed_work_may_change_the_type() {
        // Real outbound shape: plaintext value → ciphertext bytes after AEAD-seal.
        let raw: Exposed<&'static str, (Covert,)> = Exposed::new("hello");
        let bytes: Exposed<Vec<u8>, ()> = raw
            .vouch_with(Covert::Transformed, |s| Ok::<_, ()>(s.as_bytes().to_vec()))
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
            .vouch(reason!(AuthN::SelfProduced, "test fixture"))
            .vouch_accept_risk(reason!(Covert::AcceptedRisk, "test fixture"))
            .into_inner();
        assert_eq!(v, 7);
    }

    struct End;
    impl Boundary for End {}
    impl Sends<u32> for End {
        type Open = (Covert,);
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

    /// Parts take argued answers as they are, and leave only as the value the work
    /// builds from them.
    #[test]
    fn parts_leave_as_what_they_build() {
        let framed: Exposed<u64, (), End> = outbound_as::<End, u64, _>(7u8)
            .vouch(reason!(AuthZ::NoSecret, "test fixture"))
            .vouch_with(Covert::Transformed, |b| Ok::<_, ()>(u64::from(b) << 8))
            .unwrap();
        assert_eq!(framed.into_inner(), 7 << 8);
    }

    /// At a declared end the work keeps the value's type.
    #[test]
    fn declared_work_keeps_the_type() {
        let checked: Exposed<u32, (), End> = outbound::<End, _>(9u32)
            .vouch_with(Covert::Transformed, |v| Ok::<_, ()>(v.rotate_left(8)))
            .unwrap();
        assert_eq!(checked.into_inner(), 9u32.rotate_left(8));
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
        // The parts of a `u32` open what the `u32` does, and become one in the work.
        let framed: Exposed<u32, (), End> = outbound_as::<End, u32, _>((2u16, 3u16))
            .vouch_with(Covert::Transformed, |(a, b)| {
                Ok::<_, ()>(u32::from(a) * u32::from(b))
            })
            .unwrap();
        assert_eq!(framed.into_inner(), 6);
    }
}
