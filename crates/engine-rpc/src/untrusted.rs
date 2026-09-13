//! A second view of the execute contract, for a consumer that does not take the
//! peer's word for what it sends.
//!
//! The raw traits in [`crate::execute`] stay exactly as they are, and remain the
//! default. This module adds, beside each of them, a trait whose arguments arrive
//! as [`Untrusted`] — and an adapter that turns an implementation of the second
//! back into an implementation of the first, so remoc still sees the contract it
//! generated from.
//!
//! ## The scope is the consumer's to name
//!
//! `Scope` is an associated type rather than a parameter, so an implementor names
//! it once per leg: *this is how I judge what arrives here*. That is the right
//! shape, because a concern scope is not a property of the bytes. The same
//! `SessionState` carries a different one depending on who produced it — the
//! execution-worker, which runs adversary-authored wasm, or a peer that does not.
//! Two consumers of this same contract may legitimately disagree, and each is
//! right about its own position.
//!
//! (It also has to be an associated type: a free parameter on the adapter impl is
//! unconstrained by the self type, which is E0207.)
//!
//! ## What it buys over wrapping at the call site
//!
//! The wrapping is not something a consumer remembers to do. There is no bare
//! value in the signature to forget about, and a method added to the raw trait
//! breaks this one too rather than quietly arriving unwrapped.

use std::future::Future;

use enclavid_boundary::{Open, Untrusted};
use hatch_client::SessionState;

use crate::execute::{CallbackError, CallbackService};
use crate::padded::Padded;

/// The callback surface as its SERVER sees it: everything the caller pushed in,
/// wrapped in the scope this implementor declares.
///
/// The mirror of [`CallbackService`]; implement this and hand it to
/// [`ExecutorLeg::run`](crate::ExecutorLeg::run), which is the only way to serve
/// these callbacks at all.
/// Futures are spelled out with an explicit `+ Send` rather than written as
/// `async fn`: remoc serves these on a task pool and needs the bound, which a
/// plain `async fn` in a trait does not promise. Implementors still write
/// `async fn` — the bound is satisfied, not restated.
pub trait CallbackServiceUntrusted {
    /// How this implementor judges what arrives on this leg. Named once, here.
    ///
    /// `Open`, so it cannot be `()`. An implementor that named the empty scope
    /// would be handed values with nothing left to answer about them — the view
    /// would compile, wrap, and mean nothing. Naming a concern is the whole
    /// undertaking, so the trait requires at least one.
    type Scope: Open;

    /// Rehydrate a stored blob by content hash. See
    /// [`CallbackService::media_load`].
    fn media_load(
        &self,
        hash: Untrusted<[u8; 32], Self::Scope>,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, CallbackError>> + Send;

    /// Seal + persist the post-round session state. See
    /// [`CallbackService::session_change`].
    ///
    /// The frame stays on the inside of the wrapper rather than being opened
    /// here, because the two answer different questions: [`Padded`] says the
    /// length told the host nothing, the scope says whose word the CONTENT is.
    /// Closing one says nothing about the other.
    fn session_change(
        &self,
        state: Untrusted<Padded<SessionState>, Self::Scope>,
    ) -> impl Future<Output = Result<(), CallbackError>> + Send;
}

/// Serves a [`CallbackServiceUntrusted`] as a [`CallbackService`], wrapping each
/// argument on the way in.
///
/// This is the only place the wrapping happens, and it is mechanical: the
/// judgement lives in the implementor's `Scope` and in how it discharges, not
/// here.
///
/// `pub(crate)` because no caller should ever have to reach for it: the door in
/// `leg` takes the untrusted view and applies this itself, and the raw server
/// type is not re-exported, so there is no unwrapped path to choose instead.
pub(crate) struct Untrusting<T>(pub T);

impl<T> CallbackService for Untrusting<T>
where
    T: CallbackServiceUntrusted + Send + Sync + 'static,
    T::Scope: Send,
{
    async fn media_load(&self, hash: [u8; 32]) -> Result<Option<Vec<u8>>, CallbackError> {
        self.0.media_load(Untrusted::new(hash)).await
    }

    async fn session_change(&self, state: Padded<SessionState>) -> Result<(), CallbackError> {
        self.0.session_change(Untrusted::new(state)).await
    }
}
