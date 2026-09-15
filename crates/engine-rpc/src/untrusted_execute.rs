//! The execute contract as each SERVER sees it: arguments wrapped in the scope the
//! serving role declares.
//!
//! Both ends of this hop serve something. api serves the callbacks the keyless
//! worker drives mid-round; the worker serves the round itself. So there are two
//! views here, not one, and they are not symmetric — api has pinned the peer it is
//! judging and the worker has not.
//!
//! The raw traits in [`crate::execute`] stay exactly as they are, because they are
//! what remoc derived the wire form from. Beside each sits a trait whose arguments
//! arrive as [`Untrusted`], and [`Untrusting`] turns an implementation of the
//! second back into one of the first.
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

use enclavid_boundary::{Exposed, Open, Untrusted};
use hatch_client::SessionState;
use remoc::codec::Ciborium;

use crate::adapter::Untrusting;
use crate::bundle::CompiledBundle;
use crate::execute::{
    CallbackError, CallbackService, CallbackServiceClient, ExecError, ExecutorService, RunOutcome,
    RunReply, RunRequest,
};
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
    ///
    /// The REPLY is a release, and the only one on this leg that is not framed: it
    /// is the applicant's own plaintext, and its length is chosen by the policy —
    /// by which blob it asks to rehydrate. So the implementor answers for it like
    /// any other crossing, and `Exposed<_, ()>` is what the door will take.
    fn media_load(
        &self,
        hash: Untrusted<[u8; 32], Self::Scope>,
    ) -> impl Future<Output = Result<Exposed<Option<Vec<u8>>, ()>, CallbackError>> + Send;

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

/// The execute surface as its SERVER sees it — the worker's own seat.
///
/// The mirror of the raw `ExecutorService`, and the reason it exists is sharper on this
/// side than on api's. api pins the worker's measurement, so every concern api
/// names is about a peer it has authenticated. The worker cannot pin back — api's
/// measurement is a function of the leaves', leaves first, api last, no cycle — so
/// it runs `AcceptAny` and its caller is a genuine SNP guest and not identifiably
/// api. What that leaves open is not a formality: an entry filed under a key the
/// caller chose is served to whoever asks for that key next.
///
/// Implement this and hand it to [`serve_executor`](crate::serve_executor), which
/// is the only way to serve these calls at all — the raw server type is not
/// exported.
///
/// Futures are spelled out with an explicit `+ Send` rather than written as
/// `async fn`: remoc serves these on a task pool and needs the bound, which a
/// plain `async fn` in a trait does not promise. Implementors still write
/// `async fn` — the bound is satisfied, not restated.
pub trait ExecutorServiceUntrusted {
    /// How this implementor judges what arrives on this leg. Named once, here —
    /// what a worker does not know about its caller does not vary between rounds.
    ///
    /// `Open`, so it cannot be `()`.
    type Scope: Open;

    /// The L1-cache path. See the raw `ExecutorService::run`.
    ///
    /// `callbacks` stays bare, and deliberately. It is a CAPABILITY, not a value:
    /// this side cannot inspect where it points, and no discharge about it would
    /// be about anything.
    ///
    /// What bounds it is not disposability — the process that holds this client is
    /// the long-lived supervisor, not the per-round child. It is that the holder is
    /// KEYLESS, that the client's reach ends with the connection it arrived on, and
    /// that the untrusted wasm which might want it never touches it: a child gets a
    /// narrowed client pointing at the supervisor's own relay.
    ///
    /// The RETURN is `Exposed<_, ()>`, so this end answers for what it releases the
    /// same way the calling end answers for what it sends. It is not symmetry for
    /// its own sake: the reply crosses the hop a host process splices, its shape is
    /// this role's to choose, and the recipient is a peer this role cannot identify.
    fn run(
        &self,
        req: Untrusted<RunRequest, Self::Scope>,
        callbacks: CallbackServiceClient<Ciborium>,
    ) -> impl Future<Output = Result<Exposed<RunOutcome, ()>, ExecError>> + Send;

    /// The post-miss path. See the raw `ExecutorService::run_with_bundle`.
    ///
    /// The bundle is wrapped SEPARATELY from the request, because it is the one
    /// value on this hop for which no discharge kind fits and that has to be
    /// written rather than absorbed into a sentence about the round.
    fn run_with_bundle(
        &self,
        req: Untrusted<RunRequest, Self::Scope>,
        bundle: Untrusted<CompiledBundle, Self::Scope>,
        callbacks: CallbackServiceClient<Ciborium>,
    ) -> impl Future<Output = Result<Exposed<RunReply, ()>, ExecError>> + Send;
}

/// A shared service is still one: the worker's L1 and child pool outlive any one
/// connection, which is a property of how the role is assembled rather than of
/// what it judges.
impl<T> ExecutorServiceUntrusted for std::sync::Arc<T>
where
    T: ExecutorServiceUntrusted + Send + Sync + 'static,
{
    type Scope = T::Scope;

    fn run(
        &self,
        req: Untrusted<RunRequest, Self::Scope>,
        callbacks: CallbackServiceClient<Ciborium>,
    ) -> impl Future<Output = Result<Exposed<RunOutcome, ()>, ExecError>> + Send {
        (**self).run(req, callbacks)
    }

    fn run_with_bundle(
        &self,
        req: Untrusted<RunRequest, Self::Scope>,
        bundle: Untrusted<CompiledBundle, Self::Scope>,
        callbacks: CallbackServiceClient<Ciborium>,
    ) -> impl Future<Output = Result<Exposed<RunReply, ()>, ExecError>> + Send {
        (**self).run_with_bundle(req, bundle, callbacks)
    }
}

impl<T> CallbackService for Untrusting<T>
where
    T: CallbackServiceUntrusted + Send + Sync + 'static,
    T::Scope: Send,
{
    async fn media_load(&self, hash: [u8; 32]) -> Result<Option<Vec<u8>>, CallbackError> {
        self.0
            .media_load(Untrusted::new(hash))
            .await
            .map(Exposed::into_inner)
    }

    async fn session_change(&self, state: Padded<SessionState>) -> Result<(), CallbackError> {
        self.0.session_change(Untrusted::new(state)).await
    }
}

impl<T> ExecutorService for Untrusting<T>
where
    T: ExecutorServiceUntrusted + Send + Sync + 'static,
    T::Scope: Send,
{
    async fn run(
        &self,
        req: RunRequest,
        callbacks: CallbackServiceClient<Ciborium>,
    ) -> Result<RunOutcome, ExecError> {
        self.0
            .run(Untrusted::new(req), callbacks)
            .await
            .map(Exposed::into_inner)
    }

    async fn run_with_bundle(
        &self,
        req: RunRequest,
        bundle: CompiledBundle,
        callbacks: CallbackServiceClient<Ciborium>,
    ) -> Result<RunReply, ExecError> {
        self.0
            .run_with_bundle(Untrusted::new(req), Untrusted::new(bundle), callbacks)
            .await
            .map(Exposed::into_inner)
    }
}
