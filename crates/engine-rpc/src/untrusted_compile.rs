//! The compile contract as its SERVER sees it: arguments wrapped in the scope the
//! serving role declares.
//!
//! The mirror of [`crate::untrusted`] on the other leg, and the reason it exists is
//! sharper here. api pins the workers' measurements, so on api's side every concern
//! is about a peer it has authenticated. The leaves cannot pin back — api's
//! measurement is a function of theirs, leaves first, api last, no cycle — so they
//! run `AcceptAny`, and from this seat:
//!
//! ```text
//! trust_unchecked::<AuthN>(reason!("RA-TLS against a pinned measurement"))
//!     api-side    → TRUE
//!     worker-side → FALSE
//! ```
//!
//! `AcceptAny` is not an absence of attestation — the quote is verified whole, and
//! the caller is a genuine SNP guest on this part with the quote bound to the very
//! TLS key in front of it. What is missing is WHICH image. So a worker's inbound
//! `AuthN` is genuinely open, and open in a way api's never is.
//!
//! This is not the thing `docs/engine-boundary.md` rules out. That rules out a
//! worker writing `trust::<Asserted>` — a claim about the peer's own word, which the
//! peer cannot make about itself. A serving role naming what IT does not know about
//! ITS caller is a second, independent party asking its own question.
//!
//! The scope is an associated type so the answer is given once per role, not once
//! per call: what a compile-worker does not know about its caller does not vary
//! between compiles.

use std::future::Future;

use enclavid_boundary::{Open, Untrusted};

use crate::bundle::CompiledBundle;
use crate::compile::{CompileError, CompileRequest, CompilerService};

/// The compile surface as its server sees it. Implement this and hand it to
/// [`serve_compiler`](crate::serve_compiler), which is the only way to serve these
/// calls at all — the raw server type is not exported.
///
/// Futures are spelled out with an explicit `+ Send` rather than written as
/// `async fn`: remoc serves these on a task pool and needs the bound, which a plain
/// `async fn` in a trait does not promise. Implementors still write `async fn` — the
/// bound is satisfied, not restated.
pub trait CompilerServiceUntrusted {
    /// How this implementor judges what arrives on this hop. Named once, here.
    ///
    /// `Open`, so it cannot be `()`. An implementor that named the empty scope would
    /// be handed values with nothing left to answer about them, and the view would
    /// wrap, compile, and mean nothing.
    type Scope: Open;

    /// Fuse, compile, and parse the embedded sections. See
    /// [`CompilerService::compile`].
    fn compile(
        &self,
        req: Untrusted<CompileRequest, Self::Scope>,
    ) -> impl Future<Output = Result<CompiledBundle, CompileError>> + Send;
}

/// A shared service is still one: the supervisor is `Arc`-held because its pool and
/// its configuration outlive any one connection, and that is a property of how the
/// role is assembled rather than of what it judges.
impl<T> CompilerServiceUntrusted for std::sync::Arc<T>
where
    T: CompilerServiceUntrusted + Send + Sync + 'static,
{
    type Scope = T::Scope;

    fn compile(
        &self,
        req: Untrusted<CompileRequest, Self::Scope>,
    ) -> impl Future<Output = Result<CompiledBundle, CompileError>> + Send {
        (**self).compile(req)
    }
}

/// Serves a [`CompilerServiceUntrusted`] as a [`CompilerService`], wrapping the
/// argument on the way in.
///
/// `pub(crate)` because no caller should have to reach for it: the door applies it,
/// and the raw server type is not exported, so there is no unwrapped path to pick
/// instead.
pub(crate) struct Judging<T>(pub T);

impl<T> CompilerService for Judging<T>
where
    T: CompilerServiceUntrusted + Send + Sync + 'static,
    T::Scope: Send,
{
    async fn compile(&self, req: CompileRequest) -> Result<CompiledBundle, CompileError> {
        self.0.compile(Untrusted::new(req)).await
    }
}
