//! The execute hop, owned end to end.
//!
//! `hatch-client` is legible because two things hold together. One named mint
//! gives a value its full concern set, and ONE function — `pub(crate)` in a crate
//! its callers are outside of — is the only way bytes reach the socket. The second
//! is what makes the first more than a habit: you may forget to mint, but you
//! cannot route around the door.
//!
//! The execute hop had neither. api dialled, received the generated
//! `ExecutorServiceClient`, and called it. Nothing stood between a value and the
//! wire, so a wrapper api applied on its own way out was api reassuring itself
//! about a crossing it owned both ends of — ritual, not a boundary.
//!
//! This module is the missing half. The generated client is no longer re-exported,
//! so no crate outside this one can NAME one — and the only shape left to reach for
//! is the door, whose methods say what must already be closed.
//!
//! Nameability, not containment, and the difference is worth stating because the
//! stronger claim is tempting. `#[remoc::rtc::remote]` derives the wire form from a
//! trait DECLARATION, and every type either contract needs is exported, so a
//! fifteen-line redeclaration in another crate produces a bit-identical client and
//! server. What the wall buys is that the raw path cannot be taken by ACCIDENT:
//! there is no unwrapped shape sitting in an import list for a maintainer to pick up
//! by mistake. A reviewer enumerating what speaks this contract should grep the
//! trait's own name, not assume the door is the only caller.
//!
//! ## What stays with the caller
//!
//! Everything about WHO. [`connect_executor`] takes a byte stream that is already
//! attested, and [`serve_executor`] the same: the dial, the TLS, the measurement
//! pins and what a refusal means stay with the role that decides them. This crate
//! owns what may cross a hop, never who is on the far end of it — which is why it
//! takes on no transport and no attestation dependency, and why the pins do not
//! move.
//!
//! ## The compile hop
//!
//! It has no door YET, and the reason it long had none has gone: the compile-worker
//! used to drive its own child over this same `CompilerService`, so its client could
//! not be withheld from the crate's surface without walling off a hop inside one
//! CVM. That seam now lives with the role that owns both its ends
//! (`engine_compiler::CompileChildService`), and `CompilerServiceClient` is
//! api-facing only.

use std::sync::Arc;

use remoc::codec::Ciborium;
use remoc::rtc::ServerShared;
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(feature = "execute")]
use crate::execute::{
    ExecutorService, ExecutorServiceClient, ExecutorServiceServerShared, RunOutcome,
};

/// Concurrent callback invocations one run's server handles. `media_load` /
/// `session_change` are serialized by the round in practice (one round at a
/// time), so a small pool is ample.
#[cfg(feature = "execute")]
const CALLBACK_CONCURRENCY: usize = 4;

/// What can go wrong bringing the hop up, once the stream is already attested.
///
/// Deliberately narrow and dependency-free: the caller owns a richer vocabulary
/// for the dial (which peer, which measurement, what it presented), and folding
/// these four into it is the caller's job, not this crate's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegError {
    /// remoc could not bring the multiplexed connection up over the stream.
    Rpc,
    /// The connection came up but the service client did not cross it.
    Clients,
    /// The peer closed before sending its client.
    Closed,
    /// The server loop ended in failure.
    Serve,
}

/// Names the failure, never the leg: one enum serves both hops, and the caller
/// already knows which one it dialled — it prefixes its own.
impl std::fmt::Display for LegError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self {
            LegError::Rpc => "rpc connect",
            LegError::Clients => "service client exchange",
            LegError::Closed => "peer closed before sending its client",
            LegError::Serve => "serve loop",
        };
        write!(f, "{what} failed")
    }
}
impl std::error::Error for LegError {}

/// Serve the execute contract on an already-attested stream until the peer goes
/// away — the WORKER's half of the hop.
///
/// It is here, rather than in the worker, because it is what sends the generated
/// client across the base channel: the type has to be named to bring the
/// connection up at all, and naming it is exactly what no crate outside this one
/// may do any more. `service` is per-connection, so a caller that wants to know
/// who is asking builds one per accept and passes it in.
#[cfg(feature = "execute")]
pub async fn serve_executor<S, R, W>(
    read: R,
    write: W,
    service: Arc<S>,
    concurrency: usize,
) -> Result<(), LegError>
where
    S: ExecutorService + Send + Sync + 'static,
    R: AsyncRead + Send + Sync + Unpin + 'static,
    W: AsyncWrite + Send + Sync + Unpin + 'static,
{
    type Cli = ExecutorServiceClient<Ciborium>;

    let (conn, mut tx, _rx) =
        remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(crate::connection_cfg(), read, write)
            .await
            .map_err(|_| LegError::Rpc)?;
    tokio::spawn(conn);

    let (server, client) = ExecutorServiceServerShared::<_, Ciborium>::new(service, concurrency);
    tx.send(client).await.map_err(|_| LegError::Clients)?;
    server.serve(true).await.map_err(|_| LegError::Serve)?;
    Ok(())
}

/// Bring the hop up on an already-attested stream and take the peer's client —
/// the CALLER's half.
///
/// Returns the leg plus the connection driver's handle, which the caller owns:
/// how a dead leg is noticed, reported and redialled is the caller's policy and
/// none of this crate's business.
#[cfg(feature = "execute")]
pub async fn connect_executor<R, W>(
    read: R,
    write: W,
) -> Result<(ExecutorLeg, tokio::task::JoinHandle<()>), LegError>
where
    R: AsyncRead + Send + Sync + Unpin + 'static,
    W: AsyncWrite + Send + Sync + Unpin + 'static,
{
    type Cli = ExecutorServiceClient<Ciborium>;

    let (conn, _tx, mut rx) =
        remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(crate::connection_cfg(), read, write)
            .await
            .map_err(|_| LegError::Rpc)?;
    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });
    let client = rx
        .recv()
        .await
        .map_err(|_| LegError::Clients)?
        .ok_or(LegError::Closed)?;
    Ok((ExecutorLeg(client), driver))
}

/// The only handle on the execute hop that exists outside this crate.
///
/// It holds the generated client, which nothing else can name. Calls go through
/// the doors below, so what a caller must have closed before a value crosses is
/// stated in a signature the caller cannot get around rather than in a comment it
/// can forget.
#[cfg(feature = "execute")]
pub struct ExecutorLeg(ExecutorServiceClient<Ciborium>);

/// The doors.
///
/// Not behind a feature. A contract that says what may cross a hop is not
/// separable from the words it says it in, and a leg whose door could be compiled
/// away is a leg with no door — which is what an optional boundary meant. The
/// serving half compiles two items it never names; that is the whole cost, against
/// a configuration in which the demand silently disappears.
#[cfg(feature = "execute")]
mod doors {
    use std::sync::Arc;

    use super::{CALLBACK_CONCURRENCY, ExecutorLeg, RunOutcome};
    use crate::execute::{
        CallbackServiceClient, CallbackServiceServerShared, ExecError, ExecutorService, RunReply,
        RunRequest, RunStatus,
    };
    use crate::untrusted::{CallbackServiceUntrusted, Untrusting};
    use enclavid_boundary::{Exposed, Untrusted};
    use remoc::codec::Ciborium;
    use remoc::rtc::ServerShared;

    /// Stand up this round's callback server and hand back its client.
    ///
    /// The caller supplies a [`CallbackServiceUntrusted`], never a raw
    /// `CallbackService`, and that is the inbound half of the wall: the server
    /// type is not re-exported, so no crate outside this one can serve the raw
    /// contract at all. Wrapping is therefore not something the caller opts into
    /// and can forget — there is no unwrapped shape for it to implement.
    ///
    /// It self-terminates once the client handed to the RPC and this copy both
    /// drop, so no task leaks per attempt.
    fn callback_client<C>(callbacks: C) -> CallbackServiceClient<Ciborium>
    where
        C: CallbackServiceUntrusted + Send + Sync + 'static,
        C::Scope: Send,
    {
        let (server, client) = CallbackServiceServerShared::<_, Ciborium>::new(
            Arc::new(Untrusting(callbacks)),
            CALLBACK_CONCURRENCY,
        );
        tokio::spawn(async move {
            let _ = server.serve(true).await;
        });
        client
    }

    impl ExecutorLeg {
        /// The cache-only attempt.
        ///
        /// `req` arrives fully vouched — `Exposed<_, ()>` is reachable only by
        /// peeling every concern the caller's mint opened, so the type is a
        /// receipt that the chain was walked rather than a claim that it was. The
        /// round's state inside it is a [`Padded`](crate::Padded), which is a
        /// stronger statement still: that one has no constructor that skips the
        /// work.
        ///
        /// `callbacks` is the same demand in the other direction, and so is the
        /// RETURN. A peer answers on two channels — what it pushes back mid-round
        /// and what it replies with — and both are equally its own word, so both
        /// arrive under the scope this implementor named. Typing only the pushed
        /// half would have left the reply, which api renders to an applicant and
        /// acts on, as the one thing the peer says that nobody has to judge.
        pub async fn run<C>(
            &self,
            req: Exposed<RunRequest, ()>,
            callbacks: C,
        ) -> Result<Untrusted<RunOutcome, C::Scope>, ExecError>
        where
            C: CallbackServiceUntrusted + Send + Sync + 'static,
            C::Scope: Send,
        {
            self.0
                .run(req.into_inner(), callback_client(callbacks))
                .await
                .map(Untrusted::new)
        }

        /// The post-miss attempt, with the bundle the caller resolved under its own
        /// key. Unframes the reply, so the caller never handles a raw frame.
        ///
        /// `bundle` is deliberately bare. Its `cwasm` is the one value on this hop
        /// with no honest discharge available — nobody inspects those bytes — and
        /// wrapping it would invite a written answer where there is none.
        pub async fn run_with_bundle<C>(
            &self,
            req: Exposed<RunRequest, ()>,
            bundle: crate::CompiledBundle,
            callbacks: C,
        ) -> Result<Untrusted<RunStatus, C::Scope>, ExecError>
        where
            C: CallbackServiceUntrusted + Send + Sync + 'static,
            C::Scope: Send,
        {
            self.0
                .run_with_bundle(req.into_inner(), bundle, callback_client(callbacks))
                .await
                .and_then(|RunReply { status }| status.open().map_err(Into::into))
                .map(Untrusted::new)
        }
    }
}

// =====================================================================
// The compile hop.
// =====================================================================

/// Serve the compile contract on an already-attested stream until the peer goes
/// away — the WORKER's half.
///
/// Takes the UNTRUSTED view, never the raw trait: the raw server type is not
/// exported, so within this workspace there is no second shape to implement by
/// mistake. What arrives therefore arrives under a scope the serving role named,
/// which on this hop is the point — the leaves run `AcceptAny`, so the caller is a
/// genuine SNP guest and not identifiably api.
#[cfg(feature = "compile")]
pub async fn serve_compiler<S, R, W>(
    read: R,
    write: W,
    service: S,
    concurrency: usize,
) -> Result<(), LegError>
where
    S: crate::untrusted_compile::CompilerServiceUntrusted + Send + Sync + 'static,
    S::Scope: Send,
    R: AsyncRead + Send + Sync + Unpin + 'static,
    W: AsyncWrite + Send + Sync + Unpin + 'static,
{
    use crate::compile::{CompilerServiceClient, CompilerServiceServerShared};
    type Cli = CompilerServiceClient<Ciborium>;

    let (conn, mut tx, _rx) =
        remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(crate::connection_cfg(), read, write)
            .await
            .map_err(|_| LegError::Rpc)?;
    tokio::spawn(conn);

    let (server, client) = CompilerServiceServerShared::<_, Ciborium>::new(
        Arc::new(crate::untrusted_compile::Judging(service)),
        concurrency,
    );
    tx.send(client).await.map_err(|_| LegError::Clients)?;
    server.serve(true).await.map_err(|_| LegError::Serve)?;
    Ok(())
}

/// Bring the compile hop up on an already-attested stream — the CALLER's half.
///
/// `S` is how the caller judges what comes BACK, named once here rather than at
/// each call, because a scope is a property of the channel and this channel has
/// exactly one answer for every bundle that ever crosses it.
#[cfg(feature = "compile")]
pub async fn connect_compiler<S, R, W>(
    read: R,
    write: W,
) -> Result<(CompilerLeg<S>, tokio::task::JoinHandle<()>), LegError>
where
    S: enclavid_boundary::Open,
    R: AsyncRead + Send + Sync + Unpin + 'static,
    W: AsyncWrite + Send + Sync + Unpin + 'static,
{
    use crate::compile::CompilerServiceClient;
    type Cli = CompilerServiceClient<Ciborium>;

    let (conn, _tx, mut rx) =
        remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(crate::connection_cfg(), read, write)
            .await
            .map_err(|_| LegError::Rpc)?;
    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });
    let client = rx
        .recv()
        .await
        .map_err(|_| LegError::Clients)?
        .ok_or(LegError::Closed)?;
    Ok((CompilerLeg(client, std::marker::PhantomData), driver))
}

/// The only handle on the compile hop that exists outside this crate.
///
/// `S` is the scope the holder judges the hop's ANSWERS under — declared once, at
/// the dial, because the question a returned bundle raises does not vary call to
/// call.
#[cfg(feature = "compile")]
pub struct CompilerLeg<S>(
    crate::compile::CompilerServiceClient<Ciborium>,
    std::marker::PhantomData<S>,
);

#[cfg(feature = "compile")]
impl<S: enclavid_boundary::Open> CompilerLeg<S> {
    /// Compile, and hand back the bundle as the peer's word.
    ///
    /// `req` arrives at `Exposed<_, ()>` — every concern the caller's mint opened has
    /// been answered somewhere. A receipt, not a proof: see `Exposed::map`.
    ///
    /// The answer comes back `Untrusted`. Nothing binds it to the question — this
    /// side cannot re-derive it (it carries no Cranelift, by design) and a digest
    /// the peer also chose would be its word twice — so the wrapper is where that
    /// gets said rather than assumed.
    pub async fn compile(
        &self,
        req: enclavid_boundary::Exposed<crate::compile::CompileRequest, ()>,
    ) -> Result<enclavid_boundary::Untrusted<crate::CompiledBundle, S>, crate::CompileError> {
        use crate::compile::CompilerService as _;
        self.0
            .compile(req.into_inner())
            .await
            .map(enclavid_boundary::Untrusted::new)
    }
}
