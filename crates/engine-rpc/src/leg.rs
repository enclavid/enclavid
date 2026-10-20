//! The execute hop, owned end to end.
//!
//! `hatch-client` is legible because two things hold together. One named mint
//! gives a value its full concern set, and ONE function — `pub(crate)` in a crate
//! its callers are outside of — is the only way bytes reach the socket. The second
//! is what makes the first more than a habit: you may forget to mint, but you
//! cannot route around the door.
//!
//! The execute hop had neither. api dialled, received the generated
//! `RemoteExecutorClient`, and called it. Nothing stood between a value and the
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
//! used to drive its own child over this same `RemoteCompiler`, so its client could
//! not be withheld from the crate's surface without walling off a hop inside one
//! CVM. That seam now lives with the role that owns both its ends
//! (`engine_compiler::RemoteCompileChild`), and `RemoteCompilerClient` is
//! api-facing only.

use std::sync::Arc;

use remoc::codec::Ciborium;
use remoc::rtc::ServerShared;
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(feature = "execute")]
use crate::execute::{
    PropsRead, RemoteCallbacksClient, RemoteExecutorAdapter, RemoteExecutorAt,
    RemoteExecutorClient, RemoteExecutorServerShared, RemoteExecutorServes,
};
#[cfg(feature = "execute")]
use crate::keys::CompatToken;
#[cfg(feature = "execute")]
use enclavid_boundary::Untrusted;

/// How many requests a served leg lets wait to be taken, unless the role says
/// otherwise ([`serve_executor`], [`serve_compiler`]). api's rounds and compiles
/// arrive a few at a time on its one connection, and each is taken off at once.
pub const DEFAULT_REQUEST_BUFFER: usize = 4;

/// How many callback requests may wait for one round's server to take them,
/// unless the caller says otherwise ([`connect_executor`]).
///
/// Not a bound on how many run at once: remoc spawns a handler for each request
/// as it takes it off this buffer. `media_load` / `session_change` are serialized
/// by the round in practice, so a small buffer is ample.
#[cfg(feature = "execute")]
pub const DEFAULT_CALLBACK_REQUEST_BUFFER: usize = 4;

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

/// The handle a caller awaits to learn its leg is over.
///
/// A leg is over when its connection ends, and also when the channel its calls go
/// out on closes under a connection that lives on. remoc closes a request channel
/// for good on any failed send — an item past its size limit, say, which fails
/// before a byte of it is sent — and leaves the multiplexer up and pinging. A
/// caller watching only the connection would go on handing out a client whose
/// every call fails, and report the leg up while it did.
///
/// `closed` is that channel's end: one client's `closed()`, or the first of
/// several when a leg carries more than one. When it fires the connection is
/// dropped here, so the peer sees the leg end as well and a redial starts clean.
pub fn leg_end(
    mut driver: tokio::task::JoinHandle<()>,
    closed: impl std::future::Future<Output = ()> + Send + 'static,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tokio::select! {
            _ = &mut driver => {}
            () = closed => driver.abort(),
        }
    })
}

/// Serve the execute contract on an already-attested stream until the peer goes
/// away — the WORKER's half of the hop.
///
/// It is here, rather than in the worker, because it is what sends the generated
/// client across the base channel: the type has to be named to bring the
/// connection up at all, and naming it is exactly what no crate outside this one
/// may do any more. `service` is per-connection, so a caller that wants to know
/// who is asking builds one per accept and passes it in.
///
/// Takes the contract as its server sees it at end `B` — an
/// [`RemoteExecutorAt`] — never the raw trait: the raw server type is not
/// exported, so there is no unwrapped shape to implement. This end accepts any
/// attested guest, so what arrives arrives from a genuine SNP guest and not
/// identifiably from api, and `B`'s declaration is where the serving role says
/// what that leaves open.
///
/// `request_buffer` is how many requests may wait to be taken
/// ([`DEFAULT_REQUEST_BUFFER`] unless the role says otherwise), and NOT how many
/// run at once: remoc spawns a handler for each request as it takes it, without
/// limit. A role that must bound concurrent work bounds it in that work. `leg` is
/// what the role sets of its end of the connection.
#[cfg(feature = "execute")]
pub async fn serve_executor<B, S, R, W>(
    read: R,
    write: W,
    service: S,
    request_buffer: usize,
    leg: &crate::LegSettings,
) -> Result<(), LegError>
where
    B: RemoteExecutorServes + 'static,
    S: RemoteExecutorAt<B> + Send + Sync + 'static,
    R: AsyncRead + Send + Sync + Unpin + 'static,
    W: AsyncWrite + Send + Sync + Unpin + 'static,
{
    type Cli = RemoteExecutorClient<Ciborium>;

    let (conn, mut tx, _rx) =
        remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(crate::connection_cfg(leg), read, write)
            .await
            .map_err(|_| LegError::Rpc)?;
    tokio::spawn(conn);

    let (server, client) = RemoteExecutorServerShared::<_, Ciborium>::new(
        Arc::new(RemoteExecutorAdapter::<S, B>::new(service)),
        request_buffer,
    );
    tx.send(client).await.map_err(|_| LegError::Clients)?;
    server.serve(true).await.map_err(|_| LegError::Serve)?;
    Ok(())
}

/// Bring the hop up on an already-attested stream and take the peer's client —
/// the CALLER's half.
///
/// Returns the leg plus a handle that finishes when the leg is over — its
/// connection ended or its request channel closed, see [`leg_end`]. The caller
/// owns it: how a dead leg is reported and redialled is the caller's policy and
/// none of this crate's business. Noticing it is this crate's, because the
/// channel belongs to a client nothing outside it can name.
///
/// `B` is the caller's end of the hop, whose declaration says what is open on
/// each value that crosses it. `leg` is what the caller sets of its end of the
/// connection, and `callback_buffer` how many of a round's callbacks may wait for
/// its server ([`DEFAULT_CALLBACK_REQUEST_BUFFER`] unless the caller says
/// otherwise).
#[cfg(feature = "execute")]
pub async fn connect_executor<B, R, W>(
    read: R,
    write: W,
    leg: &crate::LegSettings,
    callback_buffer: usize,
) -> Result<(ExecutorLeg<B>, tokio::task::JoinHandle<()>), LegError>
where
    R: AsyncRead + Send + Sync + Unpin + 'static,
    W: AsyncWrite + Send + Sync + Unpin + 'static,
{
    type Cli = RemoteExecutorClient<Ciborium>;

    let (conn, _tx, mut rx) =
        remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(crate::connection_cfg(leg), read, write)
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
    let ended = leg_end(driver, remoc::rtc::Client::closed(&client));
    Ok((
        ExecutorLeg {
            client,
            callback_buffer,
            _end: std::marker::PhantomData,
        },
        ended,
    ))
}

/// The only handle on the execute hop that exists outside this crate, held at
/// end `B`.
///
/// It holds the generated client, which nothing else can name. Calls go through
/// the doors below, so what a caller must have closed before a value crosses is
/// stated in a signature the caller cannot get around rather than in a comment it
/// can forget — and stated by `B`'s declaration, which is the one place the
/// caller says how it judges this leg.
#[cfg(feature = "execute")]
pub struct ExecutorLeg<B> {
    client: RemoteExecutorClient<Ciborium>,
    /// How many of a round's callbacks may wait for its server.
    callback_buffer: usize,
    _end: std::marker::PhantomData<fn() -> B>,
}

/// The callbacks a round was handed, as end `B` calls them — the only handle on
/// them a serving role is given.
///
/// The serve view hands this rather than the generated client, and the client is
/// not re-exported, so what a role sends back mid-round goes through `B`'s
/// declaration as what it replies does: each argument leaves answered, each
/// answer arrives open on what `B` left open on it.
#[cfg(feature = "execute")]
pub struct Callbacks<B> {
    client: RemoteCallbacksClient<Ciborium>,
    _end: std::marker::PhantomData<fn() -> B>,
}

#[cfg(feature = "execute")]
impl<B> From<RemoteCallbacksClient<Ciborium>> for Callbacks<B> {
    fn from(client: RemoteCallbacksClient<Ciborium>) -> Self {
        Self {
            client,
            _end: std::marker::PhantomData,
        }
    }
}

/// What a cache-only preparation answered, each half the worker's word, open
/// on what end `B` left open on the preparation's outcome.
#[cfg(feature = "execute")]
pub enum Preparation<S, B> {
    /// The composition is held, and this is what was read.
    Read(Untrusted<PropsRead, S, B>),
    /// It is not cached; the worker's cwasm ABI id, to resolve it under.
    CacheMiss(Untrusted<CompatToken, S, B>),
}

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

    use super::{Callbacks, ExecutorLeg, Preparation};
    use crate::execute::{
        CallbackError, Committed, ExecError, MediaBytes, MediaHash, PrepareOutcome, PrepareReply,
        PrepareRequest, PropsRead, RemoteCallbacks, RemoteCallbacksAdapter, RemoteCallbacksAt,
        RemoteCallbacksCalls, RemoteCallbacksClient, RemoteCallbacksServerShared,
        RemoteCallbacksServes, RemoteExecutor, RemoteExecutorCalls, RunOutcome, RunReply,
        RunRequest, RunStatus,
    };
    use crate::padded::{FrameError, Padded};
    use crate::stream::BundleStream;
    use enclavid_boundary::{Exposed, Receives, Sends, Untrusted, inbound, outbound};
    use remoc::codec::Ciborium;
    use remoc::rtc::ServerShared;
    use session_types::{Decision, SessionState};

    /// A frame the peer sent that does not decode, as the caller hears of it:
    /// `Unknown`, and the error itself dropped unread — it is the peer's doing as
    /// much as the frame was, so nothing of it is passed on.
    fn unframed<S, B>(_: Untrusted<FrameError, S, B>) -> ExecError {
        ExecError::Unknown
    }

    /// Stand up this round's callback server and hand back its client.
    ///
    /// The caller supplies a [`RemoteCallbacksAt`] at its own end, never a raw
    /// `RemoteCallbacks`, and that is the inbound half of the wall: the server
    /// type is not re-exported, so no crate outside this one can serve the raw
    /// contract at all. Wrapping is therefore not something the caller opts into
    /// and can forget — there is no unwrapped shape for it to implement.
    ///
    /// It self-terminates once the client handed to the RPC and this copy both
    /// drop, so no task leaks per attempt. `buffer` is how many callbacks may
    /// wait for it.
    fn callback_client<B, C>(callbacks: C, buffer: usize) -> RemoteCallbacksClient<Ciborium>
    where
        B: RemoteCallbacksServes + 'static,
        C: RemoteCallbacksAt<B> + Send + Sync + 'static,
    {
        let (server, client) = RemoteCallbacksServerShared::<_, Ciborium>::new(
            Arc::new(RemoteCallbacksAdapter::<C, B>::new(callbacks)),
            buffer,
        );
        tokio::spawn(async move {
            let _ = server.serve(true).await;
        });
        client
    }

    impl<B> ExecutorLeg<B>
    where
        B: RemoteExecutorCalls + RemoteCallbacksServes + 'static,
    {
        /// The cache-only attempt.
        ///
        /// `req` arrives answered — `Exposed<_, (), B>` is reachable only through
        /// `B`'s declaration and the answers its sender gave after it, so the type
        /// is a receipt rather than a claim. The round's state inside it is a
        /// [`Padded`](crate::Padded), which is a stronger statement still: that one
        /// has no constructor that skips the work.
        ///
        /// `callbacks` is the same demand in the other direction, and so is the
        /// RETURN. A peer answers on two channels — what it pushes back mid-round
        /// and what it replies with — and both are equally its own word, so both
        /// arrive open on what `B` left open. Typing only the pushed half would
        /// have left the reply, which api renders to an applicant and acts on, as
        /// the one thing the peer says that nobody has to judge.
        pub async fn run<C>(
            &self,
            req: Exposed<RunRequest, (), B>,
            callbacks: C,
        ) -> Result<Untrusted<RunOutcome, <B as Receives<RunOutcome>>::Open, B>, ExecError>
        where
            C: RemoteCallbacksAt<B> + Send + Sync + 'static,
        {
            self.client
                .run(
                    req.into_inner(),
                    callback_client::<B, C>(callbacks, self.callback_buffer),
                )
                .await
                .map(inbound::<B, _>)
        }

        /// The post-miss attempt, with the bundle the caller resolved under its own
        /// key. Unframes the reply, so the caller never handles a raw frame.
        ///
        /// `bundle` crosses answered by `B`'s declaration alone, which the bound
        /// demands: the door frames it into the stream itself, so there is no
        /// later point at which a sender could answer for it. The bytes the
        /// worker is about to file and later map are answered for again on its
        /// side, which is where acting on them happens.
        ///
        /// It crosses as two streams beside a bounded request ([`BundleStream`]):
        /// the request is the round alone, so a full clip and a large bundle
        /// never have to fit one remoc item together.
        pub async fn run_with_bundle<C>(
            &self,
            req: Exposed<RunRequest, (), B>,
            bundle: crate::BundleSource,
            callbacks: C,
        ) -> Result<Untrusted<RunStatus, <B as Receives<RunReply>>::Open, B>, ExecError>
        where
            B: Sends<BundleStream, Open = ()>,
            C: RemoteCallbacksAt<B> + Send + Sync + 'static,
        {
            let (stream, writer) = BundleStream::split(bundle);
            let stream = outbound::<B, _>(stream).into_inner();
            let mut call = std::pin::pin!(self.client.run_with_bundle(
                req.into_inner(),
                stream,
                callback_client::<B, C>(callbacks, self.callback_buffer)
            ));
            // The reply is the round's outcome and the writer's never is: a worker
            // that already holds this composition never reads the stream, and one
            // that refused it stopped reading. Driven here rather than spawned, so
            // the writer cannot outlive the round however the round ends.
            let reply = tokio::select! {
                reply = &mut call => reply,
                () = writer => call.await,
            };
            inbound::<B, _>(reply?)
                .try_map(|RunReply { status }| status.open())
                .map_err(unframed)
        }

        /// The cache-only attempt at preparing a session. `req` arrives answered,
        /// as a round's does; the reply arrives open on what `B` left open on it.
        /// Unframed, and taken apart by its variant, so that each half is judged
        /// on its own grounds: the two lead to different paths, and neither is
        /// acted on before it is judged.
        pub async fn prepare(
            &self,
            req: Exposed<PrepareRequest, (), B>,
        ) -> Result<Preparation<<B as Receives<PrepareOutcome>>::Open, B>, ExecError> {
            let outcome = inbound::<B, _>(self.client.prepare(req.into_inner()).await?);
            Ok(
                match outcome.split(|o| match o {
                    PrepareOutcome::Prepared(read) => Ok(read),
                    PrepareOutcome::CacheMiss { compat_token } => Err(compat_token),
                }) {
                    Ok(read) => Preparation::Read(read.try_map(|r| r.open()).map_err(unframed)?),
                    Err(compat_token) => Preparation::CacheMiss(compat_token),
                },
            )
        }

        /// The post-miss attempt at preparing a session, with the bundle the
        /// caller resolved under its own key, which crosses as a round's does
        /// (see [`run_with_bundle`](Self::run_with_bundle)). Unframes the reply.
        pub async fn prepare_with_bundle(
            &self,
            req: Exposed<PrepareRequest, (), B>,
            bundle: crate::BundleSource,
        ) -> Result<Untrusted<PropsRead, <B as Receives<PrepareReply>>::Open, B>, ExecError>
        where
            B: Sends<BundleStream, Open = ()>,
        {
            let (stream, writer) = BundleStream::split(bundle);
            let stream = outbound::<B, _>(stream).into_inner();
            let mut call =
                std::pin::pin!(self.client.prepare_with_bundle(req.into_inner(), stream));
            let reply = tokio::select! {
                reply = &mut call => reply,
                () = writer => call.await,
            };
            inbound::<B, _>(reply?)
                .try_map(|PrepareReply { props }| props.open())
                .map_err(unframed)
        }
    }

    impl<B: RemoteCallbacksCalls> Callbacks<B> {
        /// Ask for a blob by the hash a round named.
        pub async fn media_load(
            &self,
            hash: Exposed<MediaHash, (), B>,
        ) -> Result<
            Untrusted<Option<MediaBytes>, <B as Receives<Option<MediaBytes>>>::Open, B>,
            CallbackError,
        > {
            self.client
                .media_load(hash.into_inner())
                .await
                .map(inbound::<B, _>)
        }

        /// Hand a round's state, and its decision if it made one, back to be
        /// committed.
        pub async fn session_change(
            &self,
            state: Exposed<Padded<SessionState>, (), B>,
            decision: Exposed<Padded<Option<Decision>>, (), B>,
        ) -> Result<Untrusted<Committed, <B as Receives<Committed>>::Open, B>, CallbackError>
        {
            self.client
                .session_change(state.into_inner(), decision.into_inner())
                .await
                .map(inbound::<B, _>)
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
///
/// `request_buffer` is how many requests may wait to be taken, as on
/// `serve_executor` — not how many run at once — and `leg` what the role sets of
/// its end of the connection.
#[cfg(feature = "compile")]
pub async fn serve_compiler<S, R, W>(
    read: R,
    write: W,
    service: S,
    request_buffer: usize,
    leg: &crate::LegSettings,
) -> Result<(), LegError>
where
    S: crate::untrusted_compile::RemoteCompilerUntrusted + Send + Sync + 'static,
    S::Scope: Send,
    R: AsyncRead + Send + Sync + Unpin + 'static,
    W: AsyncWrite + Send + Sync + Unpin + 'static,
{
    use crate::compile::{RemoteCompilerClient, RemoteCompilerServerShared};
    type Cli = RemoteCompilerClient<Ciborium>;

    let (conn, mut tx, _rx) =
        remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(crate::connection_cfg(leg), read, write)
            .await
            .map_err(|_| LegError::Rpc)?;
    tokio::spawn(conn);

    let (server, client) = RemoteCompilerServerShared::<_, Ciborium>::new(
        Arc::new(crate::adapter::Untrusting(service)),
        request_buffer,
    );
    tx.send(client).await.map_err(|_| LegError::Clients)?;
    server.serve(true).await.map_err(|_| LegError::Serve)?;
    Ok(())
}

/// Bring the compile hop up on an already-attested stream — the CALLER's half.
/// The handle it returns finishes when the leg is over, as [`connect_executor`]'s
/// does.
///
/// `S` is how the caller judges what comes BACK, named once here rather than at
/// each call, because a scope is a property of the channel and this channel has
/// exactly one answer for every bundle that ever crosses it. `leg` is what the
/// caller sets of its end of the connection.
#[cfg(feature = "compile")]
pub async fn connect_compiler<S, R, W>(
    read: R,
    write: W,
    leg: &crate::LegSettings,
) -> Result<(CompilerLeg<S>, tokio::task::JoinHandle<()>), LegError>
where
    S: enclavid_boundary::Open,
    R: AsyncRead + Send + Sync + Unpin + 'static,
    W: AsyncWrite + Send + Sync + Unpin + 'static,
{
    use crate::compile::RemoteCompilerClient;
    type Cli = RemoteCompilerClient<Ciborium>;

    let (conn, _tx, mut rx) =
        remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(crate::connection_cfg(leg), read, write)
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
    let ended = leg_end(driver, remoc::rtc::Client::closed(&client));
    Ok((CompilerLeg(client, std::marker::PhantomData), ended))
}

/// The only handle on the compile hop that exists outside this crate.
///
/// `S` is the scope the holder judges the hop's ANSWERS under — declared once, at
/// the dial, because the question a returned bundle raises does not vary call to
/// call.
#[cfg(feature = "compile")]
pub struct CompilerLeg<S>(
    crate::compile::RemoteCompilerClient<Ciborium>,
    std::marker::PhantomData<S>,
);

#[cfg(feature = "compile")]
impl<S: enclavid_boundary::Open> CompilerLeg<S> {
    /// Compile, and hand back the bundle as the peer's word.
    ///
    /// `req` arrives at `Exposed<_, ()>` — every concern the caller's mint opened has
    /// been answered somewhere. A receipt, not a proof: see `Exposed::map`. Its
    /// components stream beside the call, written here while it is awaited.
    ///
    /// The answer comes back `Untrusted`, a refusal as much as a bundle. Nothing
    /// binds a bundle to the question — this side cannot re-derive it (it carries
    /// no Cranelift, by design) and a digest the peer also chose would be its word
    /// twice — and a refusal names interfaces and packages the peer picked. The
    /// wrapper is where that gets said rather than assumed.
    pub async fn compile(
        &self,
        req: enclavid_boundary::Exposed<crate::compile::CompileSource, ()>,
    ) -> Result<
        enclavid_boundary::Untrusted<crate::CompileReply, S>,
        enclavid_boundary::Untrusted<crate::CompileError, S>,
    > {
        use crate::compile::RemoteCompiler as _;
        let (request, writer) = req.into_inner().split();
        let mut call = std::pin::pin!(self.0.compile(request));
        // The reply comes once the components were read, or once the worker
        // gave up on them; the writer is never the outcome. Driven here rather
        // than spawned, so it cannot outlive the call however the call ends.
        let reply = tokio::select! {
            reply = &mut call => reply,
            () = writer => call.await,
        };
        reply
            .map(enclavid_boundary::Untrusted::new)
            .map_err(enclavid_boundary::Untrusted::new)
    }
}

/// The execute door end to end: `connect_executor` on one side, `serve_executor`
/// on the other, the real connection config between them.
#[cfg(all(test, feature = "execute"))]
mod door_tests {
    use enclavid_boundary::{Asserted, AuthN, Exposed, Untrusted};
    use enclavid_boundary_macros::boundary;
    use session_types::{
        Clip, Decision, Event, MAX_CLIP_BYTES, MAX_CLIP_FRAMES, MediaResult, SessionState,
    };

    use super::{
        Callbacks, DEFAULT_CALLBACK_REQUEST_BUFFER, DEFAULT_REQUEST_BUFFER, ExecutorLeg,
        connect_executor, serve_executor,
    };
    use crate::bundle::{CompiledBundle, sample_bundle};
    use crate::execute::{
        CallbackError, Committed, ExecError, MediaBytes, MediaHash, PrepareOutcome, PrepareReply,
        PrepareRequest, RemoteCallbacksAt, RemoteExecutorAt, RunOutcome, RunReply, RunRequest,
        RunStatus,
    };
    use crate::keys::CompositionKey;
    use crate::padded::{Framed, Padded};
    use crate::stream::BundleStream;

    boundary! {
        /// The calling end, for the test: every concern answered.
        Api {
            calls: [crate::execute::RemoteExecutor],
            serves: [crate::execute::RemoteCallbacks],
            observer: Test,
        }
        out (AuthN,) {
            /// test fixture
            _: AuthN::SelfProduced,
            RunRequest,
            PrepareRequest,
            BundleStream,
            Option<MediaBytes>,
            Committed,
            CallbackError,
        }
        in (Asserted,) {
            /// test fixture
            _: Asserted::Contained,
            RunOutcome,
            RunReply,
            PrepareOutcome,
            PrepareReply,
            ExecError,
            MediaHash,
            Padded<SessionState>,
            Padded<Option<Decision>>,
        }
    }

    boundary! {
        /// The serving end, for the test: every concern answered.
        Worker {
            calls: [crate::execute::RemoteCallbacks],
            serves: [crate::execute::RemoteExecutor],
            observer: Test,
        }
        in (AuthN,) {
            /// test fixture
            _: AuthN::SelfProduced,
            RunRequest,
            PrepareRequest,
            BundleStream,
            Option<MediaBytes>,
            Committed,
            CallbackError,
        }
        out (AuthN,) {
            /// test fixture
            _: AuthN::SelfProduced,
            RunOutcome,
            RunReply,
            PrepareOutcome,
            PrepareReply,
            ExecError,
            MediaHash,
            Padded<SessionState>,
            Padded<Option<Decision>>,
        }
    }

    /// A worker that checks the bundle it is sent against `expect`, or — with
    /// `None` — never reads it at all, as a worker that already holds the
    /// composition does.
    struct FakeWorker {
        expect: Option<Vec<u8>>,
    }

    impl RemoteExecutorAt<Worker> for FakeWorker {
        async fn run(
            &self,
            _req: Untrusted<RunRequest, (), Worker>,
            _callbacks: Callbacks<Worker>,
        ) -> Result<Exposed<RunOutcome, (), Worker>, ExecError> {
            Err(ExecError::Unknown)
        }

        async fn run_with_bundle(
            &self,
            req: Untrusted<RunRequest, (), Worker>,
            bundle: Untrusted<BundleStream, (), Worker>,
            _callbacks: Callbacks<Worker>,
        ) -> Result<Exposed<RunReply, (), Worker>, ExecError> {
            let _ = req.into_inner();
            let bundle = bundle.into_inner();
            if let Some(expect) = &self.expect {
                let mut cwasm = Vec::new();
                let (len, meta, _) = bundle
                    .receive(
                        &mut cwasm,
                        crate::DEFAULT_BUNDLE_STREAM_DEADLINE,
                        crate::DEFAULT_BUNDLE_STREAM_IDLE,
                    )
                    .await
                    .map_err(|_| ExecError::Unknown)?;
                let whole = len == expect.len() as u64 && cwasm == *expect;
                let meta_intact = meta.embedded_imports.len() == 1
                    && meta.catalogs.len() == 1
                    && meta.catalogs[0].decls.disclosure_fields.contains("dob");
                if !(whole && meta_intact) {
                    return Err(ExecError::Unknown);
                }
            }
            let reply = RunReply {
                status: Padded::seal(&RunStatus::Completed(Decision::Approved))?,
            };
            Ok(Worker::expose(reply))
        }

        async fn prepare(
            &self,
            _req: Untrusted<PrepareRequest, (), Worker>,
        ) -> Result<Exposed<PrepareOutcome, (), Worker>, ExecError> {
            Err(ExecError::Unknown)
        }

        async fn prepare_with_bundle(
            &self,
            _req: Untrusted<PrepareRequest, (), Worker>,
            _bundle: Untrusted<BundleStream, (), Worker>,
        ) -> Result<Exposed<PrepareReply, (), Worker>, ExecError> {
            Err(ExecError::Unknown)
        }
    }

    struct NoCallbacks;

    impl RemoteCallbacksAt<Api> for NoCallbacks {
        async fn media_load(
            &self,
            _hash: Untrusted<MediaHash, (), Api>,
        ) -> Result<Exposed<Option<MediaBytes>, (), Api>, CallbackError> {
            Err(CallbackError)
        }

        async fn session_change(
            &self,
            _state: Untrusted<Padded<SessionState>, (), Api>,
            _decision: Untrusted<Padded<Option<Decision>>, (), Api>,
        ) -> Result<Exposed<Committed, (), Api>, CallbackError> {
            Err(CallbackError)
        }
    }

    /// A worker whose cached round calls back mid-round, as a policy does that
    /// reads a capture and finishes: a blob by its hash, then the round's state
    /// and decision, each through the door its end is given.
    struct CallingWorker;

    impl RemoteExecutorAt<Worker> for CallingWorker {
        async fn run(
            &self,
            req: Untrusted<RunRequest, (), Worker>,
            callbacks: Callbacks<Worker>,
        ) -> Result<Exposed<RunOutcome, (), Worker>, ExecError> {
            let RunRequest { session_state, .. } = req.into_inner();
            let blob = callbacks
                .media_load(Worker::expose(MediaHash([9; 32])))
                .await?
                .into_inner();
            if blob != Some(MediaBytes(vec![0xAB, 0xCD])) {
                return Err(ExecError::Unknown);
            }
            callbacks
                .session_change(
                    Worker::expose(session_state),
                    Worker::expose(Padded::seal(&Some(Decision::Approved))?),
                )
                .await?
                .into_inner();
            let status = Padded::seal(&RunStatus::Completed(Decision::Approved))?;
            Ok(Worker::expose(RunOutcome::Ran(status)))
        }

        async fn run_with_bundle(
            &self,
            _req: Untrusted<RunRequest, (), Worker>,
            _bundle: Untrusted<BundleStream, (), Worker>,
            _callbacks: Callbacks<Worker>,
        ) -> Result<Exposed<RunReply, (), Worker>, ExecError> {
            Err(ExecError::Unknown)
        }

        async fn prepare(
            &self,
            _req: Untrusted<PrepareRequest, (), Worker>,
        ) -> Result<Exposed<PrepareOutcome, (), Worker>, ExecError> {
            Err(ExecError::Unknown)
        }

        async fn prepare_with_bundle(
            &self,
            _req: Untrusted<PrepareRequest, (), Worker>,
            _bundle: Untrusted<BundleStream, (), Worker>,
        ) -> Result<Exposed<PrepareReply, (), Worker>, ExecError> {
            Err(ExecError::Unknown)
        }
    }

    /// api's side of the callbacks, recording what arrives through its door.
    #[derive(Clone, Default)]
    struct RecordingCallbacks {
        hashes: std::sync::Arc<std::sync::Mutex<Vec<MediaHash>>>,
        decisions: std::sync::Arc<std::sync::Mutex<Vec<Option<Decision>>>>,
    }

    impl RemoteCallbacksAt<Api> for RecordingCallbacks {
        async fn media_load(
            &self,
            hash: Untrusted<MediaHash, (), Api>,
        ) -> Result<Exposed<Option<MediaBytes>, (), Api>, CallbackError> {
            self.hashes.lock().unwrap().push(hash.into_inner());
            Ok(Api::expose(Some(MediaBytes(vec![0xAB, 0xCD]))))
        }

        async fn session_change(
            &self,
            _state: Untrusted<Padded<SessionState>, (), Api>,
            decision: Untrusted<Padded<Option<Decision>>, (), Api>,
        ) -> Result<Exposed<Committed, (), Api>, CallbackError> {
            let decision = decision.into_inner().open()?;
            self.decisions.lock().unwrap().push(decision);
            Ok(Api::expose(Committed))
        }
    }

    async fn leg<S>(worker: S) -> ExecutorLeg<Api>
    where
        S: RemoteExecutorAt<Worker> + Send + Sync + 'static,
    {
        let (a, b) = tokio::io::duplex(1 << 20);
        let (ar, aw) = tokio::io::split(a);
        let (br, bw) = tokio::io::split(b);
        let settings = crate::LegSettings::default();
        tokio::spawn(async move {
            let _ = serve_executor::<Worker, _, _, _>(
                ar,
                aw,
                worker,
                DEFAULT_REQUEST_BUFFER,
                &settings,
            )
            .await;
        });
        let (leg, _ended) =
            connect_executor::<Api, _, _>(br, bw, &settings, DEFAULT_CALLBACK_REQUEST_BUFFER)
                .await
                .expect("the leg comes up");
        leg
    }

    fn round(event: Event) -> Exposed<RunRequest, (), Api> {
        Api::expose(RunRequest {
            composition_key: CompositionKey::from_digest([0x22; 32]),
            max_cwasm_bytes: crate::MAX_CWASM_BYTES,
            props: Padded::seal(&crate::execute::RoundProps(Vec::new())).expect("fits the frame"),
            session_state: Padded::seal(&SessionState::default()).expect("fits the frame"),
            event,
        })
    }

    fn approved(status: Result<Untrusted<RunStatus, (), Api>, ExecError>) -> bool {
        matches!(
            status.map(|s| s.into_inner()),
            Ok(RunStatus::Completed(Decision::Approved))
        )
    }

    /// The declaration is data a test can read: what crosses, what it opens,
    /// what is answered, and why.
    #[test]
    fn a_declaration_reads_back_as_data() {
        let d = Api::DECLARATION;
        assert_eq!(d.name, "Api");
        assert_eq!(d.calls, ["crate::execute::RemoteExecutor"]);
        let request = d
            .crossings
            .iter()
            .find(|c| c.ty == "RunRequest")
            .expect("RunRequest crosses");
        assert_eq!(request.opens, ["AuthN"]);
        assert_eq!(request.answers[0].kind, "SelfProduced");
        assert_eq!(request.answers[0].doc, "test fixture");
        assert!(request.answers[0].every_type);
        assert!(request.left.is_empty());
    }

    /// A round's callbacks cross both doors: the worker calls back through the
    /// `Callbacks` its end is handed, and api's server receives through the
    /// adapter written for its end — the hash as the worker named it, the decision
    /// as the round made it, and the blob and the commit back the other way.
    #[tokio::test]
    async fn a_round_calls_back_through_both_doors() {
        let leg = leg(CallingWorker).await;
        let callbacks = RecordingCallbacks::default();
        let event = Event::Media(MediaResult {
            slot: 0,
            clip: Clip { frames: Vec::new() },
        });
        let outcome = leg
            .run(round(event), callbacks.clone())
            .await
            .expect("the round runs")
            .into_inner();
        let RunOutcome::Ran(status) = outcome else {
            panic!("the round was answered as a miss");
        };
        assert!(matches!(
            status.open(),
            Ok(RunStatus::Completed(Decision::Approved))
        ));
        assert_eq!(*callbacks.hashes.lock().unwrap(), [MediaHash([9; 32])]);
        assert_eq!(
            *callbacks.decisions.lock().unwrap(),
            [Some(Decision::Approved)]
        );
    }

    /// The round that failed in the field: a full capture, during a cache miss,
    /// with a bundle that put the request past one remoc item.
    #[tokio::test]
    async fn a_full_clip_and_a_bundle_that_overflowed_one_item_cross_in_one_round() {
        let cwasm: Vec<u8> = (0..8 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        assert!(
            MAX_CLIP_BYTES + <SessionState as Framed>::FRAME + cwasm.len()
                > remoc::rch::DEFAULT_MAX_ITEM_SIZE,
            "the premise: inside the request, this bundle would not fit"
        );
        let leg = leg(FakeWorker {
            expect: Some(cwasm.clone()),
        })
        .await;
        let event = Event::Media(MediaResult {
            slot: 0,
            clip: Clip {
                frames: vec![vec![0xEE; MAX_CLIP_BYTES / MAX_CLIP_FRAMES]; MAX_CLIP_FRAMES],
            },
        });
        let bundle = CompiledBundle {
            cwasm,
            ..sample_bundle()
        };
        let bundle = crate::BundleSource::whole(bundle).unwrap();
        assert!(approved(
            leg.run_with_bundle(round(event), bundle, NoCallbacks).await
        ));
    }

    /// A worker that already holds the composition — another round of it got there
    /// first — runs from that and never reads this round's stream. The writer that
    /// then cannot write is not the round's outcome.
    #[tokio::test]
    async fn a_worker_that_never_reads_the_bundle_still_answers_the_round() {
        let leg = leg(FakeWorker { expect: None }).await;
        let bundle = crate::BundleSource::whole(sample_bundle()).unwrap();
        assert!(approved(
            leg.run_with_bundle(round(Event::Start), bundle, NoCallbacks)
                .await
        ));
    }
}

#[cfg(test)]
mod leg_end_tests {
    use std::time::Duration;

    use tokio::sync::oneshot;

    use super::leg_end;

    /// Says so when the task holding it is dropped — aborted, here.
    struct Dropped(Option<oneshot::Sender<()>>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            if let Some(tx) = self.0.take() {
                let _ = tx.send(());
            }
        }
    }

    const PATIENCE: Duration = Duration::from_secs(10);

    #[tokio::test]
    async fn a_closed_channel_ends_the_leg_and_drops_its_connection() {
        let (dropped_tx, dropped_rx) = oneshot::channel();
        let driver = tokio::spawn(async move {
            let _held = Dropped(Some(dropped_tx));
            std::future::pending::<()>().await;
        });
        let (close_tx, close_rx) = oneshot::channel::<()>();
        let ended = leg_end(driver, async move {
            let _ = close_rx.await;
        });

        close_tx.send(()).unwrap();
        tokio::time::timeout(PATIENCE, ended)
            .await
            .expect("the leg ends")
            .unwrap();
        tokio::time::timeout(PATIENCE, dropped_rx)
            .await
            .expect("the connection is dropped")
            .unwrap();
    }

    #[tokio::test]
    async fn the_connection_ending_ends_the_leg() {
        let driver = tokio::spawn(async {});
        let ended = leg_end(driver, std::future::pending());
        tokio::time::timeout(PATIENCE, ended)
            .await
            .expect("the leg ends")
            .unwrap();
    }
}
