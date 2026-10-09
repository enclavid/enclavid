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
use crate::execute::{ExecutorServiceClient, ExecutorServiceServerShared, RunOutcome};

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
/// Takes the UNTRUSTED view, never the raw trait — the same demand
/// [`serve_compiler`] makes, and for the same reason. This end runs `AcceptAny`,
/// so what arrives arrives from a genuine SNP guest and not identifiably from api;
/// a role serving it has something open to name whether or not it feels like it.
///
/// `request_buffer` is how many requests may wait to be taken
/// ([`DEFAULT_REQUEST_BUFFER`] unless the role says otherwise), and NOT how many
/// run at once: remoc spawns a handler for each request as it takes it, without
/// limit. A role that must bound concurrent work bounds it in that work. `leg` is
/// what the role sets of its end of the connection.
#[cfg(feature = "execute")]
pub async fn serve_executor<S, R, W>(
    read: R,
    write: W,
    service: S,
    request_buffer: usize,
    leg: &crate::LegSettings,
) -> Result<(), LegError>
where
    S: crate::untrusted_execute::ExecutorServiceUntrusted + Send + Sync + 'static,
    S::Scope: Send,
    R: AsyncRead + Send + Sync + Unpin + 'static,
    W: AsyncWrite + Send + Sync + Unpin + 'static,
{
    type Cli = ExecutorServiceClient<Ciborium>;

    let (conn, mut tx, _rx) =
        remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(crate::connection_cfg(leg), read, write)
            .await
            .map_err(|_| LegError::Rpc)?;
    tokio::spawn(conn);

    let (server, client) = ExecutorServiceServerShared::<_, Ciborium>::new(
        Arc::new(crate::adapter::Untrusting(service)),
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
/// `leg` is what the caller sets of its end of the connection, and
/// `callback_buffer` how many of a round's callbacks may wait for its server
/// ([`DEFAULT_CALLBACK_REQUEST_BUFFER`] unless the caller says otherwise).
#[cfg(feature = "execute")]
pub async fn connect_executor<R, W>(
    read: R,
    write: W,
    leg: &crate::LegSettings,
    callback_buffer: usize,
) -> Result<(ExecutorLeg, tokio::task::JoinHandle<()>), LegError>
where
    R: AsyncRead + Send + Sync + Unpin + 'static,
    W: AsyncWrite + Send + Sync + Unpin + 'static,
{
    type Cli = ExecutorServiceClient<Ciborium>;

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
        },
        ended,
    ))
}

/// The only handle on the execute hop that exists outside this crate.
///
/// It holds the generated client, which nothing else can name. Calls go through
/// the doors below, so what a caller must have closed before a value crosses is
/// stated in a signature the caller cannot get around rather than in a comment it
/// can forget.
#[cfg(feature = "execute")]
pub struct ExecutorLeg {
    client: ExecutorServiceClient<Ciborium>,
    /// How many of a round's callbacks may wait for its server.
    callback_buffer: usize,
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

    use super::{ExecutorLeg, RunOutcome};
    use crate::adapter::Untrusting;
    use crate::execute::{
        CallbackServiceClient, CallbackServiceServerShared, ExecError, ExecutorService, RunReply,
        RunRequest, RunStatus,
    };
    use crate::stream::BundleStream;
    use crate::untrusted_execute::CallbackServiceUntrusted;
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
    /// drop, so no task leaks per attempt. `buffer` is how many callbacks may
    /// wait for it.
    fn callback_client<C>(callbacks: C, buffer: usize) -> CallbackServiceClient<Ciborium>
    where
        C: CallbackServiceUntrusted + Send + Sync + 'static,
        C::Scope: Send,
    {
        let (server, client) = CallbackServiceServerShared::<_, Ciborium>::new(
            Arc::new(Untrusting(callbacks)),
            buffer,
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
            self.client
                .run(
                    req.into_inner(),
                    callback_client(callbacks, self.callback_buffer),
                )
                .await
                .map(Untrusted::new)
        }

        /// The post-miss attempt, with the bundle the caller resolved under its own
        /// key. Unframes the reply, so the caller never handles a raw frame.
        ///
        /// `bundle` is deliberately bare ON THIS SIDE. The caller resolved it under
        /// its own key, so releasing it raises no question the round's own mint has
        /// not already answered for the leg.
        ///
        /// The RECEIVING side is where it earns a wrapper, and it has one: the
        /// worker takes `Untrusted<BundleStream, _>` separately from the request,
        /// because the bytes it is about to file and later MMAP are the one value on
        /// this hop for which no discharge kind fits. That answer belongs to the
        /// side that acts on them, not to the side that forwards them.
        ///
        /// It crosses as two streams beside a bounded request ([`BundleStream`]):
        /// the request is the round alone, so a full clip and a large bundle
        /// never have to fit one remoc item together. The same bytes, framed
        /// differently, and the header names them — so the release raises
        /// nothing new. Their lengths are fixed per composition, set when the
        /// consumer's policy was compiled and never a function of applicant data,
        /// and "this composition was cold" was already legible on this hop.
        pub async fn run_with_bundle<C>(
            &self,
            req: Exposed<RunRequest, ()>,
            bundle: crate::BundleSource,
            callbacks: C,
        ) -> Result<Untrusted<RunStatus, C::Scope>, ExecError>
        where
            C: CallbackServiceUntrusted + Send + Sync + 'static,
            C::Scope: Send,
        {
            let (stream, writer) = BundleStream::split(bundle);
            let mut call = std::pin::pin!(self.client.run_with_bundle(
                req.into_inner(),
                stream,
                callback_client(callbacks, self.callback_buffer)
            ));
            // The reply is the round's outcome and the writer's never is: a worker
            // that already holds this composition never reads the stream, and one
            // that refused it stopped reading. Driven here rather than spawned, so
            // the writer cannot outlive the round however the round ends.
            let reply = tokio::select! {
                reply = &mut call => reply,
                () = writer => call.await,
            };
            reply
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
    S: crate::untrusted_compile::CompilerServiceUntrusted + Send + Sync + 'static,
    S::Scope: Send,
    R: AsyncRead + Send + Sync + Unpin + 'static,
    W: AsyncWrite + Send + Sync + Unpin + 'static,
{
    use crate::compile::{CompilerServiceClient, CompilerServiceServerShared};
    type Cli = CompilerServiceClient<Ciborium>;

    let (conn, mut tx, _rx) =
        remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(crate::connection_cfg(leg), read, write)
            .await
            .map_err(|_| LegError::Rpc)?;
    tokio::spawn(conn);

    let (server, client) = CompilerServiceServerShared::<_, Ciborium>::new(
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
    use crate::compile::CompilerServiceClient;
    type Cli = CompilerServiceClient<Ciborium>;

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
    crate::compile::CompilerServiceClient<Ciborium>,
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
    /// The answer comes back `Untrusted`. Nothing binds it to the question — this
    /// side cannot re-derive it (it carries no Cranelift, by design) and a digest
    /// the peer also chose would be its word twice — so the wrapper is where that
    /// gets said rather than assumed.
    pub async fn compile(
        &self,
        req: enclavid_boundary::Exposed<crate::compile::CompileSource, ()>,
    ) -> Result<enclavid_boundary::Untrusted<crate::CompileReply, S>, crate::CompileError> {
        use crate::compile::CompilerService as _;
        let (request, writer) = req.into_inner().split();
        let mut call = std::pin::pin!(self.0.compile(request));
        // The reply comes once the components were read, or once the worker
        // gave up on them; the writer is never the outcome. Driven here rather
        // than spawned, so it cannot outlive the call however the call ends.
        let reply = tokio::select! {
            reply = &mut call => reply,
            () = writer => call.await,
        };
        reply.map(enclavid_boundary::Untrusted::new)
    }
}

/// The execute door end to end: `connect_executor` on one side, `serve_executor`
/// on the other, the real connection config between them.
#[cfg(all(test, feature = "execute"))]
mod door_tests {
    use enclavid_boundary::{AuthN, Exposed, Untrusted, reason};
    use hatch_client::{
        Clip, Decision, Event, MAX_CLIP_BYTES, MAX_CLIP_FRAMES, MediaResult, SessionState,
    };
    use remoc::codec::Ciborium;

    use super::{
        DEFAULT_CALLBACK_REQUEST_BUFFER, DEFAULT_REQUEST_BUFFER, ExecutorLeg, connect_executor,
        serve_executor,
    };
    use crate::bundle::{CompiledBundle, sample_bundle};
    use crate::execute::{
        CallbackError, CallbackServiceClient, ExecError, RunOutcome, RunReply, RunRequest,
        RunStatus,
    };
    use crate::keys::CompositionKey;
    use crate::padded::{Framed, Padded};
    use crate::stream::BundleStream;
    use crate::untrusted_execute::{CallbackServiceUntrusted, ExecutorServiceUntrusted};

    /// A worker that checks the bundle it is sent against `expect`, or — with
    /// `None` — never reads it at all, as a worker that already holds the
    /// composition does.
    struct FakeWorker {
        expect: Option<Vec<u8>>,
    }

    impl ExecutorServiceUntrusted for FakeWorker {
        type Scope = (AuthN,);

        async fn run(
            &self,
            _req: Untrusted<RunRequest, Self::Scope>,
            _callbacks: CallbackServiceClient<Ciborium>,
        ) -> Result<Exposed<RunOutcome, ()>, ExecError> {
            Err(ExecError::Unknown)
        }

        async fn run_with_bundle(
            &self,
            req: Untrusted<RunRequest, Self::Scope>,
            bundle: Untrusted<BundleStream, Self::Scope>,
            _callbacks: CallbackServiceClient<Ciborium>,
        ) -> Result<Exposed<RunReply, ()>, ExecError> {
            let _ = req
                .trust_unchecked::<AuthN, _>(reason!("test fixture"))
                .into_inner();
            let bundle = bundle
                .trust_unchecked::<AuthN, _>(reason!("test fixture"))
                .into_inner();
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
            Ok(Exposed::<_, (AuthN,)>::new(reply)
                .vouch_unchecked::<AuthN, _>(reason!("test fixture")))
        }
    }

    struct NoCallbacks;

    impl CallbackServiceUntrusted for NoCallbacks {
        type Scope = (AuthN,);

        async fn media_load(
            &self,
            _hash: Untrusted<[u8; 32], Self::Scope>,
        ) -> Result<Exposed<Option<Vec<u8>>, ()>, CallbackError> {
            Err(CallbackError)
        }

        async fn session_change(
            &self,
            _state: Untrusted<Padded<SessionState>, Self::Scope>,
            _decision: Untrusted<Padded<Option<Decision>>, Self::Scope>,
        ) -> Result<(), CallbackError> {
            Err(CallbackError)
        }
    }

    async fn leg(worker: FakeWorker) -> ExecutorLeg {
        let (a, b) = tokio::io::duplex(1 << 20);
        let (ar, aw) = tokio::io::split(a);
        let (br, bw) = tokio::io::split(b);
        let settings = crate::LegSettings::default();
        tokio::spawn(async move {
            let _ = serve_executor(ar, aw, worker, DEFAULT_REQUEST_BUFFER, &settings).await;
        });
        let (leg, _ended) = connect_executor(br, bw, &settings, DEFAULT_CALLBACK_REQUEST_BUFFER)
            .await
            .expect("the leg comes up");
        leg
    }

    fn round(event: Event) -> Exposed<RunRequest, ()> {
        Exposed::<_, (AuthN,)>::new(RunRequest {
            composition_key: CompositionKey::from_digest([0x22; 32]),
            props: Vec::new(),
            session_state: Padded::seal(&SessionState::default()).expect("fits the frame"),
            event,
        })
        .vouch_unchecked::<AuthN, _>(reason!("test fixture"))
    }

    fn approved(status: Result<Untrusted<RunStatus, (AuthN,)>, ExecError>) -> bool {
        matches!(
            status.map(|s| s
                .trust_unchecked::<AuthN, _>(reason!("test fixture"))
                .into_inner()),
            Ok(RunStatus::Completed(Decision::Approved))
        )
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
