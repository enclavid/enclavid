//! The EXECUTE boundary: drive ONE reducer round on a remote execution-worker.
//! api NEVER runs wasm in-process — it always drives an execution-worker over
//! rpc, so the api binary links NO wasmtime runtime (and no Cranelift).
//!
//! [`Executor`] wraps the `engine_rpc::RemoteExecutor` client. The worker is a
//! separate CVM, brought up at boot rather than by api. api
//! [`connect`](connect_execution_worker)s to it at a configured address, under
//! mutual RA-TLS; the transport is TCP by default and vsock under that feature.
//!
//! Per round api stands up a `RemoteCallbacks` server (`media_load` /
//! `session_change`) on the SAME connection and passes its client into
//! [`run`](Executor::run), so the KEYLESS worker rehydrates blobs and persists
//! state without ever holding the seal key (remoc multiplexes the callbacks over
//! the in-flight run — no hand-rolled duplex).
//!
//! Bundle resolution is NOT among them. The worker owns the in-memory L1 of
//! components; on a miss it returns `RunOutcome::CacheMiss` and runs nothing,
//! and api resolves the bundle under its own key before calling
//! [`run_with_bundle`](Executor::run_with_bundle). The keyless side never asks
//! the key-holding side for a composition.
//!
//! Preparing a session takes the same two calls with no round
//! ([`prepare`](Executor::prepare)): it fills the worker's L1 ahead of the
//! session's rounds, and has the props read against the type the composition
//! declares for them.

use enclavid_boundary::{Asserted, AuthZ, Covert, Exposed, Untrusted, reason};
use engine_rpc::{
    BundleSource, CompositionKey, ExecError, ExecutorLeg, MediaBytes, Padded, Preparation,
    PrepareRequest, Preparing, PropsRead, RemoteCallbacksAt, RoundProps, RunOutcome, RunRequest,
    RunStatus,
};
use fleet_transport::LegFailure;
use safe_logger::debug;
use session_types::{Event, SessionState};

use crate::boundary::ExecutionWorker;

/// Mint a round's request — the only way one reaches an execution-worker, and
/// the receipt `ExecutorLeg::run` and `run_with_bundle` demand.
///
/// One mint for the whole message, so every field it carries is answered here
/// and none rides in on another's receipt. `AuthN` is this end's declaration's
/// (`crate::boundary::ExecutionWorker`); `AuthZ` and `Covert` are answered here,
/// because the fields answer them differently.
///
/// `AuthZ` is MATCHED, upstream, and the reason covers the five fields:
///
///   * the event is the reply sent under the bearer that opened this session's
///     state (`round::extract`), and it goes to the runner of this session's
///     policy, whose prompt it answers;
///   * the state, the props, the key and the ceiling are the peer's own: the
///     state is what it wrote on the session's previous round, or the empty one
///     genesis starts from; the props are what its preparation read; the key
///     names the composition it is handed on every miss; the ceiling is the
///     session's terms.
///
/// `Covert` is closed by the work for the two fields whose length the policy
/// chooses — the state, and the props as read against its type: the work's
/// codomain IS the wire type, so no `RunRequest` exists whose frames skipped the
/// padding. The other three are not framed, and the reason for each is that
/// nobody with something to hide chose its shape:
///
///   * the event is `Start`, a consent reply of one bit, or the applicant's own
///     capture, whose length the host watched arrive as the request it came in;
///   * the key is 64 hex characters api computed before any round ran;
///   * the ceiling is the session's terms, which the operator's limits gave at
///     its creation.
pub(crate) fn outbound_round(
    composition_key: &CompositionKey,
    max_cwasm_bytes: u64,
    state: &SessionState,
    props: Option<&str>,
    event: Event,
) -> Result<Exposed<RunRequest, (), ExecutionWorker>, ExecError> {
    let props = RoundProps(props.map(str::as_bytes).unwrap_or_default().to_vec());
    Ok(ExecutionWorker::expose_builder::<RunRequest, _>((
        composition_key,
        max_cwasm_bytes,
        state,
        props,
        event,
    ))
    .vouch(reason!(
        AuthZ::Matched,
        "the event is the reply sent under the bearer that opened this session's state, \
         to the runner of the policy whose prompt it answers; the rest is this peer's own \
         prior output, what its preparation read, the key it is handed on every miss, and \
         the session's terms"
    ))
    .vouch_with(
        Covert::Transformed,
        |(composition_key, max_cwasm_bytes, state, props, event)| {
            Ok::<_, engine_rpc::FrameError>(RunRequest {
                composition_key: composition_key.clone(),
                max_cwasm_bytes,
                props: Padded::seal(&props)?,
                session_state: Padded::seal(state)?,
                event,
            })
        },
    )?
    .build())
}

/// Mint a rehydrated blob as a released value — the ONE thing api hands back to
/// the process that runs adversary-authored wasm, and the only value on this leg
/// that is not framed. `crate::applicant::media_store` calls it once its
/// captured-hash gate has admitted the hash.
///
/// These are the applicant's own pixels, going out over the hop the host splices,
/// whose `AuthN` this end's declaration answers. Two answers here, and the last
/// is the one worth reading twice because it is why there is no frame:
///
///   * `AuthZ` — SCOPED, by the captured-hash gate rather than by a sentence: the
///     only blobs nameable are ones this session stored, and a hash outside that
///     set never reaches a store read at all.
///   * `Covert` — ALREADY-HELD. Media is sealed to the host WITHOUT padding, under
///     an HKDF name derived from `(session, hash)`, so the host held this blob's
///     exact length and saw the read before this hop carried anything.
///
/// The residual under that last one is real and bounded: WHICH of this session's
/// own blobs a round fetched. The gate bounds the set, the worker's per-run memo
/// bounds repeats within a round, and the applicant's round count bounds the rest.
pub(crate) fn outbound_blob(
    loaded: Option<Vec<u8>>,
) -> Exposed<Option<MediaBytes>, (), ExecutionWorker> {
    ExecutionWorker::expose(loaded.map(MediaBytes))
        .vouch(reason!(
            AuthZ::Scoped,
            "the captured-hash gate admits only blobs THIS session stored, so the set this \
             peer can name is the applicant's own frames and nothing else"
        ))
        .vouch(reason!(
            Covert::AlreadyHeld,
            "media is sealed to the host WITHOUT padding under an HKDF name derived from \
             (session, hash), so it held this blob's exact length and saw the read before \
             this hop carried anything"
        ))
}

/// The EXECUTE boundary: a client for an execution-worker's
/// `engine_rpc::RemoteExecutor`, held at api's end of the leg
/// ([`ExecutionWorker`]). A cheap remoc handle (`Send + Sync`); concurrent rounds
/// multiplex over the one connection.
pub struct Executor {
    leg: std::sync::Arc<crate::fleet::Leg<std::sync::Arc<ExecutorLeg<ExecutionWorker>>>>,
}

impl Executor {
    pub fn new(
        leg: std::sync::Arc<crate::fleet::Leg<std::sync::Arc<ExecutorLeg<ExecutionWorker>>>>,
    ) -> Self {
        Self { leg }
    }

    /// The client, or the leg's own failure. A request arriving during an outage
    /// fails rather than waits: how long to wait for a peer is the host's
    /// decision, and the health port is already telling it which leg is down.
    fn client(&self) -> Result<std::sync::Arc<ExecutorLeg<ExecutionWorker>>, ExecError> {
        // api's OWN error, built here and never crossing the wire — which is why
        // the contract needs no variant for it. Whatever this side must tell apart
        // it can tell apart at the point it knows.
        self.leg.get().ok_or(ExecError::Unknown)
    }

    /// Cache-only attempt: try to run from the worker's L1. `Ran` on a hit;
    /// [`RunOutcome::CacheMiss`] on a miss, at which point the caller resolves the
    /// bundle under ITS OWN `composition_key` and calls
    /// [`run_with_bundle`](Self::run_with_bundle). The two-phase loop lives in the
    /// caller (`SessionRunCtx::run`), so bundle resolution stays with the
    /// key-holding orchestrator, never the worker.
    pub async fn run<C>(
        &self,
        req: Exposed<RunRequest, (), ExecutionWorker>,
        callbacks: C,
    ) -> Result<Untrusted<RunOutcome, (), ExecutionWorker>, ExecError>
    where
        C: RemoteCallbacksAt<ExecutionWorker> + Send + Sync + 'static,
    {
        self.client()?.run(req, callbacks).await
    }

    /// Post-miss attempt: hand the worker the `bundle` we resolved under
    /// `req.composition_key`; it files it in L1 under that key and runs. Always runs
    /// (a bundle is in hand), so this returns the round's `RunStatus` directly.
    /// The bundle streams beside the request (`engine_rpc::BundleStream`), written
    /// by the door in this process while the call is awaited — from memory after
    /// a compile, from the cache on an L2 hit.
    pub async fn run_with_bundle<C>(
        &self,
        req: Exposed<RunRequest, (), ExecutionWorker>,
        bundle: BundleSource,
        callbacks: C,
    ) -> Result<Untrusted<RunStatus, (), ExecutionWorker>, ExecError>
    where
        C: RemoteCallbacksAt<ExecutionWorker> + Send + Sync + 'static,
    {
        self.client()?.run_with_bundle(req, bundle, callbacks).await
    }

    /// Cache-only attempt at preparing a session: hold its composition, and read
    /// its props if asked. What the worker read on a hit, or its ABI id on a
    /// miss, at which point the caller resolves the bundle as a round does and
    /// calls [`prepare_with_bundle`](Self::prepare_with_bundle). Both are the
    /// worker's word, and api's end leaves them open (`crate::boundary`): the two
    /// halves are judged where they are used.
    pub async fn prepare(
        &self,
        req: Exposed<PrepareRequest, (), ExecutionWorker>,
    ) -> Result<Preparation<(Asserted,), ExecutionWorker>, ExecError> {
        self.client()?.prepare(req).await
    }

    /// Post-miss attempt at preparing a session, with the bundle resolved under
    /// `req.composition_key`, which crosses as a round's does.
    pub async fn prepare_with_bundle(
        &self,
        req: Exposed<PrepareRequest, (), ExecutionWorker>,
        bundle: BundleSource,
    ) -> Result<Untrusted<PropsRead, (Asserted,), ExecutionWorker>, ExecError> {
        self.client()?.prepare_with_bundle(req, bundle).await
    }
}

/// Mint a session's preparation — the only way one reaches an execution-worker.
///
/// Every concern on it is answered by this end's declaration
/// (`crate::boundary::ExecutionWorker`), because every preparation answers them
/// alike: the props, the key and the ceiling are what every round of the session
/// hands the same peer, and their lengths are the consumer's and the operator's,
/// all seen by the host before the session had a round.
pub(crate) fn outbound_preparation(
    composition_key: &CompositionKey,
    max_cwasm_bytes: u64,
    preparing: Preparing,
) -> Exposed<PrepareRequest, (), ExecutionWorker> {
    ExecutionWorker::expose(PrepareRequest {
        composition_key: composition_key.clone(),
        max_cwasm_bytes,
        preparing,
    })
}

/// Connect to an execution-worker already listening at `addr` and hand back an
/// [`Executor`] client. Mirrors `connect_compile_worker`: the worker is
/// infra-started, not spawned by api; the transport is a direct TCP dial today,
/// swapped for the host vsock-relay rendezvous + RA-TLS under Plan-A. The worker
/// sends us its service client on the base channel once connected. `leg` is this
/// end of the connection, and `callback_buffer` how many of a round's callbacks
/// may wait for its server.
pub async fn connect_execution_worker(
    addr: &str,
    attestor: std::sync::Arc<dyn enclavid_attestation::Attestor>,
    leg: engine_rpc::LegSettings,
    callback_buffer: usize,
) -> Result<
    (
        std::sync::Arc<ExecutorLeg<ExecutionWorker>>,
        tokio::task::JoinHandle<()>,
    ),
    LegFailure,
> {
    let stream = fleet_transport::dial(addr).await.map_err(|e| {
        debug!("connect {addr}: {e}");
        LegFailure::Connect(e.kind())
    })?;
    // Mutual RA-TLS over the dial: we attest the worker's cert (pinned measurement)
    // and present our own attested cert. A completed handshake proves the peer is the
    // pinned execution-worker measurement — no CA, no post-handshake window.
    let config =
        crate::endorsement::fleet_client_config(attestor, crate::health::Peer::ExecutionWorker)
            .map_err(|e| {
                debug!("ra-tls: {e}");
                LegFailure::Mint
            })?;
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let tls = connector
        .connect(enclavid_ra_tls::fresh_server_name(), stream)
        .await
        .map_err(|e| {
            debug!("ra-tls: {e}");
            // A peer that attested to the wrong image is the failure this fleet
            // is most likely to see, and the one `Attest` said least about.
            match enclavid_ra_tls::pin_mismatch(&e)
                .and_then(|p| fleet_transport::Measurement::parse(&p.presented))
            {
                Some(m) => LegFailure::Pin(m),
                None => LegFailure::Attest,
            }
        })?;
    let (read, write) = tokio::io::split(tls);

    // Everything above this line is WHO — the dial, the pins, what a refusal
    // means. Everything below is WHAT MAY CROSS, and that is engine-rpc's: it
    // brings the hop up and keeps the generated client, which api has no name for.
    // How api judges what crosses is its end's declaration, `ExecutionWorker`.
    let (leg, driver) =
        engine_rpc::connect_executor::<ExecutionWorker, _, _>(read, write, &leg, callback_buffer)
            .await
            .map_err(|e| {
                debug!("execute leg: {e}");
                match e {
                    engine_rpc::LegError::Rpc => LegFailure::Rpc,
                    engine_rpc::LegError::Clients | engine_rpc::LegError::Serve => {
                        LegFailure::Clients
                    }
                    engine_rpc::LegError::Closed => LegFailure::Closed,
                }
            })?;

    Ok((std::sync::Arc::new(leg), driver))
}
