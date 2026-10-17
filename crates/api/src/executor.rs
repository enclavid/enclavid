//! The EXECUTE boundary: drive ONE reducer round on a remote execution-worker.
//! api NEVER runs wasm in-process — it always drives an execution-worker over
//! rpc, so the api binary links NO wasmtime runtime (and no Cranelift).
//!
//! [`Executor`] wraps the `engine_rpc::ExecutorService` client. The worker is a
//! separate CVM, brought up at boot rather than by api. api
//! [`connect`](connect_execution_worker)s to it at a configured address, under
//! mutual RA-TLS; the transport is TCP by default and vsock under that feature.
//!
//! Per round api stands up a `CallbackService` server (`media_load` /
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

use enclavid_boundary::{Asserted, AuthN, AuthZ, Covert, Exposed, Untrusted, reason};
use engine_rpc::{
    BundleSource, CallbackServiceUntrusted, CompositionKey, ExecError, ExecutorLeg, Padded,
    Preparation, PrepareRequest, Preparing, PropsRead, RoundProps, RunOutcome, RunRequest,
    RunStatus,
};
use fleet_transport::LegFailure;
use safe_logger::debug;
use session_types::{Event, SessionState};

/// What is still open on a value api is about to release to the
/// execution-worker.
///
/// Declared here rather than taken from a client's `boundary::outbound`: those
/// facades are the host's, whose every byte the host reads. A scope is a property
/// of the CHANNEL, so this leg names its own.
type ToWorker<T> = Exposed<T, (AuthN, AuthZ, Covert)>;

/// Open a value for the execution-worker with the leg's own answer given, so
/// what is left is what differs per message.
///
/// `AuthN` is IDENTIFIED, and it is the same for everything this leg carries — a
/// round, a preparation, a blob a round asked for: the leg dials one
/// compile-time-pinned measurement, and that peer keeps what it is handed in its
/// own memory, where the host that splices the hop cannot read it.
///
/// `AuthZ` and `Covert` stay open. What may go to the code that runs a consumer's
/// policy, and what a value's shape can carry, are answered value by value, by the
/// mints below. Private to this module, so its receipt reaches no other door.
fn to_worker<T>(value: T) -> Exposed<T, (AuthZ, Covert)> {
    let open: ToWorker<T> = Exposed::new(value);
    open.vouch_unchecked::<AuthN, _>(reason!(
        "identified: this leg dials ONE compile-time-pinned measurement, the handshake \
         fails before a byte moves if the peer is not it, and the peer keeps what it \
         is handed in its own memory"
    ))
}

/// Mint a round's request — the only way one reaches an execution-worker, and
/// the receipt `ExecutorLeg::run` and `run_with_bundle` demand.
///
/// One mint for the whole message, so every field it carries is answered here
/// and none rides in on another's receipt.
///
/// `AuthZ` takes one answer for the four fields, and it names the kind of each:
///
///   * the state, the props and the key are NO-SECRET: the state is what this
///     peer wrote on the session's previous round, or the empty one genesis
///     starts from; the props are what its preparation read; the key names the
///     composition it is handed on every miss;
///   * the event is MATCHED, upstream: it is the reply sent under the bearer that
///     opened this session's state (`round::extract`), and it goes to the runner
///     of this session's policy, whose prompt it answers.
///
/// `Covert` is closed by the work for the two fields whose length the policy
/// chooses — the state, and the props as read against its type: the peel's
/// codomain IS the wire type, so no `RunRequest` exists whose frames skipped the
/// padding. The other two are not framed, and the reason for each is that
/// nobody with something to hide chose its shape:
///
///   * the event is `Start`, a consent reply of one bit, or the applicant's own
///     capture, whose length the host watched arrive as the request it came in;
///   * the key is 64 hex characters api computed before any round ran.
pub(crate) fn outbound_round(
    composition_key: &CompositionKey,
    state: &SessionState,
    props: Option<&str>,
    event: Event,
) -> Result<Exposed<RunRequest, ()>, ExecError> {
    let props = RoundProps(props.map(str::as_bytes).unwrap_or_default().to_vec());
    Ok(to_worker((composition_key, state, props, event))
        .vouch_unchecked::<AuthZ, _>(reason!(
            "no-secret for the state, the props and the key — this peer's own prior \
             output or the empty genesis state, what its preparation read, and the key \
             it is handed on every miss; matched for the event — the reply sent under \
             the bearer that opened this session's state, to the runner of the policy \
             whose prompt it answers"
        ))
        .vouch::<Covert, _, _, _, _>(|(composition_key, state, props, event)| {
            Ok::<_, engine_rpc::FrameError>(RunRequest {
                composition_key: composition_key.clone(),
                props: Padded::seal(&props)?,
                session_state: Padded::seal(state)?,
                event,
            })
        })?)
}

/// Mint a rehydrated blob as a released value — the ONE thing api hands back to
/// the process that runs adversary-authored wasm, and the only value on this leg
/// that is not framed. `crate::applicant::media_store` calls it once its
/// captured-hash gate has admitted the hash.
///
/// These are the applicant's own pixels, going out over the hop the host splices,
/// whose `AuthN` the leg answers ([`to_worker`]). Two answers here, and the last
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
pub(crate) fn outbound_blob(loaded: Option<Vec<u8>>) -> Exposed<Option<Vec<u8>>, ()> {
    to_worker(loaded)
        .vouch_unchecked::<AuthZ, _>(reason!(
            "scoped: the captured-hash gate admits only blobs THIS session stored, so \
             the set this peer can name is the applicant's own frames and nothing else"
        ))
        .vouch_unchecked::<Covert, _>(reason!(
            "already-held: media is sealed to the host WITHOUT padding under an HKDF \
             name derived from (session, hash), so it held this blob's exact length \
             and saw the read before this hop carried anything"
        ))
}

/// The EXECUTE boundary: a client for an execution-worker's
/// `engine_rpc::ExecutorService`. A cheap remoc handle (`Send + Sync`); concurrent
/// rounds multiplex over the one connection.
pub struct Executor {
    leg: std::sync::Arc<crate::fleet::Leg<std::sync::Arc<ExecutorLeg>>>,
}

impl Executor {
    pub fn new(leg: std::sync::Arc<crate::fleet::Leg<std::sync::Arc<ExecutorLeg>>>) -> Self {
        Self { leg }
    }

    /// The client, or the leg's own failure. A request arriving during an outage
    /// fails rather than waits: how long to wait for a peer is the host's
    /// decision, and the health port is already telling it which leg is down.
    fn client(&self) -> Result<std::sync::Arc<ExecutorLeg>, ExecError> {
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
        req: Exposed<RunRequest, ()>,
        callbacks: C,
    ) -> Result<Untrusted<RunOutcome, C::Scope>, ExecError>
    where
        C: CallbackServiceUntrusted + Send + Sync + 'static,
        C::Scope: Send,
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
        req: Exposed<RunRequest, ()>,
        bundle: BundleSource,
        callbacks: C,
    ) -> Result<Untrusted<RunStatus, C::Scope>, ExecError>
    where
        C: CallbackServiceUntrusted + Send + Sync + 'static,
        C::Scope: Send,
    {
        self.client()?.run_with_bundle(req, bundle, callbacks).await
    }

    /// Cache-only attempt at preparing a session: hold its composition, and read
    /// its props if asked. What the worker read on a hit, or its ABI id on a
    /// miss, at which point the caller resolves the bundle as a round does and
    /// calls [`prepare_with_bundle`](Self::prepare_with_bundle). Both are the
    /// worker's word, judged as everything on this leg is (`WorkerScope` in
    /// `crate::applicant::callbacks`).
    pub async fn prepare(
        &self,
        req: Exposed<PrepareRequest, ()>,
    ) -> Result<Preparation<(Asserted,)>, ExecError> {
        self.client()?.prepare(req).await
    }

    /// Post-miss attempt at preparing a session, with the bundle resolved under
    /// `req.composition_key`, which crosses as a round's does.
    pub async fn prepare_with_bundle(
        &self,
        req: Exposed<PrepareRequest, ()>,
        bundle: BundleSource,
    ) -> Result<Untrusted<PropsRead, (Asserted,)>, ExecError> {
        self.client()?.prepare_with_bundle(req, bundle).await
    }
}

/// Mint a session's preparation as a fully-vouched request — the only way one
/// reaches an execution-worker.
///
/// `AuthZ` is NO-SECRET: the props are the ones every round of the session hands
/// this same peer, as WAVE once read, and the key names the composition it is
/// handed on every miss. `Covert` is ALREADY-HELD: the props are the consumer's
/// JSON, whose length the host saw on the request that created the session, and
/// nothing of the applicant's is in it — a session is prepared before any of its
/// rounds. The key beside them is 64 hex characters, whatever it names.
pub(crate) fn outbound_preparation(
    composition_key: &CompositionKey,
    preparing: Preparing,
) -> Exposed<PrepareRequest, ()> {
    to_worker(PrepareRequest {
        composition_key: composition_key.clone(),
        preparing,
    })
    .vouch_unchecked::<AuthZ, _>(reason!(
        "no-secret: the props every round of this session hands the same peer, and \
         the key it is handed on every miss"
    ))
    .vouch_unchecked::<Covert, _>(reason!(
        "already-held: the consumer's own props, whose length the host saw when the \
         session was created, beside a key of fixed length; nothing of an applicant's \
         is in either"
    ))
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
) -> Result<(std::sync::Arc<ExecutorLeg>, tokio::task::JoinHandle<()>), LegFailure> {
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
        .connect(enclavid_ra_tls::server_name(), stream)
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
    let (leg, driver) = engine_rpc::connect_executor(read, write, &leg, callback_buffer)
        .await
        .map_err(|e| {
            debug!("execute leg: {e}");
            match e {
                engine_rpc::LegError::Rpc => LegFailure::Rpc,
                engine_rpc::LegError::Clients | engine_rpc::LegError::Serve => LegFailure::Clients,
                engine_rpc::LegError::Closed => LegFailure::Closed,
            }
        })?;

    Ok((std::sync::Arc::new(leg), driver))
}
