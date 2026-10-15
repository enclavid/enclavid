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
use hatch_client::SessionState;
use safe_logger::debug;

/// What is still open on a value api is about to release to a worker CVM.
///
/// Declared here rather than taken from `hatch_client::boundary::outbound`: that
/// facade is the TEE↔host wire perimeter and owns the answers that crossing
/// raises. A scope is a property of the CHANNEL, so this leg names its own.
type ToWorker<T> = Exposed<T, (AuthN, AuthZ, Covert)>;

/// Mint the round's prior state as a fully-vouched, constant-size frame — the
/// only way a `SessionState` reaches an execution-worker.
///
/// NOT a generic "anything crossing to a worker" mint, on the same reasoning as
/// `outbound_session_id`: it is specific to this value so the audited answers live
/// in one place (grep `outbound_round_state(`) instead of being restated at each
/// call, where they would be the same two sentences forever.
///
/// `AuthN` is IDENTIFIED and `AuthZ` is NO-SECRET, and the two rest on different
/// facts even though both are settled once for the whole leg. `AuthN`'s is the
/// dial: one compile-time-pinned measurement, checked at the handshake. `AuthZ`'s
/// is what this VALUE is — the peer's own prior output, which it wrote on the
/// previous round's `session_change` and is now being handed back.
///
/// `Covert` is the only axis that differs per value, and it is the only one
/// discharged by doing the work rather than by naming a fact: the peel's codomain
/// IS the wire type, so a caller cannot get a `RunRequest` field out of this
/// without the padding having happened.
///
/// The wrapper is RETURNED rather than unwrapped here, and that is what keeps it
/// from being decoration. `ExecutorLeg::run` demands `Exposed<RunRequest, ()>`,
/// and that type cannot be constructed — only arrived at, by peeling every
/// concern this mint opened — so the receipt has to survive across the crate line
/// to the door.
pub(crate) fn outbound_round_state(
    state: &SessionState,
) -> Result<Exposed<Padded<SessionState>, ()>, ExecError> {
    let framed: ToWorker<&SessionState> = Exposed::new(state);
    Ok(framed
        .vouch_unchecked::<AuthN, _>(reason!(
            "identified: this leg dials ONE compile-time-pinned measurement, and the \
             handshake fails before a byte moves if the peer is not it"
        ))
        .vouch_unchecked::<AuthZ, _>(reason!(
            "no-secret: this is the peer's OWN prior output coming back — it authored \
             these bytes on the previous round's session_change, so the release \
             hands it nothing it did not already hold"
        ))
        .vouch::<Covert, _, _, _, _>(Padded::seal)?)
}

/// Mint a round's props — the WAVE its session's preparation wrote, `None` for a
/// composition that declares none — as a constant-size frame, the only way they
/// reach an execution-worker.
///
/// `AuthN` is IDENTIFIED, as for the state. `AuthZ` is NO-SECRET: the worker's
/// own output, from the preparation, handed back to the same peer. `Covert` is
/// TRANSFORMED, done by the peel: as read, the props' length is their type's
/// and their own.
pub(crate) fn outbound_round_props(props: Option<&str>) -> Result<Padded<RoundProps>, ExecError> {
    let props = RoundProps(props.map(str::as_bytes).unwrap_or_default().to_vec());
    let framed: ToWorker<RoundProps> = Exposed::new(props);
    Ok(framed
        .vouch_unchecked::<AuthN, _>(reason!(
            "identified: this leg dials ONE compile-time-pinned measurement, and the \
             handshake fails before a byte moves if the peer is not it"
        ))
        .vouch_unchecked::<AuthZ, _>(reason!(
            "no-secret: the props as a preparation's worker wrote them, handed back to \
             the same peer"
        ))
        .vouch::<Covert, _, _, _, _>(|props| Padded::seal(&props))?
        .into_inner())
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
/// `AuthN` is IDENTIFIED, as for a round. `AuthZ` is NO-SECRET: the props are
/// the ones every round of the session hands this same peer, as WAVE once
/// read, and the key names the composition it is handed on every miss.
/// `Covert` is ALREADY-HELD: the props are the consumer's JSON, whose length
/// the host saw on the request that created the session, and nothing of the
/// applicant's is in it — a session is prepared before any of its rounds.
pub(crate) fn outbound_preparation(
    composition_key: &CompositionKey,
    preparing: Preparing,
) -> Exposed<PrepareRequest, ()> {
    let open: ToWorker<PrepareRequest> = Exposed::new(PrepareRequest {
        composition_key: composition_key.clone(),
        preparing,
    });
    open.vouch_unchecked::<AuthN, _>(reason!(
        "identified: this leg dials ONE compile-time-pinned measurement, and the \
         handshake fails before a byte moves if the peer is not it"
    ))
    .vouch_unchecked::<AuthZ, _>(reason!(
        "no-secret: the props every round of this session hands the same peer, and \
         the key it is handed on every miss"
    ))
    .vouch_unchecked::<Covert, _>(reason!(
        "already-held: the consumer's own props, whose length the host saw when the \
         session was created; nothing of an applicant's is in them"
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
