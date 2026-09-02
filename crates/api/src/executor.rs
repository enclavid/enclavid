//! The EXECUTE boundary: drive ONE reducer round on a remote execution-worker.
//! api NEVER runs wasm in-process — it always drives an execution-worker over
//! rpc, so the api binary links NO wasmtime runtime (and no Cranelift).
//!
//! [`Executor`] wraps the `engine_rpc::ExecutorService` client. The worker is a
//! separate CVM, brought up at boot rather than by api. api
//! [`connect`](connect_execution_worker)s to it at a configured address, under
//! mutual RA-TLS; the transport is TCP by default and vsock under that feature.
//!
//! Per round api stands up a `CallbackService` server (`load_component` /
//! `media_load` / `session_change`) on the SAME connection and passes its client
//! into [`run`](Executor::run), so the KEYLESS worker calls back for compiled-
//! bundle resolution + blob rehydration + state persistence without ever holding
//! the seal key (remoc multiplexes the callbacks over the in-flight run — no
//! hand-rolled duplex). The worker owns the in-memory L1 of components and PULLS
//! the bundle via `load_component` on a miss; the run request carries no bundle.

use std::sync::Arc;

use remoc::codec::Ciborium;
// `ServerShared` (the trait) is in scope so `CallbackServiceServerShared::new`
// resolves — the per-run callback server we hand the worker.
use fleet_transport::LegFailure;
use remoc::rtc::ServerShared;
use safe_logger::debug;
// `CallbackService` / `ExecutorService` (the remoc traits) are in scope so the
// generated client's `.run()` + the callback server resolve.
use engine_rpc::{
    CallbackService, CallbackServiceClient, CallbackServiceServerShared, CompiledBundle, ExecError,
    ExecutorService, ExecutorServiceClient, RunOutcome, RunReply, RunRequest, RunStatus,
};

/// Concurrent callback invocations the per-run CallbackService server handles.
/// `media_load` / `session_change` are serialized by the run in practice (one
/// round at a time), so a small pool is ample.
const CALLBACK_CONCURRENCY: usize = 4;

/// The EXECUTE boundary: a client for an execution-worker's
/// `engine_rpc::ExecutorService`. A cheap remoc handle (`Send + Sync`); concurrent
/// rounds multiplex over the one connection.
pub struct Executor {
    client: ExecutorServiceClient<Ciborium>,
}

impl Executor {
    pub fn new(client: ExecutorServiceClient<Ciborium>) -> Self {
        Self { client }
    }

    /// Cache-only attempt: try to run from the worker's L1. `Ran` on a hit;
    /// [`RunOutcome::CacheMiss`] on a miss, at which point the caller resolves the
    /// bundle under ITS OWN `composition_key` and calls
    /// [`run_with_bundle`](Self::run_with_bundle). The two-phase loop lives in the
    /// caller (`SessionRunCtx::run`), so bundle resolution stays with the
    /// key-holding orchestrator, never the worker.
    pub async fn run<C>(&self, req: RunRequest, callbacks: Arc<C>) -> Result<RunOutcome, ExecError>
    where
        C: CallbackService + Send + Sync + 'static,
    {
        self.client.run(req, Self::callback_client(callbacks)).await
    }

    /// Post-miss attempt: hand the worker the `bundle` we resolved under
    /// `req.composition_key`; it files it in L1 under that key and runs. Always runs
    /// (a bundle is in hand), so this returns the round's `RunStatus` directly.
    pub async fn run_with_bundle<C>(
        &self,
        req: RunRequest,
        bundle: CompiledBundle,
        callbacks: Arc<C>,
    ) -> Result<RunStatus, ExecError>
    where
        C: CallbackService + Send + Sync + 'static,
    {
        self.client
            .run_with_bundle(req, bundle, Self::callback_client(callbacks))
            .await
            .map(|RunReply { status }| status)
    }

    /// Stand up the per-call `CallbackService` server (media_load / session_change)
    /// on the connection and hand back its client. It self-terminates once the
    /// client we pass into the RPC and this copy both drop (after the call returns),
    /// so no task leaks per attempt.
    fn callback_client<C>(callbacks: Arc<C>) -> CallbackServiceClient<Ciborium>
    where
        C: CallbackService + Send + Sync + 'static,
    {
        let (cb_server, cb_client) =
            CallbackServiceServerShared::<_, Ciborium>::new(callbacks, CALLBACK_CONCURRENCY);
        tokio::spawn(async move {
            let _ = cb_server.serve(true).await;
        });
        cb_client
    }
}

/// Connect to an execution-worker already listening at `addr` and hand back an
/// [`Executor`] client. Mirrors `connect_compile_worker`: the worker is
/// infra-started, not spawned by api; the transport is a direct TCP dial today,
/// swapped for the host vsock-relay rendezvous + RA-TLS under Plan-A. The worker
/// sends us its service client on the base channel once connected.
pub async fn connect_execution_worker(
    addr: &str,
    attestor: std::sync::Arc<dyn enclavid_attestation::Attestor>,
) -> Result<Executor, LegFailure> {
    type Cli = ExecutorServiceClient<Ciborium>;

    let stream = fleet_transport::dial(addr).await.map_err(|e| {
        debug!("connect {addr}: {e}");
        LegFailure::Connect(e.kind())
    })?;
    // Mutual RA-TLS over the dial: we attest the worker's cert (pinned measurement)
    // and present our own attested cert. A completed handshake proves the peer is the
    // pinned execution-worker measurement — no CA, no post-handshake window.
    let config = crate::endorsement::fleet_client_config(attestor).map_err(|e| {
        debug!("ra-tls: {e}");
        LegFailure::Attest
    })?;
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let tls = connector
        .connect(enclavid_ra_tls::server_name(), stream)
        .await
        .map_err(|e| {
            debug!("ra-tls: {e}");
            LegFailure::Attest
        })?;
    let (read, write) = tokio::io::split(tls);

    let (conn, _tx, mut rx) =
        remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(engine_rpc::connection_cfg(), read, write)
            .await
            .map_err(|e| {
                debug!("rpc connect: {e}");
                LegFailure::Rpc
            })?;
    crate::fleet::watch(conn, "execution-worker");

    let client = rx
        .recv()
        .await
        .map_err(|e| {
            debug!("recv clients: {e}");
            LegFailure::Clients
        })?
        .ok_or(LegFailure::Closed)?;

    Ok(Executor::new(client))
}
