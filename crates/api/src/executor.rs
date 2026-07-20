//! The EXECUTE boundary: drive ONE reducer round on a remote execution-worker.
//! api NEVER runs wasm in-process — it always drives an execution-worker over
//! rpc, so the api binary links NO wasmtime runtime (and no Cranelift).
//!
//! [`Executor`] wraps the `engine_rpc::ExecutorService` client. The worker is a
//! separate process/CVM started by INFRASTRUCTURE (docker-compose / k8s), not
//! by api — exactly like the hatch and the compile-worker. api
//! [`connect`](connect_execution_worker)s to it at a configured address (TCP in
//! dev, a vsock-relay rendezvous under RA-TLS in Plan-A).
//!
//! Per round api stands up a `CallbackService` server (`load_component` /
//! `media_load` / `session_change`) on the SAME connection and passes its client
//! into [`run`](Executor::run), so the KEYLESS worker calls back for compiled-
//! bundle resolution + blob rehydration + state persistence without ever holding
//! the seal key (remoc multiplexes the callbacks over the in-flight run — no
//! hand-rolled duplex). The worker owns the in-memory L1 of components and PULLS
//! the bundle via `load_component` on a miss; the run request carries no bundle.

use std::sync::Arc;

use hatch_client::{Event, SessionState};
use remoc::codec::Ciborium;
// `ServerShared` (the trait) is in scope so `CallbackServiceServerShared::new`
// resolves — the per-run callback server we hand the worker.
use remoc::rtc::ServerShared;
// `CallbackService` / `ExecutorService` (the remoc traits) are in scope so the
// generated client's `.run()` + the callback server resolve.
use engine_rpc::{
    CallbackService, CallbackServiceServerShared, ExecError, ExecutorService,
    ExecutorServiceClient, Prop, RunReply, RunRequest, RunStatus,
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

    /// Drive one reducer round on the worker. `callbacks` is the api-served
    /// `CallbackService` the keyless worker calls back into — including
    /// `load_component`, which the worker uses to pull the compiled bundle on an
    /// L1 miss (so the run request carries no bundle). Returns the round's
    /// [`RunStatus`]; state persistence already happened via the callback, so the
    /// engine's returned state is discarded worker-side.
    pub async fn run<C>(
        &self,
        composition_key: &str,
        session_state: SessionState,
        event: Event,
        props: Vec<(String, Prop)>,
        callbacks: Arc<C>,
    ) -> Result<RunStatus, ExecError>
    where
        C: CallbackService + Send + Sync + 'static,
    {
        // Stand up the per-run callback server on the same connection. It
        // self-terminates once the client we pass into `run` and our copy both
        // drop (after this fn returns), so no task leaks per round.
        let (cb_server, cb_client) =
            CallbackServiceServerShared::<_, Ciborium>::new(callbacks, CALLBACK_CONCURRENCY);
        tokio::spawn(async move {
            let _ = cb_server.serve(true).await;
        });

        let req = RunRequest {
            composition_key: composition_key.to_string(),
            props,
            session_state,
            event,
        };
        self.client
            .run(req, cb_client)
            .await
            .map(|RunReply { status }| status)
    }
}

/// Connect to an execution-worker already listening at `addr` and hand back an
/// [`Executor`] client. Mirrors `connect_compile_worker`: the worker is
/// infra-started, not spawned by api; the transport is a direct TCP dial today,
/// swapped for the host vsock-relay rendezvous + RA-TLS under Plan-A. The worker
/// sends us its service client on the base channel once connected.
pub async fn connect_execution_worker(addr: &str) -> Result<Executor, String> {
    type Cli = ExecutorServiceClient<Ciborium>;

    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| format!("connect execution-worker at `{addr}`: {e}"))?;
    let (read, write) = stream.into_split();

    let (conn, _tx, mut rx) =
        remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(engine_rpc::connection_cfg(), read, write)
            .await
            .map_err(|e| format!("execution-worker remoc connect: {e}"))?;
    tokio::spawn(conn);

    let client = rx
        .recv()
        .await
        .map_err(|e| format!("execution-worker recv client: {e}"))?
        .ok_or("execution-worker closed before sending its service client")?;

    Ok(Executor::new(client))
}
