//! The `execution-worker` deployable: the SUPERVISOR of the execute side.
//!
//! It LISTENS for the orchestrator (api) and serves `engine_rpc::ExecutorService`
//! — the same api-facing contract as before — but it runs NO wasm itself. Per
//! reducer round it drives a fresh `session-child` PROCESS (spawned + bounded +
//! deadline-guarded + reaped by the shared [`engine_supervisor::ChildPool`]), primes
//! it with the compiled bundle, drives exactly one round in it, and discards it.
//! Untrusted policy wasm and `Component::deserialize` execute ONLY in that
//! disposable per-round child, behind an OS address-space boundary — so a wasmtime
//! sandbox escape is confined to one round's plaintext (one applicant), with no
//! cross-round persistence and no cross-session bleed. Started by INFRASTRUCTURE
//! (docker-compose / k8s), exactly like the hatch and the compile-worker.
//!
//! **Keyless.** The supervisor holds no `tee_seal_key` and no applicant token.
//! Two hops carry the keyless callbacks:
//!   * api → supervisor: the orchestrator passes a `CallbackServiceClient` into
//!     [`run`](ExecutorService::run) (bundle resolution + blob rehydration + state
//!     persistence, all seal-key-side).
//!   * supervisor → child: the supervisor stands up a [`RelayCallbacks`] (a
//!     narrowed [`ChildCallbacks`], NO `load_component`) that forwards the child's
//!     `media_load` / `session_change` on to the api client — so the untrusted-
//!     wasm child gets blob + state I/O but never the seal key nor the OCI-pull /
//!     compile probe surface.
//!
//! **What is domain vs supervisor.** The generic process plumbing — spawn a
//! disposable child over a socketpair, bound concurrency, enforce the per-round
//! wall-clock DEADLINE (so a wedged child can't leak its slot), kill + reap —
//! lives in [`engine_supervisor::ChildPool`], shared with the compile-worker. What
//! stays HERE is the executor's domain: the bundle-byte L1 and the callback relay.
//!
//! **L1.** The supervisor owns the fleet's ONLY in-memory L1, holding bundle
//! BYTES (`composition_key -> Arc<CompiledBundle>`), NOT deserialized components —
//! a live `Component` can't cross a process boundary, and the
//! `Component::deserialize` unsafe sink must stay in the disposable child. On an
//! L1 miss it PULLS the bundle from api via `load_component` (`try_get_with`
//! coalesces concurrent misses into ONE pull) and hands a copy to each spawned
//! child to deserialize + prime.
//!
//! Transport TODAY: a plain TCP listener (dev) to api; Plan-A swaps it for the
//! host vsock-relay rendezvous + RA-TLS. The supervisor↔child hop is a private
//! per-child socketpair (never leaves this host).

use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use remoc::codec::Ciborium;
use remoc::rtc::ServerShared;
use tokio::net::{TcpListener, TcpStream};
use engine_supervisor::ChildPool;

use engine_executor::{SessionState, compat_token};
use engine_rpc::{
    CallbackError, CallbackService, CallbackServiceClient, ChildCallbacks,
    ChildCallbacksServerShared, ChildService, ChildServiceClient, CompiledBundle, ConsentDisclosure,
    ExecError, ExecutorService, ExecutorServiceClient, ExecutorServiceServerShared, LoadError,
    RunReply, RunRequest,
};

/// Concurrent callback invocations the per-run relay handles. `media_load` /
/// `session_change` are serialized by the round in practice, so a small pool is
/// ample (mirrors the api-side callback server).
const CALLBACK_CONCURRENCY: usize = 4;

/// Wall-clock ceiling on ONE round in the child (tunable via
/// `ENCLAVID_ROUND_DEADLINE_SECS`; enforced by the [`ChildPool`]). A child that
/// WEDGES rather than crashes — an escaped payload that keeps its remoc reactor
/// answering keepalives while parking the `run`, or a hung upstream callback —
/// would otherwise hold its child-slot permit forever and, after `max_children`
/// such rounds, starve the WHOLE worker (the exact whole-worker blast radius this
/// split exists to bound; remoc has a dead-transport timeout but NO per-request
/// deadline). On expiry the pool kills the child and we surface `ExecError::Run`
/// so api returns 5xx and the applicant retries against intact api-side state.
/// Generous so no legitimately slow round (ML inference, OCR) is false-killed.
const DEFAULT_ROUND_DEADLINE_SECS: u64 = 120;

/// Default L1 (bundle byte-cache) RAM budget (tunable via
/// `ENCLAVID_BUNDLE_CACHE_BYTES`). The cache is weighed by `cwasm` length so this
/// is a BYTE ceiling, not an entry count: each bundle is ~10-15 MiB, so an
/// entry-count cap would nominally admit >100 GB, and an authenticated consumer
/// minting many distinct `composition_key`s could OOM the supervisor (crashing
/// every concurrent in-flight round). 2 GiB holds ~130-200 compositions, far
/// under any deployment box.
const DEFAULT_BUNDLE_CACHE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// The `engine_rpc::ExecutorService` impl. Shared (`Arc`) across api connections;
/// each round runs in its own child, spawned + bounded + deadline-guarded by
/// [`ChildPool`].
struct Supervisor {
    /// L1: compiled bundle BYTES per composition (NOT deserialized components).
    /// Long-lived across sessions + rounds; the expensive layer (OCI pull +
    /// compile + api round-trip) is what this saves. Each spawned child gets a
    /// copy to deserialize itself.
    bundle_cache: Cache<String, Arc<CompiledBundle>>,
    /// The disposable per-round child pool (spawn + concurrency bound + round
    /// deadline + reap), shared with the compile-worker.
    pool: ChildPool,
}

impl Supervisor {
    /// Resolve the compiled bundle from L1, PULLING from api on a miss.
    /// `try_get_with` coalesces concurrent misses for the same key into ONE
    /// `load_component` pull; errors aren't cached (a transient failure retries).
    /// A config-resolution status (e.g. 410 GONE) is preserved as
    /// [`ExecError::Config`] so api surfaces it verbatim. Runs supervisor-side,
    /// BEFORE the child is spawned, so a config failure never spends a child slot.
    async fn resolve_bundle(
        &self,
        composition_key: &str,
        callbacks: &CallbackServiceClient<Ciborium>,
    ) -> Result<Arc<CompiledBundle>, ExecError> {
        let cb = callbacks.clone();
        let key = composition_key.to_string();
        self.bundle_cache
            .try_get_with(key.clone(), async move {
                cb.load_component(key, compat_token()).await.map(Arc::new)
            })
            .await
            .map_err(|arc: Arc<LoadError>| ExecError::Config {
                status: arc.status,
                message: arc.message.clone(),
            })
    }
}

impl ExecutorService for Supervisor {
    async fn run(
        &self,
        req: RunRequest,
        callbacks: CallbackServiceClient<Ciborium>,
    ) -> Result<RunReply, ExecError> {
        // Resolve the compiled bundle (L1 byte cache; pull from api on miss) —
        // domain-side, before any child is spawned.
        let bundle = self.resolve_bundle(&req.composition_key, &callbacks).await?;
        let RunRequest { session_state, event, props, .. } = req;

        // Drive ONE round in a fresh disposable child, under the pool's
        // concurrency bound + wall-clock deadline (the pool kills + reaps a wedged
        // child so it can't leak its slot). The closure is the DOMAIN work: prime
        // the child with the bundle, stand up the callback relay, run.
        let outcome = self
            .pool
            .run(move |client: ChildServiceClient<Ciborium>| async move {
                // Prime once (deserialize + InstancePre in the child); ships the
                // ~10-15 MiB cwasm over the socketpair.
                client.prime((*bundle).clone()).await?;

                // Relay: the child's media_load / session_change forward THROUGH
                // here to api's callbacks (the seal-key holder). No `load_component`
                // is exposed to the child.
                let relay = Arc::new(RelayCallbacks { upstream: callbacks });
                let (relay_server, relay_client) =
                    ChildCallbacksServerShared::<_, Ciborium>::new(relay, CALLBACK_CONCURRENCY);
                tokio::spawn(async move {
                    let _ = relay_server.serve(true).await;
                });

                client.run(session_state, event, props, relay_client).await
            })
            .await;

        // The pool returns the closure's domain result verbatim on success; a
        // pool-level failure (spawn error, or the deadline killing a wedged
        // child) becomes a fail-safe `ExecError::Run` (api 5xx → applicant retry).
        match outcome {
            Ok(domain_result) => domain_result,
            Err(pool_err) => Err(ExecError::Run(format!("child supervisor: {pool_err}"))),
        }
    }
}

/// Forwards the child's narrowed callbacks straight to api's full
/// `CallbackService` client. The upstream client method already returns the same
/// `Result<_, CallbackError>` these methods return (remoc folds transport errors
/// into `CallbackError`), so each is a one-line forward.
struct RelayCallbacks {
    upstream: CallbackServiceClient<Ciborium>,
}

impl ChildCallbacks for RelayCallbacks {
    async fn media_load(&self, hash: [u8; 32]) -> Result<Option<Vec<u8>>, CallbackError> {
        self.upstream.media_load(hash).await
    }

    async fn session_change(
        &self,
        state: SessionState,
        disclosures: Vec<ConsentDisclosure>,
        media: Vec<([u8; 32], Vec<u8>)>,
    ) -> Result<(), CallbackError> {
        self.upstream.session_change(state, disclosures, media).await
    }
}

/// Locate the `session-child` binary: `ENCLAVID_SESSION_CHILD_BIN` if set, else
/// the sibling of this supervisor's own executable (they build + deploy
/// together). Fails loud if neither resolves — per the minimal-defaults rule.
fn child_exe() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("ENCLAVID_SESSION_CHILD_BIN") {
        return std::path::PathBuf::from(p);
    }
    let mut p = std::env::current_exe()
        .expect("execution-worker: resolve current_exe for sibling session-child path");
    p.set_file_name("session-child");
    p
}

/// The base channel carries the `ExecutorServiceClient` from us (server) to api
/// (client).
type Cli = ExecutorServiceClient<Ciborium>;

#[tokio::main]
async fn main() {
    // api-facing listen address: first arg or ENCLAVID_EXECUTION_WORKER_LISTEN.
    // Fail loud if absent (per the minimal-defaults rule).
    let addr = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("ENCLAVID_EXECUTION_WORKER_LISTEN").ok())
        .expect(
            "execution-worker: listen address required (arg1 or \
             ENCLAVID_EXECUTION_WORKER_LISTEN, e.g. 127.0.0.1:7002)",
        );

    // Hard cap on concurrent per-round children (deployment envelope). Tunable;
    // a sane default keeps memory bounded (one process each).
    let max_children: usize = std::env::var("ENCLAVID_MAX_CHILDREN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64);
    let round_deadline = Duration::from_secs(
        std::env::var("ENCLAVID_ROUND_DEADLINE_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_ROUND_DEADLINE_SECS),
    );
    let bundle_cache_bytes: u64 = std::env::var("ENCLAVID_BUNDLE_CACHE_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_BUNDLE_CACHE_BYTES);

    let child_exe = child_exe();

    let svc = Arc::new(Supervisor {
        bundle_cache: Cache::builder()
            // Weigh each entry by its cwasm length so `max_capacity` is a RAM
            // budget, not an entry count (each bundle is ~10-15 MiB). Mirrors the
            // api-side MediaCache; closes the consumer-driven OOM. A bundle past
            // u32::MAX is clamped — it can't occur.
            .weigher(|_key, v: &Arc<CompiledBundle>| v.cwasm.len().try_into().unwrap_or(u32::MAX))
            .max_capacity(bundle_cache_bytes)
            .time_to_idle(Duration::from_secs(3600))
            .build(),
        pool: ChildPool::new(child_exe.clone(), max_children, round_deadline),
    });

    let listener = TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("execution-worker: bind {addr}: {e}"));
    eprintln!(
        "execution-worker (supervisor): listening on {addr}, session-child={}, \
         max_children={max_children}, round_deadline={}s, bundle_cache={} MiB",
        child_exe.display(),
        round_deadline.as_secs(),
        bundle_cache_bytes / (1024 * 1024),
    );

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let svc = svc.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_conn(stream, svc).await {
                        eprintln!("execution-worker: connection from {peer} ended: {e}");
                    }
                });
            }
            Err(e) => eprintln!("execution-worker: accept failed: {e}"),
        }
    }
}

/// Frame one accepted api connection with remoc and serve `ExecutorService`.
async fn serve_conn(stream: TcpStream, svc: Arc<Supervisor>) -> Result<(), String> {
    let (read, write) = stream.into_split();
    let (conn, mut tx, _rx) =
        remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(engine_rpc::connection_cfg(), read, write)
            .await
            .map_err(|e| format!("remoc connect: {e}"))?;
    tokio::spawn(conn);

    let (server, client) = ExecutorServiceServerShared::<_, Ciborium>::new(svc, 4);
    tx.send(client)
        .await
        .map_err(|e| format!("send service client: {e}"))?;
    server.serve(true).await.map_err(|e| format!("serve: {e}"))?;
    Ok(())
}
