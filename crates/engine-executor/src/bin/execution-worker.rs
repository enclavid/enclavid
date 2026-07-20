//! The `execution-worker` deployable: holds this crate's runtime [`Executor`]
//! and serves `rpc::ExecutorService`. It LISTENS on an address; the orchestrator
//! (api) connects to it. Started by INFRASTRUCTURE (docker-compose / k8s), not
//! spawned by api — exactly like the hatch and the compile-worker. Isolating
//! the runtime that executes UNTRUSTED policy wasm in its own process/CVM is the
//! execute side of the compile⊥execute split.
//!
//! **Keyless.** The worker holds no `tee_seal_key` and no applicant token. Blob
//! rehydration + state persistence happen via the [`CallbackService`] client the
//! orchestrator passes into [`run`](ExecutorService::run): the worker's
//! `media_store` / `listener` are thin proxies that forward `media_load` /
//! `session_change` BACK over the SAME remoc connection, so the seal key never
//! crosses into this process (remoc multiplexes the callbacks over the in-flight
//! run — no hand-rolled duplex).
//!
//! **Component cache (the fleet's ONLY in-memory L1).** A fused `cwasm` is
//! ~10–15 MiB, so the worker caches the deserialized component + embedded
//! registry per `composition_key`. On a miss it PULLS the compiled bundle from
//! the orchestrator via the `load_component` callback (the orchestrator serves
//! it from its L2 sealed-cwasm store, or compiles on an L2 miss). `try_get_with`
//! coalesces concurrent misses for the same composition into ONE pull. The
//! orchestrator holds no in-memory component cache; steady-state rounds carry
//! only the key + session + event (see `rpc::execute`).
//!
//! Transport TODAY: a plain TCP listener (dev); Plan-A swaps it for the host
//! vsock-relay rendezvous + RA-TLS (both peers dial the relay, the host splices).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use remoc::codec::Ciborium;
use remoc::rtc::ServerShared;
use tokio::net::{TcpListener, TcpStream};

use engine_executor::{
    Component, EmbeddedImport, EmbeddedRegistry, Executor, MediaStore, Prop, RunError, RunInputs,
    RunResult, RunStatus, SessionChange, SessionListener, compat_token,
};
use rpc::{
    CallbackService, CallbackServiceClient, CompiledBundle, ExecError, ExecutorService,
    ExecutorServiceClient, ExecutorServiceServerShared, RunReply, RunRequest,
};

/// A deserialized, ready-to-run composition, cached per `composition_key`. Holds
/// the fused wasmtime `Component` plus the two host-side inputs the run needs:
/// the composition-wide embedded registry (ref → data) and the per-catalog
/// i18n/icons import manifest. Immutable once built; shared by `Arc` across
/// concurrent rounds for the same composition.
struct PrimedComposition {
    component: Component,
    embedded: Arc<EmbeddedRegistry>,
    embedded_imports: Arc<Vec<EmbeddedImport>>,
}

/// The `rpc::ExecutorService` impl. Shared (`Arc`) across connections; the
/// wasmtime engine runs rounds concurrently, and the component cache is shared.
struct Service {
    executor: Arc<Executor>,
    cache: Cache<String, Arc<PrimedComposition>>,
}

impl ExecutorService for Service {
    async fn run(
        &self,
        req: RunRequest,
        callbacks: CallbackServiceClient<Ciborium>,
    ) -> Result<RunReply, ExecError> {
        // Resolve the composition from L1, PULLING the bundle from the
        // orchestrator on a miss (`load_component`). `try_get_with` coalesces
        // concurrent misses for the same key into ONE pull + deserialize.
        // Errors (String) aren't cached, so a transient failure retries.
        let executor = self.executor.clone();
        let key = req.composition_key.clone();
        let cb = callbacks.clone();
        let primed = self
            .cache
            .try_get_with(key.clone(), async move {
                // `?` on load_component converts a LoadError into
                // ExecError::Config, preserving the config status (e.g. 410).
                let bundle = cb.load_component(key, compat_token()).await?;
                prime(&executor, &bundle).map_err(ExecError::Run)
            })
            .await
            // try_get_with wraps the loader error in Arc (shared with coalesced
            // waiters); ExecError is Clone, so unwrap it back.
            .map_err(|arc: std::sync::Arc<ExecError>| (*arc).clone())?;

        // Map the consumer config to the bindgen `Prop` the policy reads.
        let props: Vec<(String, Prop)> =
            req.props.into_iter().map(|(k, v)| (k, to_engine_prop(v))).collect();

        // Keyless callback proxies: the run's blob loads + state persistence
        // forward to the orchestrator over the SAME connection. The seal key
        // stays orchestrator-side.
        let listener: Arc<dyn SessionListener> =
            Arc::new(CallbackListener { callbacks: callbacks.clone() });
        let media_store: Arc<dyn MediaStore> = Arc::new(CallbackMediaStore {
            callbacks,
            memo: std::sync::Mutex::new(std::collections::HashMap::new()),
        });
        let inputs = RunInputs {
            listener,
            embedded: primed.embedded.clone(),
            media_store,
        };

        let (status, _next_state) = self
            .executor
            .run(
                &primed.component,
                &primed.embedded_imports,
                req.session_state,
                req.event,
                props,
                inputs,
            )
            .await
            // `{e:#}` walks the anyhow chain so a buried host-fn / trap cause
            // reaches the orchestrator's log, not just the top wasm line.
            .map_err(|e| ExecError::Run(format!("{e:#}")))?;

        Ok(RunReply { status: to_wire_status(status) })
    }
}

/// Deserialize a bundle's cwasm into a live component and rebuild its embedded
/// registry from the stored catalogs. `Err(String)` on a wasmtime toolchain skew
/// / tampered cwasm — surfaced as a run failure; the orchestrator's compat_token
/// keys L2 so a matching-version cwasm is served next.
fn prime(executor: &Executor, bundle: &CompiledBundle) -> Result<Arc<PrimedComposition>, String> {
    let component = executor
        .deserialize_component(&bundle.cwasm)
        .map_err(|e| format!("deserialize cwasm: {e}"))?;
    let mut builder = EmbeddedRegistry::builder();
    for c in &bundle.catalogs {
        builder.add_component(c.hash, c.decls.clone());
    }
    Ok(Arc::new(PrimedComposition {
        component,
        embedded: Arc::new(builder.build()),
        embedded_imports: Arc::new(bundle.embedded_imports.clone()),
    }))
}

/// `SessionListener` that forwards each round's `on_session_change` to the
/// orchestrator's `CallbackService::session_change`. Converts the BORROWED
/// `SessionChange` to owned wire form synchronously (before the await), so the
/// future owns everything it sends.
struct CallbackListener {
    callbacks: CallbackServiceClient<Ciborium>,
}

impl SessionListener for CallbackListener {
    fn on_session_change<'a>(
        &'a self,
        change: SessionChange<'a>,
    ) -> Pin<Box<dyn Future<Output = RunResult<()>> + Send + 'a>> {
        let state = change.state.clone();
        let disclosures: Vec<rpc::ConsentDisclosure> = change
            .disclosures
            .iter()
            .map(|d| rpc::ConsentDisclosure { fields: d.fields.clone() })
            .collect();
        // Copy the captured frames out of their Arcs into owned wire bytes.
        let media: Vec<([u8; 32], Vec<u8>)> = change
            .media
            .map(|m| m.blobs.iter().map(|(h, b)| (*h, b.as_ref().clone())).collect())
            .unwrap_or_default();
        let callbacks = self.callbacks.clone();
        Box::pin(async move {
            callbacks
                .session_change(state, disclosures, media)
                .await
                .map_err(|e| RunError::msg(format!("session_change callback: {e}")))
        })
    }
}

/// `MediaStore` that forwards `blob::from-blob-ref` loads to the orchestrator's
/// `CallbackService::media_load` (which holds the seal key + the captured-hash
/// gate). `None` = miss, exactly as the in-process store returned.
struct CallbackMediaStore {
    callbacks: CallbackServiceClient<Ciborium>,
    /// Per-run memo of rehydrated blobs, keyed by content hash. Collapses REPEAT
    /// `bytes()` reads of the SAME blob within a round to ONE `media_load` RPC.
    ///
    /// Covert-channel defence: the engine mints a fresh COLD handle per
    /// `blob::from-blob-ref` (`media.rs` — `bytes: None`), so a policy looping
    /// `blob::new(hex(H)).bytes()` would otherwise emit one host-observable
    /// `media_load` per iteration — a fuel-bounded count channel (~log2(fuel)
    /// bits/round) that even RA-TLS traffic-analysis on the relay can read (frame
    /// COUNT, not content). Memoizing here restores the "≤1 host-observable read
    /// per distinct blob" bound the api-side `MediaCache` gave when the store was
    /// in-process — now that the store sits across the host-transiting wire.
    /// Per-run (dropped when the run ends), so it holds no cross-session state and
    /// only ever caches gate-approved captures (a miss traps the round).
    memo: std::sync::Mutex<std::collections::HashMap<[u8; 32], Arc<Vec<u8>>>>,
}

impl MediaStore for CallbackMediaStore {
    fn load<'a>(
        &'a self,
        blob_hash: &'a [u8; 32],
    ) -> Pin<Box<dyn Future<Output = RunResult<Option<Arc<Vec<u8>>>>> + Send + 'a>> {
        let hash = *blob_hash;
        let callbacks = self.callbacks.clone();
        Box::pin(async move {
            // Repeat read → served from the per-run memo, no RPC crosses the
            // (host-transiting) api<->worker wire.
            if let Some(bytes) = self.memo.lock().unwrap().get(&hash).cloned() {
                return Ok(Some(bytes));
            }
            let loaded = callbacks
                .media_load(hash)
                .await
                .map_err(|e| RunError::msg(format!("media_load callback: {e}")))?;
            let arc = loaded.map(Arc::new);
            if let Some(bytes) = &arc {
                self.memo.lock().unwrap().insert(hash, bytes.clone());
            }
            Ok(arc)
        })
    }
}

/// Map the wire `Prop` mirror to the bindgen `enclavid:host/types.prop`.
fn to_engine_prop(p: rpc::Prop) -> Prop {
    match p {
        rpc::Prop::Null => Prop::Null,
        rpc::Prop::Bool(b) => Prop::Bool(b),
        rpc::Prop::Int(i) => Prop::Int(i),
        rpc::Prop::Float(f) => Prop::Float(f),
        rpc::Prop::String(s) => Prop::String(s),
    }
}

/// Map the engine's `RunStatus` to the wire mirror (both wrap the same
/// hatch_client `Prompt` / `Decision`).
fn to_wire_status(s: RunStatus) -> rpc::RunStatus {
    match s {
        RunStatus::AwaitingInput(p) => rpc::RunStatus::AwaitingInput(p),
        RunStatus::Completed(d) => rpc::RunStatus::Completed(d),
    }
}

/// The base channel carries the `ExecutorServiceClient` from us (server) to the
/// orchestrator (client).
type Cli = ExecutorServiceClient<Ciborium>;

#[tokio::main]
async fn main() {
    // Listen address: first arg or ENCLAVID_EXECUTION_WORKER_LISTEN. Fail loud if
    // absent (per the minimal-defaults rule).
    let addr = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("ENCLAVID_EXECUTION_WORKER_LISTEN").ok())
        .expect(
            "execution-worker: listen address required (arg1 or \
             ENCLAVID_EXECUTION_WORKER_LISTEN, e.g. 127.0.0.1:7002)",
        );

    let svc = Arc::new(Service {
        executor: Arc::new(Executor::new().expect("execution-worker: create executor engine")),
        // Bounded per-composition component cache — same idiom as the
        // orchestrator's L1 PolicyCache.
        cache: Cache::builder()
            .max_capacity(10_000)
            .time_to_idle(Duration::from_secs(3600))
            .build(),
    });

    let listener = TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("execution-worker: bind {addr}: {e}"));
    eprintln!("execution-worker: listening on {addr}");

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

/// Frame one accepted connection with remoc and serve `ExecutorService` on it.
async fn serve_conn(stream: TcpStream, svc: Arc<Service>) -> Result<(), String> {
    let (read, write) = stream.into_split();
    let (conn, mut tx, _rx) =
        remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(rpc::connection_cfg(), read, write)
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
