//! The `session-child` deployable: the disposable PER-ROUND process the
//! `execution-worker` supervisor spawns to run UNTRUSTED policy wasm behind an
//! OS address-space boundary.
//!
//! Lifecycle (one round, then die): the supervisor spawns this process with one
//! end of a socketpair on **fd 0**, [`prime`](engine_rpc::ChildService::prime)s
//! it once with the compiled bundle (deserialize + build the reusable
//! `InstancePre`), drives exactly one [`run`](engine_rpc::ChildService::run), then
//! drops its client — this process's `serve` loop ends and it exits. A fresh
//! child is spawned for the next round. So a wasmtime sandbox ESCAPE is confined
//! to ONE round's plaintext (one applicant), and `Component::deserialize` (an
//! unsafe sink over attacker-influenced bytes) runs only in this throwaway
//! process — no cross-round persistence, no cross-session bleed.
//!
//! **Keyless.** This process never holds `tee_seal_key` or an applicant token.
//! Blob rehydration ([`media_load`](engine_rpc::ChildCallbacks::media_load)) and
//! state persistence ([`session_change`](engine_rpc::ChildCallbacks::session_change))
//! forward over the socketpair to the SUPERVISOR's relay, which forwards them on
//! to api (the seal-key holder). The narrowed [`ChildCallbacks`] boundary omits
//! `load_component`, so this untrusted-wasm process is never handed the OCI-pull /
//! compile probe surface.
//!
//! Single-threaded runtime: one round, no cross-round concurrency to exploit, and
//! forward-compatible with a future fork-from-zygote (which needs a single-
//! threaded process at fork time).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};

use remoc::codec::Ciborium;

use engine_executor::{
    Component, EmbeddedRegistry, Event, Executor, MediaStore, Prop, PrimedComposition, RunError,
    RunInputs, RunResult, RunStatus, SessionChange, SessionListener, SessionState,
};
use engine_rpc::{
    ChildCallbacks, ChildCallbacksClient, ChildService, ChildServiceServerShared, CompiledBundle,
    ExecError, RunReply,
};

/// The `engine_rpc::ChildService` impl. `prime` is called once (stores the
/// primed composition); `run` reads it. Under per-round each is called exactly
/// once, but `OnceLock` keeps the contract explicit (prime-before-run, prime-once).
struct Child {
    executor: Arc<Executor>,
    primed: OnceLock<PrimedComposition>,
}

impl ChildService for Child {
    async fn prime(&self, bundle: CompiledBundle) -> Result<(), ExecError> {
        // Deserialize the cwasm (the unsafe sink stays in THIS disposable
        // process) and build the reusable InstancePre.
        let component: Component = self
            .executor
            .deserialize_component(&bundle.cwasm)
            .map_err(|e| ExecError::Run(format!("deserialize cwasm: {e}")))?;
        // Rebuild the composition-wide embedded registry from the bundle's
        // per-component catalogs (ref → data), same as the old in-worker prime.
        let mut builder = EmbeddedRegistry::builder();
        for c in &bundle.catalogs {
            builder.add_component(c.hash, c.decls.clone());
        }
        let embedded = Arc::new(builder.build());
        let primed = self
            .executor
            .prime(&component, &bundle.embedded_imports, embedded)
            .map_err(|e| ExecError::Run(format!("prime composition: {e}")))?;
        self.primed
            .set(primed)
            .map_err(|_| ExecError::Run("session-child: prime called twice".into()))?;
        Ok(())
    }

    async fn run(
        &self,
        session_state: SessionState,
        event: Event,
        props: Vec<(String, engine_rpc::Prop)>,
        callbacks: ChildCallbacksClient<Ciborium>,
    ) -> Result<RunReply, ExecError> {
        let primed = self
            .primed
            .get()
            .ok_or_else(|| ExecError::Run("session-child: run before prime".into()))?;

        // Map the wire `Prop` mirror to the bindgen `enclavid:host/types.prop`.
        let props: Vec<(String, Prop)> =
            props.into_iter().map(|(k, v)| (k, to_engine_prop(v))).collect();

        // Keyless callback proxies: blob loads + state persistence forward to the
        // supervisor's relay over the SAME socketpair connection (→ api). The seal
        // key never enters this process.
        let listener: Arc<dyn SessionListener> =
            Arc::new(RelayListener { callbacks: callbacks.clone() });
        let media_store: Arc<dyn MediaStore> = Arc::new(RelayMediaStore {
            callbacks,
            memo: Mutex::new(HashMap::new()),
        });
        let inputs = RunInputs { listener, media_store };

        let (status, _next_state) = self
            .executor
            .run(primed, session_state, event, props, inputs)
            .await
            // `{e:#}` walks the anyhow chain so a buried host-fn / trap cause
            // reaches the supervisor's log, not just the top wasm line.
            .map_err(|e| ExecError::Run(format!("{e:#}")))?;

        Ok(RunReply { status: to_wire_status(status) })
    }
}

/// `SessionListener` that forwards each round's `on_session_change` to the
/// supervisor's `ChildCallbacks::session_change` (→ api). Converts the BORROWED
/// `SessionChange` to owned wire form synchronously (before the await), so the
/// future owns everything it sends.
struct RelayListener {
    callbacks: ChildCallbacksClient<Ciborium>,
}

impl SessionListener for RelayListener {
    fn on_session_change<'a>(
        &'a self,
        change: SessionChange<'a>,
    ) -> Pin<Box<dyn Future<Output = RunResult<()>> + Send + 'a>> {
        let state = change.state.clone();
        let disclosures: Vec<engine_rpc::ConsentDisclosure> = change
            .disclosures
            .iter()
            .map(|d| engine_rpc::ConsentDisclosure { fields: d.fields.clone() })
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

/// `MediaStore` that forwards `blob::from-blob-ref` loads to the supervisor's
/// `ChildCallbacks::media_load` (→ api, which holds the seal key + the
/// captured-hash gate). `None` = miss, exactly as the in-process store returned.
struct RelayMediaStore {
    callbacks: ChildCallbacksClient<Ciborium>,
    /// Per-run memo of rehydrated blobs, keyed by content hash. Collapses REPEAT
    /// `bytes()` reads of the SAME blob within a round to ONE `media_load` RPC.
    ///
    /// Covert-channel defence: the engine mints a fresh COLD handle per
    /// `blob::from-blob-ref` (`media.rs` — `bytes: None`), so a policy looping
    /// `blob::new(hex(H)).bytes()` would otherwise emit one `media_load` per
    /// iteration — a fuel-bounded count channel readable even by traffic-analysis
    /// on the host-transiting wire (frame COUNT, not content). Memoizing here
    /// restores the "≤1 host-observable read per distinct blob" bound, and MUST
    /// live on this (child) side of the child↔supervisor hop, not in the relay.
    /// Per-round (this process is per-round), so it holds no cross-session state
    /// and only ever caches gate-approved captures (a miss traps the round).
    memo: Mutex<HashMap<[u8; 32], Arc<Vec<u8>>>>,
}

impl MediaStore for RelayMediaStore {
    fn load<'a>(
        &'a self,
        blob_hash: &'a [u8; 32],
    ) -> Pin<Box<dyn Future<Output = RunResult<Option<Arc<Vec<u8>>>>> + Send + 'a>> {
        let hash = *blob_hash;
        let callbacks = self.callbacks.clone();
        Box::pin(async move {
            // Repeat read → served from the per-run memo, no RPC crosses the
            // (host-transiting) child<->supervisor wire.
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
fn to_engine_prop(p: engine_rpc::Prop) -> Prop {
    match p {
        engine_rpc::Prop::Null => Prop::Null,
        engine_rpc::Prop::Bool(b) => Prop::Bool(b),
        engine_rpc::Prop::Int(i) => Prop::Int(i),
        engine_rpc::Prop::Float(f) => Prop::Float(f),
        engine_rpc::Prop::String(s) => Prop::String(s),
    }
}

/// Map the engine's `RunStatus` to the wire mirror (both wrap the same
/// hatch_client `Prompt` / `Decision`).
fn to_wire_status(s: RunStatus) -> engine_rpc::RunStatus {
    match s {
        RunStatus::AwaitingInput(p) => engine_rpc::RunStatus::AwaitingInput(p),
        RunStatus::Completed(d) => engine_rpc::RunStatus::Completed(d),
    }
}

// Single-threaded runtime — one round, no background epoch (we use fuel, not
// epochs), forward-compatible with a fork-from-zygote.
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let child = Arc::new(Child {
        executor: Arc::new(Executor::new().expect("session-child: create executor engine")),
        primed: OnceLock::new(),
    });

    // The supervisor placed one end of a socketpair on our fd 0; engine-supervisor
    // adopts it, serves `ChildService`, and returns when the supervisor drops its
    // client (round done) → we exit. Request buffer 1 — prime then run,
    // sequential, no cross-round concurrency. The 64 MiB connection_cfg (prime
    // ships the ~10-15 MiB cwasm) lives in engine-supervisor.
    match engine_supervisor::serve_child::<Child, ChildServiceServerShared<Child, Ciborium>>(child, 1)
        .await
    {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("session-child: {e}");
            std::process::exit(1);
        }
    }
}
