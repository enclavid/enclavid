//! The `engine-executor-child` deployable: the disposable PER-ROUND process the
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
//! to api (the seal-key holder). Those two calls are the whole of the
//! [`ChildCallbacks`] boundary: the supervisor primed this process with its
//! bundle before starting it, so there is nothing here that can ask for a
//! composition, and no OCI-pull or compile surface to ask with.
//!
//! Single-threaded runtime: one round, no cross-round concurrency to exploit, and
//! forward-compatible with a future fork-from-zygote (which needs a single-
//! threaded process at fork time).

// The contained posture, stated where the compiler can check it. The manifest
// not asking for `safe-logger/device` is the intent; this stops a dependency
// edge from undoing it silently.
//
// Behind a feature because the claim is about ONE cargo invocation — see the
// `contained` feature in this package's manifest for why a whole-workspace build
// is not that, and which two builds pass it.
#[cfg(feature = "contained")]
safe_logger::assert_contained!();

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};

use remoc::codec::Ciborium;

use engine_executor::{
    Component, EmbeddedRegistry, Event, Executor, MediaStore, PrimedComposition, Prop, RunError,
    RunInputs, RunResult, RunStatus, SessionChange, SessionListener, SessionState,
};
use engine_rpc::{
    BundleRef, ChildCallbacks, ChildCallbacksClient, ChildService, ChildServiceServerShared,
    ExecError,
};
// The inward tier only. This package deliberately does not carry safe-logger's
// outward half — see `assert_contained!` above — so what a failure says stays in
// a debug build's private sink and never reaches the host through this process.
use safe_logger::debug;

/// The `engine_rpc::ChildService` impl. `prime` is called once (stores the
/// primed composition); `run` reads it. Under per-round each is called exactly
/// once, but `OnceLock` keeps the contract explicit (prime-before-run, prime-once).
struct Child {
    executor: Arc<Executor>,
    primed: OnceLock<PrimedComposition>,
}

impl ChildService for Child {
    async fn prime(&self, bundle: BundleRef) -> Result<(), ExecError> {
        // MMAP the cwasm via its inherited fd path (`/proc/self/fd/N`, an anonymous
        // memfd the supervisor handed us at spawn) and build the reusable
        // InstancePre. The unsafe deserialize sink stays in THIS disposable process;
        // the 7 MiB never crossed the hop — only the fd-path did.
        let component: Component = self
            .executor
            .deserialize_component_file(&bundle.cwasm_path)
            .map_err(|e| {
                debug!("deserialize cwasm file: {e}");
                ExecError::Unknown
            })?;
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
            .map_err(|e| {
                debug!("prime composition: {e}");
                ExecError::Unknown
            })?;
        self.primed.set(primed).map_err(|_| {
            debug!("engine-executor-child: prime called twice");
            ExecError::Unknown
        })?;
        Ok(())
    }

    async fn run(
        &self,
        session_state: SessionState,
        event: Event,
        props: Vec<(String, engine_rpc::Prop)>,
        callbacks: ChildCallbacksClient<Ciborium>,
    ) -> Result<engine_rpc::RunStatus, ExecError> {
        let primed = self.primed.get().ok_or_else(|| {
            debug!("engine-executor-child: run before prime");
            ExecError::Unknown
        })?;

        // Map the wire `Prop` mirror to the bindgen `enclavid:host/types.prop`.
        let props: Vec<(String, Prop)> = props
            .into_iter()
            .map(|(k, v)| (k, to_engine_prop(v)))
            .collect();

        // Keyless callback proxies: blob loads + state persistence forward to the
        // supervisor's relay over the SAME socketpair connection (→ api). The seal
        // key never enters this process.
        let listener: Arc<dyn SessionListener> = Arc::new(RelayListener {
            callbacks: callbacks.clone(),
        });
        let media_store: Arc<dyn MediaStore> = Arc::new(RelayMediaStore {
            callbacks,
            memo: Mutex::new(HashMap::new()),
        });
        let inputs = RunInputs {
            listener,
            media_store,
        };

        let (status, _next_state) = self
            .executor
            .run(primed, session_state, event, props, inputs)
            .await
            .map_err(round_failure)?;

        Ok(to_wire_status(status))
    }
}

/// Marks a failure of the leg back to api, so the chain can be told apart from a
/// policy trap after it has unwound the running wasm.
///
/// It has to unwind AS a `wasmtime::Error` — that is how a host function aborts
/// the guest — and by the time it reaches [`round_failure`] the two are the same
/// anyhow chain. Without this, the seal-key holder's own store being down reached
/// api as the consumer's policy misbehaving, and the applicant was told so.
///
/// The upstream message is deliberately NOT carried: it is built on api's side,
/// where the sizes it names are the policy's own state and disclosure lengths, and
/// relaying it would put those byte counts back on a hop the host splices.
#[derive(Debug)]
struct CallbackFailed;

impl std::fmt::Display for CallbackFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a callback to the orchestrator failed")
    }
}
impl std::error::Error for CallbackFailed {}

/// Turn a round's anyhow chain into the one bit api acts on: was it the POLICY.
///
/// The chain itself never crosses, because it interpolates text the policy
/// supplied — a trap message carries the very key wasm passed to a host function.
/// The round that traps would otherwise carry exactly the channel `Padded` closes
/// on the round that succeeds, and a policy can trap deliberately and retry.
///
/// Almost everything reaching here IS the policy: a trap, out of fuel, out of
/// memory, a host function refusing a key no catalog declared. The exception is a
/// failed callback to api — the seal-key holder's own leg went away, and saying
/// "the policy failed" about that would be attributing our outage to the consumer.
/// It is recovered as a VALUE by `downcast`, never by reading a rendering, because
/// by the time it arrives here it has unwound as an ordinary `wasmtime::Error`.
///
/// The rendering goes to `debug!`, and in the SHIPPED image that is nowhere: the
/// child is built without the `debug` feature, so the site compiles out, and its
/// stderr is `/dev/null` besides. That is the cost of not carrying it — and the
/// alternative is not a `warn!` on this side either, since a per-round line on the
/// outward tier is a channel to the host, who may be the policy's author too.
fn round_failure(e: RunError) -> ExecError {
    debug!("round failed: {e:#}");
    if e.chain()
        .any(|cause| cause.downcast_ref::<CallbackFailed>().is_some())
    {
        return ExecError::Unknown;
    }
    ExecError::Policy
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
        let callbacks = self.callbacks.clone();
        Box::pin(async move {
            callbacks.session_change(state).await.map_err(|e| {
                debug!("session_change callback: {e}");
                RunError::new(CallbackFailed)
            })
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
            let loaded = callbacks.media_load(hash).await.map_err(|e| {
                debug!("media_load callback: {e}");
                RunError::new(CallbackFailed)
            })?;
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
    // The contained posture, and the choice is the point: this process holds the
    // round's applicant plaintext in the one address space where the consumer's
    // wasm runs, so it may not speak to the host at all. `info!`/`warn!`/`error!`
    // are dropped here; `debug!` reaches whoever ran the binary by hand and, when
    // the supervisor spawned it, the `/dev/null` it was given.
    safe_logger::install_contained();

    let child = Arc::new(Child {
        executor: Arc::new(Executor::new().expect("engine-executor-child: create executor engine")),
        primed: OnceLock::new(),
    });

    // The supervisor placed one end of a socketpair on our fd 0; engine-supervisor
    // adopts it, serves `ChildService`, and returns when the supervisor drops its
    // client (round done) → we exit. Request buffer 1 — prime then run,
    // sequential, no cross-round concurrency. The cwasm itself never crosses this
    // socket: `prime` carries the path of an inherited fd, which we mmap.
    match engine_supervisor::serve_child::<Child, ChildServiceServerShared<Child, Ciborium>>(
        child, 1,
    )
    .await
    {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            // The supervisor nulls this child's stdout and stderr, and the
            // log device is opened O_CLOEXEC so a child never inherits it —
            // this reaches a developer running the child by hand and nobody
            // else. `debug!` on top of that keeps it out of the measured build
            // entirely, so the belt does not depend on the braces.
            safe_logger::debug!("engine-executor-child: {e}");
            std::process::exit(1);
        }
    }
}

/// The mapping that replaced a substring search.
#[cfg(test)]
mod round_failure_tests {
    use super::*;

    /// Whatever the policy did, and whatever string it chose while doing it, the
    /// hop carries the same value. That is the property — not that the mapping is
    /// right about the cause, but that the cause cannot steer what crosses.
    #[test]
    fn nothing_a_policy_chose_changes_what_crosses() {
        let chosen = [
            "all fuel consumed",
            "embedded localized: no component declared key 'consent_reason' ...",
            "embedded icon: no component declared key '<script>alert(1)</script>' ...",
            "x' is not registered '",
            "secret=MRZ<<DOE<<JOHN",
            "",
        ];
        for text in chosen {
            assert_eq!(
                round_failure(RunError::msg(text)),
                ExecError::Policy,
                "{text:?} changed what crossed the hop"
            );
        }
        // And a chain of any depth is still one value — the rendering never
        // reaches the wire, so its length cannot either.
        let deep = RunError::msg("innermost")
            .context("resolving a localized ref")
            .context("error while executing at wasm backtrace: 0x1234");
        assert_eq!(round_failure(deep), ExecError::Policy);
    }

    /// api's own leg failing is NOT the policy misbehaving, and that is the one
    /// distinction this mapping makes. It has to be recovered by `downcast`: a
    /// callback failure unwinds as an ordinary `wasmtime::Error`, because that is
    /// how a host function aborts the guest, so by here it is indistinguishable
    /// from a trap by any other means.
    #[test]
    fn a_failed_callback_is_not_attributed_to_the_policy() {
        let unwound = RunError::new(CallbackFailed)
            .context("error while executing at wasm backtrace: 0x1234");
        assert_eq!(round_failure(unwound), ExecError::Unknown);
    }
}
