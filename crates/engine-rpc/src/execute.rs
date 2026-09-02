//! Execute boundary — run + mid-call callbacks (the bidirectional case).
//!
//! Gated behind the `execute` feature: an execution-worker built with only
//! this feature links the executor + callback contract + `hatch-client` +
//! `engine-types` (the run needs the composition catalogs), and NOT the
//! compiler contract — least-knowledge for its measured image, and NO Cranelift.
//!
//! ## Who caches what
//!
//! The execution-worker owns the ONLY in-memory L1 (deserialized components,
//! keyed by `composition_key`). The orchestrator owns L2 (sealed cwasm files;
//! it holds `tee_seal_key`, the keyless worker cannot). On an L1 miss the worker
//! PULLS the compiled bundle from the orchestrator via the
//! [`CallbackService::load_component`] callback — the orchestrator serves it
//! from L2, or compiles on an L2 miss (OCI pull + compile-worker), seals it into
//! L2, and returns it. No bundle is ever pushed on the run itself. `compat_token`
//! (the worker's cwasm ABI id) keys L2 so a fleet version bump repartitions the
//! cache instead of feeding a stale cwasm to an incompatible runtime.

use serde::{Deserialize, Serialize};

use hatch_client::{Decision, DisplayField, Event, Prompt, SessionState};

use crate::{BundleRef, CompiledBundle};

/// serde mirror of the bindgen `enclavid:host/types.prop` — the consumer's
/// static-config scalar the policy reads via `context.props`. api builds this
/// from the session's JSON config (`enclavid-api::input`); the worker maps it
/// back to the bindgen `Prop` before the run. Defined here (not a bindgen
/// re-export) so the client-only orchestrator builds props without wasmtime.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Prop {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
}

/// serde mirror of the engine's `RunStatus` — one round's outcome. Wraps the
/// hatch_client domain `Prompt`/`Decision` (already serde; both are sealed
/// into `SessionState`). The worker maps `engine_executor::RunStatus` into this
/// at the boundary; the orchestrator projects it into the applicant view +
/// finalize without pulling wasmtime.
#[derive(Debug, Serialize, Deserialize)]
pub enum RunStatus {
    /// Policy rendered a prompt and is awaiting the matching applicant input.
    AwaitingInput(Prompt),
    /// Policy finished with a terminal decision.
    Completed(Decision),
}

/// serde mirror of the engine's `ConsentDisclosure` — the consented fields the
/// runtime sealed this round (non-empty only on a consent-disclosure accept),
/// carried on [`CallbackService::session_change`] for the orchestrator to
/// age-seal to the consumer.
#[derive(Debug, Serialize, Deserialize)]
pub struct ConsentDisclosure {
    pub fields: Vec<DisplayField>,
}

/// A run failure — an opaque trap / instantiate / host-fn / transport / bundle-
/// materialize failure, mapped to 500 (with the text-ref 422 substring exception
/// the orchestrator still applies). Bundle RESOLUTION no longer crosses this
/// boundary: the orchestrator resolves the compiled bundle itself on a
/// [`RunOutcome::CacheMiss`] and maps any config-resolution status (e.g. 410 GONE)
/// verbatim on its own side, so there is no separate config-error wire variant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ExecError {
    Run(String),
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecError::Run(m) => write!(f, "run failed: {m}"),
        }
    }
}
impl std::error::Error for ExecError {}
impl From<remoc::rtc::CallError> for ExecError {
    fn from(err: remoc::rtc::CallError) -> Self {
        ExecError::Run(format!("run rpc failed: {err}"))
    }
}

/// A callback failure or an absorbed RPC transport error.
#[derive(Debug, Serialize, Deserialize)]
pub struct CallbackError(pub String);

impl std::fmt::Display for CallbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "callback failed: {}", self.0)
    }
}
impl std::error::Error for CallbackError {}
impl From<remoc::rtc::CallError> for CallbackError {
    fn from(err: remoc::rtc::CallError) -> Self {
        CallbackError(format!("callback rpc failed: {err}"))
    }
}

/// A callback failure surfacing inside a run bubbles up as an opaque run failure
/// — the worker's `?` on a mid-run media/state callback converts here.
impl From<CallbackError> for ExecError {
    fn from(err: CallbackError) -> Self {
        ExecError::Run(format!("callback during run: {}", err.0))
    }
}

/// One reducer round's inputs on the wire. `session_state`/`event`/`props` are the
/// round's already-decrypted inputs (the seal key stays orchestrator-side).
#[derive(Serialize, Deserialize)]
pub struct RunRequest {
    /// Names the fused component in the worker's L1 cache. Computed by the
    /// ORCHESTRATOR and authoritative end-to-end — the worker only ever caches /
    /// serves under this key and never names a key back, so it cannot steer which
    /// slot a compile lands in (L2 cache-poisoning defence).
    pub composition_key: String,
    /// Static consumer config the policy reads via `context.props`.
    pub props: Vec<(String, Prop)>,
    pub session_state: SessionState,
    pub event: Event,
}

/// One reducer round's result on the wire: the next [`RunStatus`].
///
/// State is NOT returned — it is persisted mid-run via
/// [`CallbackService::session_change`] (the orchestrator holds the seal key),
/// and the orchestrator discards the engine's vestigial returned copy, exactly
/// as the in-process path did.
#[derive(Serialize, Deserialize)]
pub struct RunReply {
    pub status: RunStatus,
}

/// The result of [`ExecutorService::run`] (the cache-only path): either the round
/// ran from the worker's L1, or the composition is NOT cached. On
/// [`CacheMiss`](RunOutcome::CacheMiss) the orchestrator resolves the compiled
/// bundle under ITS OWN `composition_key` (L2 read or cold compile) and calls
/// [`run_with_bundle`](ExecutorService::run_with_bundle). Because the orchestrator
/// both computes the key AND supplies the bundle, the worker never names a cache
/// slot — a compromised worker cannot poison another session's compiled-code cache.
/// `compat_token` is the worker's cwasm ABI id, so the orchestrator resolves/keys L2
/// for a cwasm THIS runtime can deserialize.
#[derive(Serialize, Deserialize)]
pub enum RunOutcome {
    Ran(RunStatus),
    CacheMiss { compat_token: String },
}

/// The orchestrator-served CALLBACK boundary the keyless execution-worker calls
/// BACK DURING a run: the worker holds no seal key, so blob rehydration
/// (`media_load`) and state persistence (`session_change`) happen orchestrator-
/// side. Bundle resolution is NOT here — the composition is known before the run,
/// so the orchestrator resolves it UP FRONT (see [`RunOutcome::CacheMiss`]) under
/// its own key, keeping the OCI-pull / compile probe surface off the worker
/// entirely. A [`CallbackServiceClient`] is passed to the worker as an argument to
/// [`ExecutorService::run`] — remoc multiplexes these callbacks over the SAME
/// connection as the in-flight run, so the key never crosses to the worker.
#[remoc::rtc::remote]
pub trait CallbackService {
    /// Rehydrate a stored blob by content hash (orchestrator unseals). `None` =
    /// miss (unknown / never-stored ref) — the worker's `from-blob-ref` traps
    /// on it, same as the in-process gate.
    async fn media_load(&self, hash: [u8; 32]) -> Result<Option<Vec<u8>>, CallbackError>;

    /// Seal + persist the post-round session state, plus any consented
    /// `disclosures` (non-empty only on a consent-disclosure accept) and
    /// captured `media` blobs (present only on a media round) — the owned form
    /// of the engine's borrowed `SessionChange`. The orchestrator commits them
    /// in ONE atomic transaction under the seal key the worker never holds.
    async fn session_change(
        &self,
        state: SessionState,
        disclosures: Vec<ConsentDisclosure>,
        media: Vec<([u8; 32], Vec<u8>)>,
    ) -> Result<(), CallbackError>;
}

/// The execute boundary as a remote trait. The execution-worker serves it; the
/// orchestrator calls it with a [`CallbackServiceClient`] pointing at its own
/// callback server so the keyless worker can rehydrate media / persist state
/// mid-round without ever holding the seal key. Two methods split the cache paths
/// cleanly:
///
///   * [`run`](ExecutorService::run) — the L1-cache path, NO bundle: `Ran` on a
///     hit, [`RunOutcome::CacheMiss`] on a miss.
///   * [`run_with_bundle`](ExecutorService::run_with_bundle) — the post-miss path:
///     the orchestrator supplies the bundle it resolved under its OWN key; the
///     worker files it in L1 and runs. Always runs, so it returns the [`RunReply`]
///     directly (no cache-miss outcome).
///
/// The worker only ever caches / serves under the orchestrator's `composition_key`
/// and never names one back, so a compromised worker cannot poison another
/// session's cache slot.
#[remoc::rtc::remote]
pub trait ExecutorService {
    async fn run(
        &self,
        req: RunRequest,
        callbacks: CallbackServiceClient<remoc::codec::Ciborium>,
    ) -> Result<RunOutcome, ExecError>;

    async fn run_with_bundle(
        &self,
        req: RunRequest,
        bundle: CompiledBundle,
        callbacks: CallbackServiceClient<remoc::codec::Ciborium>,
    ) -> Result<RunReply, ExecError>;
}

/// The supervisor↔child seam (INTERNAL to the execution-worker host — remoc over
/// a per-child socketpair, never over the api hop).
///
/// The execution-worker is a SUPERVISOR: it holds the bundle-byte L1 and runs NO
/// wasm itself. Per reducer round it spawns a fresh [`ChildService`] PROCESS,
/// [`prime`](ChildService::prime)s it once with the compiled bundle, drives
/// exactly one [`run`](ChildService::run), and discards the child. Untrusted
/// policy wasm — and the `Component::deserialize` unsafe sink — execute ONLY in
/// that disposable per-round process, so a sandbox escape is confined to one
/// round's plaintext (one applicant) behind an OS address-space boundary, with no
/// cross-round persistence.
#[remoc::rtc::remote]
pub trait ChildService {
    /// MMAP the cwasm (via `Component::deserialize_file` on `bundle.cwasm_path`)
    /// and build the reusable `InstancePre` (the engine's `prime`). The 7-15 MiB
    /// cwasm is NOT shipped — only the [`BundleRef`] path + small metadata cross
    /// the hop — so the child hop stays tiny. A deserialize failure (toolchain
    /// skew / tampered file) surfaces as [`ExecError::Run`].
    async fn prime(&self, bundle: BundleRef) -> Result<(), ExecError>;

    /// Drive one reducer round against the primed composition.
    /// `session_state`/`event`/`props` are the round's already-decrypted inputs
    /// (the seal key never reaches this process). `callbacks` points at the
    /// SUPERVISOR's relay, which forwards `media_load` / `session_change` on to
    /// api — so this keyless process rehydrates blobs + persists state without
    /// the seal key and WITHOUT the `load_component` probe surface.
    async fn run(
        &self,
        session_state: SessionState,
        event: Event,
        props: Vec<(String, Prop)>,
        callbacks: ChildCallbacksClient<remoc::codec::Ciborium>,
    ) -> Result<RunReply, ExecError>;
}

/// The supervisor-served callback boundary a per-round engine-executor-child calls BACK
/// during a run. NARROWER than [`CallbackService`] — it omits `load_component`:
/// the supervisor already resolved + primed the bundle before spawning the child,
/// so the process running UNTRUSTED wasm is never handed the OCI-pull / compile
/// probe surface (blast-radius minimization). The supervisor's relay implements
/// this and forwards each call to its own upstream [`CallbackServiceClient`]
/// (→ api, which holds the seal key). Method shapes mirror [`CallbackService`]'s
/// `media_load` / `session_change` exactly so the relay is a straight forward.
#[remoc::rtc::remote]
pub trait ChildCallbacks {
    /// Rehydrate a stored blob by content hash (api unseals). `None` = miss.
    async fn media_load(&self, hash: [u8; 32]) -> Result<Option<Vec<u8>>, CallbackError>;

    /// Seal + persist the post-round state, consented `disclosures`, and captured
    /// `media` — relayed to api's `session_change`, committed under the seal key
    /// this process never holds.
    async fn session_change(
        &self,
        state: SessionState,
        disclosures: Vec<ConsentDisclosure>,
        media: Vec<([u8; 32], Vec<u8>)>,
    ) -> Result<(), CallbackError>;
}

#[cfg(test)]
mod execute_tests {
    use super::*;
    use remoc::codec::Ciborium;
    use remoc::rtc::ServerShared;
    use std::sync::{Arc, Mutex};
    use tokio::io::split;

    /// Orchestrator-side callback target: records the media / state calls it
    /// receives and returns canned media, so the test can assert the worker called
    /// BACK with the right arguments mid-run.
    struct MockCallbacks {
        media_calls: Mutex<Vec<[u8; 32]>>,
        state_calls: Mutex<u32>,
    }

    impl CallbackService for MockCallbacks {
        async fn media_load(&self, hash: [u8; 32]) -> Result<Option<Vec<u8>>, CallbackError> {
            self.media_calls.lock().unwrap().push(hash);
            Ok(Some(vec![0xAB, 0xCD]))
        }
        async fn session_change(
            &self,
            _state: SessionState,
            _disclosures: Vec<ConsentDisclosure>,
            _media: Vec<([u8; 32], Vec<u8>)>,
        ) -> Result<(), CallbackError> {
            *self.state_calls.lock().unwrap() += 1;
            Ok(())
        }
    }

    /// Worker-side executor: `run` (cache-only) always MISSES in this mock (naming
    /// only its ABI id, NEVER the composition_key); `run_with_bundle` runs — calling
    /// the passed-in callback client (media_load + session_change) BACK — and replies.
    struct MockExecutor;

    impl ExecutorService for MockExecutor {
        async fn run(
            &self,
            _req: RunRequest,
            _callbacks: CallbackServiceClient<Ciborium>,
        ) -> Result<RunOutcome, ExecError> {
            // Cache-only path: always a miss in this mock (no L1). The worker returns
            // its ABI id and NEVER names the composition_key.
            Ok(RunOutcome::CacheMiss {
                compat_token: "test-token".into(),
            })
        }

        async fn run_with_bundle(
            &self,
            req: RunRequest,
            bundle: CompiledBundle,
            callbacks: CallbackServiceClient<Ciborium>,
        ) -> Result<RunReply, ExecError> {
            if bundle.cwasm.is_empty() {
                return Err(ExecError::Run("empty bundle".into()));
            }
            // Bundle in hand: run, calling BACK for media + state persistence.
            let bytes = callbacks.media_load([9u8; 32]).await?;
            if bytes != Some(vec![0xAB, 0xCD]) {
                return Err(ExecError::Run("callback returned wrong media".into()));
            }
            callbacks
                .session_change(req.session_state.clone(), vec![], vec![])
                .await?;
            Ok(RunReply {
                status: RunStatus::Completed(Decision::Approved),
            })
        }
    }

    type ExecCli = ExecutorServiceClient<Ciborium>;

    /// `run()` crosses to the worker WITH a callback client; on an L1 miss the
    /// worker returns `CacheMiss` (naming only its ABI id), the orchestrator
    /// resolves the bundle under ITS OWN key and re-drives with `bundle = Some(..)`,
    /// and only THEN does the keyless worker call `media_load` + `session_change`
    /// BACK, multiplexed over the ONE remoc connection. The worker never names the
    /// composition_key — the poison-a-foreign-slot vector is gone.
    #[tokio::test]
    async fn cache_miss_then_run_with_orchestrator_supplied_bundle() {
        let callbacks = Arc::new(MockCallbacks {
            media_calls: Mutex::new(Vec::new()),
            state_calls: Mutex::new(0),
        });

        let (a, b) = tokio::io::duplex(64 * 1024);
        let (a_r, a_w) = split(a);
        let (b_r, b_w) = split(b);

        // Worker end: serve the executor.
        let server_task = tokio::spawn(async move {
            let (conn, mut tx, _rx) = remoc::Connect::io::<_, _, ExecCli, ExecCli, Ciborium>(
                remoc::Cfg::default(),
                a_r,
                a_w,
            )
            .await
            .unwrap();
            tokio::spawn(conn);
            let (server, client) =
                ExecutorServiceServerShared::<_, Ciborium>::new(Arc::new(MockExecutor), 4);
            tx.send(client).await.unwrap();
            server.serve(true).await.unwrap();
        });

        // Orchestrator end: receive the executor client, stand up its OWN
        // callback server on the same connection, pass the callback client into
        // run().
        let (conn, _tx, mut rx) =
            remoc::Connect::io::<_, _, ExecCli, ExecCli, Ciborium>(remoc::Cfg::default(), b_r, b_w)
                .await
                .unwrap();
        tokio::spawn(conn);
        let exec_client = rx.recv().await.unwrap().unwrap();

        let (cb_server, cb_client) =
            CallbackServiceServerShared::<_, Ciborium>::new(callbacks.clone(), 4);
        tokio::spawn(async move {
            let _ = cb_server.serve(true).await;
        });

        let mk_req = || RunRequest {
            composition_key: "k".into(),
            props: vec![("age".into(), Prop::Int(30))],
            session_state: SessionState::default(),
            event: Event::Start,
        };

        // Phase 1: cache-only run → miss, and NOTHING runs (no callbacks fire).
        match exec_client.run(mk_req(), cb_client.clone()).await.unwrap() {
            RunOutcome::CacheMiss { compat_token } => assert_eq!(compat_token, "test-token"),
            RunOutcome::Ran(_) => panic!("expected CacheMiss on the cache-only run"),
        }

        // Phase 2: orchestrator resolved the bundle under ITS OWN composition_key
        // and re-drives via run_with_bundle; now the round runs and calls back once.
        let RunReply { status } = exec_client
            .run_with_bundle(mk_req(), crate::bundle::sample_bundle(), cb_client)
            .await
            .unwrap();
        assert!(matches!(status, RunStatus::Completed(Decision::Approved)));
        assert_eq!(
            callbacks.media_calls.lock().unwrap().as_slice(),
            &[[9u8; 32]]
        );
        assert_eq!(*callbacks.state_calls.lock().unwrap(), 1);

        drop(exec_client);
        server_task.abort();
    }
}
