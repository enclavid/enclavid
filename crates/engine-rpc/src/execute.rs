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

use crate::CompiledBundle;

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

/// A load_component failure — a CONFIG-resolution failure (OCI pull / compile /
/// digest), which is a pure function of the pinned config (no applicant input,
/// no PII), so it carries the HTTP `status` the orchestrator surfaces to the
/// consumer VERBATIM (e.g. 410 GONE on a removed artifact). Distinct from
/// [`CallbackError`] (opaque runtime callbacks) precisely so this status
/// survives the round trip back to the orchestrator instead of flattening to 500.
#[derive(Debug, Serialize, Deserialize)]
pub struct LoadError {
    pub status: u16,
    pub message: String,
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "load_component failed ({}): {}", self.status, self.message)
    }
}
impl std::error::Error for LoadError {}
impl From<remoc::rtc::CallError> for LoadError {
    fn from(err: remoc::rtc::CallError) -> Self {
        // A transport failure isn't a config verdict — surface as a generic 500.
        LoadError { status: 500, message: format!("load_component rpc failed: {err}") }
    }
}

/// A run failure. Two kinds so the orchestrator can classify without string-
/// sniffing: [`Config`](ExecError::Config) — a config-resolution failure relayed
/// from `load_component`, whose HTTP status is surfaced verbatim; [`Run`]
/// (ExecError::Run) — an opaque trap / instantiate / host-fn / transport failure,
/// mapped to 500 (with the text-ref 422 substring exception the orchestrator
/// still applies).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ExecError {
    Run(String),
    Config { status: u16, message: String },
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecError::Run(m) => write!(f, "run failed: {m}"),
            ExecError::Config { status, message } => {
                write!(f, "config resolution failed ({status}): {message}")
            }
        }
    }
}
impl std::error::Error for ExecError {}
impl From<remoc::rtc::CallError> for ExecError {
    fn from(err: remoc::rtc::CallError) -> Self {
        ExecError::Run(format!("run rpc failed: {err}"))
    }
}
/// A config-resolution failure from a mid-run `load_component` bubbles up with
/// its status intact.
impl From<LoadError> for ExecError {
    fn from(e: LoadError) -> Self {
        ExecError::Config { status: e.status, message: e.message }
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

/// One reducer round's inputs on the wire. NO bundle — the worker owns the L1
/// component cache and PULLS the compiled bundle via
/// [`CallbackService::load_component`] only on a cache miss.
/// `session_state`/`event`/`props` are the round's already-decrypted inputs
/// (the seal key stays orchestrator-side).
#[derive(Serialize, Deserialize)]
pub struct RunRequest {
    /// Names the fused component in the worker's L1 cache; echoed back in
    /// `load_component` on a miss so the orchestrator keys L2 identically.
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

/// The orchestrator-served CALLBACK boundary the keyless execution-worker calls
/// BACK during a run: the worker holds no seal key, so blob rehydration
/// (`media_load`), state persistence (`session_change`), AND compiled-bundle
/// resolution (`load_component`) all happen orchestrator-side. A
/// [`CallbackServiceClient`] is passed to the worker as an argument to
/// [`ExecutorService::run`] — remoc multiplexes the callback calls over the SAME
/// connection as the in-flight run, so the key never crosses to the worker and
/// there is no hand-rolled request-id duplex.
#[remoc::rtc::remote]
pub trait CallbackService {
    /// Resolve the compiled bundle for `composition_key` — the worker's L1-miss
    /// pull. The orchestrator serves it from L2 (sealed cwasm, keyed by
    /// `(composition_key, compat_token)`), or compiles on an L2 miss (OCI pull +
    /// compile-worker), seals it into L2, and returns it. `compat_token` is the
    /// worker's cwasm ABI id, so the orchestrator never hands back a cwasm an
    /// incompatible runtime can't deserialize.
    async fn load_component(
        &self,
        composition_key: String,
        compat_token: String,
    ) -> Result<CompiledBundle, LoadError>;

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
/// orchestrator calls [`run`](ExecutorService::run), passing a
/// [`CallbackServiceClient`] pointing at its own callback server so the keyless
/// worker can pull the bundle / rehydrate media / persist state mid-round
/// without ever holding the seal key.
#[remoc::rtc::remote]
pub trait ExecutorService {
    async fn run(
        &self,
        req: RunRequest,
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
    /// Deserialize the `cwasm` and build the reusable `InstancePre` (the
    /// engine's `prime`). Ships the ~10-15 MiB bundle, so the child connection
    /// MUST be built with [`connection_cfg`](crate::connection_cfg) (64 MiB
    /// `max_data_size`) — the remoc default would reject it. A deserialize
    /// failure (toolchain skew / tampered bytes) surfaces as [`ExecError::Run`].
    async fn prime(&self, bundle: CompiledBundle) -> Result<(), ExecError>;

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

/// The supervisor-served callback boundary a per-round session-child calls BACK
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

    /// Orchestrator-side callback target: records the calls it receives and
    /// returns canned media + a canned bundle, so the test can assert the worker
    /// called BACK with the right arguments mid-run.
    struct MockCallbacks {
        load_calls: Mutex<Vec<(String, String)>>,
        media_calls: Mutex<Vec<[u8; 32]>>,
        state_calls: Mutex<u32>,
    }

    impl CallbackService for MockCallbacks {
        async fn load_component(
            &self,
            composition_key: String,
            compat_token: String,
        ) -> Result<CompiledBundle, LoadError> {
            self.load_calls.lock().unwrap().push((composition_key, compat_token));
            Ok(crate::bundle::sample_bundle())
        }
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

    /// Worker-side executor: on a run it PULLS the bundle via `load_component`
    /// (the L1-miss path), then calls the passed-in callback client (media_load +
    /// session_change) BACK to the orchestrator, then replies.
    struct MockExecutor;

    impl ExecutorService for MockExecutor {
        async fn run(
            &self,
            req: RunRequest,
            callbacks: CallbackServiceClient<Ciborium>,
        ) -> Result<RunReply, ExecError> {
            // L1-miss pull: fetch the compiled bundle from the orchestrator
            // (`?` converts a LoadError into ExecError::Config, status intact).
            let bundle = callbacks
                .load_component(req.composition_key.clone(), "test-token".into())
                .await?;
            if bundle.cwasm.is_empty() {
                return Err(ExecError::Run("empty bundle".into()));
            }
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

    /// A config-resolution failure (e.g. 410 GONE on a removed artifact) keeps
    /// its HTTP status across `LoadError -> ExecError::Config`, so the
    /// orchestrator surfaces it verbatim instead of flattening to 500.
    #[test]
    fn load_error_status_survives_into_exec_error() {
        let e: ExecError = LoadError { status: 410, message: "artifact gone".into() }.into();
        match e {
            ExecError::Config { status, .. } => assert_eq!(status, 410),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    type ExecCli = ExecutorServiceClient<Ciborium>;

    /// The bidirectional gate: `run()` crosses to the worker WITH a callback
    /// client argument; the keyless worker invokes `load_component` + `media_load`
    /// + `session_change` BACK to the orchestrator mid-run, all multiplexed over
    /// the ONE remoc connection. This is the pattern that removes the hand-rolled
    /// duplex — and now the bundle is PULLED, not pushed.
    #[tokio::test]
    async fn execute_bidirectional_callbacks_over_remoc() {
        let callbacks = Arc::new(MockCallbacks {
            load_calls: Mutex::new(Vec::new()),
            media_calls: Mutex::new(Vec::new()),
            state_calls: Mutex::new(0),
        });

        let (a, b) = tokio::io::duplex(64 * 1024);
        let (a_r, a_w) = split(a);
        let (b_r, b_w) = split(b);

        // Worker end: serve the executor.
        let server_task = tokio::spawn(async move {
            let (conn, mut tx, _rx) =
                remoc::Connect::io::<_, _, ExecCli, ExecCli, Ciborium>(remoc::Cfg::default(), a_r, a_w)
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

        let reply = exec_client
            .run(
                RunRequest {
                    composition_key: "k".into(),
                    props: vec![("age".into(), Prop::Int(30))],
                    session_state: SessionState::default(),
                    event: Event::Start,
                },
                cb_client,
            )
            .await
            .unwrap();

        assert!(matches!(reply.status, RunStatus::Completed(Decision::Approved)));
        assert_eq!(
            callbacks.load_calls.lock().unwrap().as_slice(),
            &[("k".to_string(), "test-token".to_string())]
        );
        assert_eq!(callbacks.media_calls.lock().unwrap().as_slice(), &[[9u8; 32]]);
        assert_eq!(*callbacks.state_calls.lock().unwrap(), 1);

        drop(exec_client);
        server_task.abort();
    }
}
