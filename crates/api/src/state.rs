use std::sync::Arc;

use secrecy::SecretBox;

use hatch_client::{CacheStore, HatchClient, KbsClient, RegistryClient, SessionStore};

use crate::compiler::{Compiler, connect_compile_worker};
use crate::executor::{Executor, connect_execution_worker};
use crate::shuffle::ShuffleKey;

/// Applicant key held in TEE memory for the duration of a request. Raw
/// bytes used as the inner AEAD layer key for session state + media.
/// `SecretBox` provides zeroization on drop and redacts from Debug output.
/// Sourced fresh from the request bearer by [`super::applicant::auth`]; not
/// cached — a wrong key is rejected cryptographically at the state read
/// (`BridgeError::Crypto` → 403), so there is no first-claim table to keep.
pub type ApplicantSessionToken = SecretBox<Vec<u8>>;

pub struct AppState {
    /// The COMPILE boundary the cold path calls: hand pulled artifact bytes to a
    /// compile-worker over rpc, get back a `CompiledBundle`. api NEVER compiles
    /// in-process (no Cranelift); the worker is started by infrastructure and
    /// api [`connect`](connect_compile_worker)s to it. See [`crate::compiler`].
    pub compiler: Arc<Compiler>,
    /// The EXECUTE boundary each reducer round drives: a client for the remote
    /// execution-worker (started by infrastructure; api [`connect`s]
    /// (connect_execution_worker) to it). api holds NO wasmtime — the round runs
    /// on the worker, which calls back for media / state persistence via the
    /// per-run CallbackService (api holds the seal key, the worker does not). See
    /// [`crate::executor`]. The orchestrator delegates compile + execute through
    /// these two client boundaries.
    pub executor: Arc<Executor>,
    /// L2 compiled-policy cache: hatch-backed, AEAD-sealed cwasm bundles, keyed
    /// by `(composition_key, compat_token)`. This is the orchestrator's ONLY
    /// compiled-artifact store — there is NO api-side in-RAM L1; the sole
    /// in-memory component cache lives on the execution-worker, which reports a
    /// miss rather than filling it itself. `resolve_bundle` (`applicant::shared`)
    /// is the L2-read-or-compile-and-store entry point that miss drives. See
    /// [`crate::cwasm_cache`].
    pub cache_store: CacheStore,
    pub session_store: Arc<SessionStore>,
    /// Registry client used by /connect for the lazy policy pull.
    /// Same hatch connection as the rest of hatch-client.
    pub registry: RegistryClient,
    /// KBS relay client for the `kbs` key path: couriers each Trustee
    /// RCAR leg to the artifact owner's KBS through the hatch. Same hatch
    /// connection.
    pub kbs: KbsClient,
    /// Per-session `DisplayField` shuffle seeds are HKDF-derived from
    /// this key + the session id at `/connect`-time and threaded
    /// into `engine::RunInputs`. See [`crate::shuffle`] for the
    /// derivation contract and threat model.
    pub shuffle_key: Arc<ShuffleKey>,
}

impl AppState {
    pub fn new(
        session_store: Arc<SessionStore>,
        hatch: HatchClient,
        compiler: Arc<Compiler>,
        executor: Arc<Executor>,
        shuffle_key: Arc<ShuffleKey>,
        cache_store: CacheStore,
    ) -> Self {
        // Registry + KBS share the hatch connection (cheap Clone: hyper Client is
        // Arc-backed) — these are EXTERNAL egress and stay on the hatch
        // regardless of the storage backend. The L2 `cache_store` is built by the
        // caller (`main`) on the selected cache backend (hatch object_store or the
        // storage-CVM) and sealed under an HKDF subkey of `tee_seal_key`.
        let kbs = KbsClient::new(hatch.clone());
        // Both boundaries are remote clients connected by the caller (`init`):
        // `compiler` → the compile-worker, `executor` → the execution-worker.
        Self {
            compiler,
            executor,
            cache_store,
            session_store,
            registry: RegistryClient::new(hatch),
            kbs,
            shuffle_key,
        }
    }

    /// Connect to hatch-client + both engine workers and build state. BOTH the
    /// COMPILE and EXECUTE boundaries are remote clients dialed here — the
    /// workers are separate processes/CVMs started by infrastructure (like the
    /// hatch), NOT spawned by api. api itself links neither Cranelift nor the
    /// wasmtime runtime.
    pub async fn init(
        transport_out: &str,
        session_store: Arc<SessionStore>,
        cache_store: CacheStore,
        shuffle_key: Arc<ShuffleKey>,
        attestor: Arc<dyn enclavid_attestation::Attestor>,
    ) -> Self {
        let hatch = HatchClient::new(transport_out)
            .await
            .expect("failed to connect to hatch");
        // Addresses are explicit config; fail loud if unset (minimal-defaults).
        let compile_addr = std::env::var("ENCLAVID_COMPILE_WORKER_ADDR").expect(
            "ENCLAVID_COMPILE_WORKER_ADDR not set (address of the compile-worker; start one \
             with `cargo run -p engine-compiler --features worker --bin compile-worker` and \
             point api at its listen address)",
        );
        let compiler = Arc::new(
            crate::fleet::dial("compile-worker", || {
                connect_compile_worker(&compile_addr, attestor.clone())
            })
            .await
            .expect("failed to connect to compile-worker"),
        );
        let exec_addr = std::env::var("ENCLAVID_EXECUTION_WORKER_ADDR").expect(
            "ENCLAVID_EXECUTION_WORKER_ADDR not set (address of the execution-worker; start one \
             with `cargo run -p engine-executor --features worker --bin execution-worker` and \
             point api at its listen address)",
        );
        let executor = Arc::new(
            crate::fleet::dial("execution-worker", || {
                connect_execution_worker(&exec_addr, attestor.clone())
            })
            .await
            .expect("failed to connect to execution-worker"),
        );
        Self::new(
            session_store,
            hatch,
            compiler,
            executor,
            shuffle_key,
            cache_store,
        )
    }
}
