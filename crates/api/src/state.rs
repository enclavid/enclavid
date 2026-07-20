use std::sync::Arc;

use secrecy::SecretBox;

use broker_client::{BrokerClient, CacheStore, KbsClient, RegistryClient, SessionStore};

use crate::applicant::media_store::MediaCache;
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
    /// L2 compiled-policy cache: broker-backed, AEAD-sealed cwasm bundles, keyed
    /// by `(composition_key, compat_token)`. This is the orchestrator's ONLY
    /// compiled-artifact store — there is NO api-side in-RAM L1; the sole
    /// in-memory component cache lives on the execution-worker, which pulls a
    /// bundle from here via `load_component` on a miss. `resolve_bundle`
    /// (`applicant::shared`) is the L2-read-or-compile-and-store entry point the
    /// `load_component` callback drives. See [`crate::cwasm_cache`].
    pub cache_store: CacheStore,
    pub session_store: Arc<SessionStore>,
    /// Registry client used by /connect for the lazy policy pull.
    /// Same broker connection as the rest of broker-client.
    pub registry: RegistryClient,
    /// KBS relay client for the `kbs` key path: couriers each Trustee
    /// RCAR leg to the artifact owner's KBS through the broker. Same broker
    /// connection.
    pub kbs: KbsClient,
    /// Per-session `DisplayField` shuffle seeds are HKDF-derived from
    /// this key + the session id at `/connect`-time and threaded
    /// into `engine::RunInputs`. See [`crate::shuffle`] for the
    /// derivation contract and threat model.
    pub shuffle_key: Arc<ShuffleKey>,
    /// Pull-through cache of rehydrated applicant media, shared across a
    /// session's rounds. Serves repeat `blob::from-blob-ref` reads in-TEE so
    /// the host sees ≤1 broker read per distinct blob. See
    /// [`media_store`](crate::applicant::media_store).
    pub media_cache: Arc<MediaCache>,
}

impl AppState {
    pub fn new(
        session_store: Arc<SessionStore>,
        broker: BrokerClient,
        compiler: Arc<Compiler>,
        executor: Arc<Executor>,
        shuffle_key: Arc<ShuffleKey>,
        tee_seal_key: &[u8; 32],
    ) -> Self {
        // Registry + KBS + cache share the same broker connection (cheap
        // Clone: hyper Client is Arc-backed). The L2 cache seals under an
        // HKDF subkey of the same `tee_seal_key` (domain-separated internally)
        // and holds only BYTES (the CompiledBundle) — no wasmtime engine.
        let kbs = KbsClient::new(broker.clone());
        let cache_store = CacheStore::new(broker.clone(), tee_seal_key);
        // Both boundaries are remote clients connected by the caller (`init`):
        // `compiler` → the compile-worker, `executor` → the execution-worker.
        Self {
            compiler,
            executor,
            cache_store,
            session_store,
            registry: RegistryClient::new(broker),
            kbs,
            shuffle_key,
            media_cache: Arc::new(MediaCache::new()),
        }
    }

    /// Connect to broker-client + both engine workers and build state. BOTH the
    /// COMPILE and EXECUTE boundaries are remote clients dialed here — the
    /// workers are separate processes/CVMs started by infrastructure (like the
    /// broker), NOT spawned by api. api itself links neither Cranelift nor the
    /// wasmtime runtime.
    pub async fn init(
        transport_out: &str,
        session_store: Arc<SessionStore>,
        shuffle_key: Arc<ShuffleKey>,
        tee_seal_key: &[u8; 32],
    ) -> Self {
        let broker = BrokerClient::new(transport_out)
            .await
            .expect("failed to connect to broker");
        // Addresses are explicit config; fail loud if unset (minimal-defaults).
        let compile_addr = std::env::var("ENCLAVID_COMPILE_WORKER_ADDR").expect(
            "ENCLAVID_COMPILE_WORKER_ADDR not set (address of the compile-worker; start one \
             with `cargo run -p engine-compiler --features worker --bin compile-worker` and \
             point api at its listen address)",
        );
        let compiler = Arc::new(
            connect_compile_worker(&compile_addr)
                .await
                .expect("failed to connect to compile-worker"),
        );
        let exec_addr = std::env::var("ENCLAVID_EXECUTION_WORKER_ADDR").expect(
            "ENCLAVID_EXECUTION_WORKER_ADDR not set (address of the execution-worker; start one \
             with `cargo run -p engine-executor --features worker --bin execution-worker` and \
             point api at its listen address)",
        );
        let executor = Arc::new(
            connect_execution_worker(&exec_addr)
                .await
                .expect("failed to connect to execution-worker"),
        );
        Self::new(
            session_store,
            broker,
            compiler,
            executor,
            shuffle_key,
            tee_seal_key,
        )
    }
}
