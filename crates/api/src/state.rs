use std::sync::Arc;

use secrecy::SecretBox;

use engine_compiler::Compiler as EngineCompiler;
use engine_executor::Executor as EngineExecutor;
use broker_client::{BrokerClient, CacheStore, KbsClient, RegistryClient, SessionStore};

use crate::applicant::media_store::MediaCache;
use crate::compiler::{Compiler, LocalCompiler};
use crate::executor::{Executor, LocalExecutor};
use crate::runtime::PolicyCache;
use crate::shuffle::ShuffleKey;

/// Applicant key held in TEE memory for the duration of a request. Raw
/// bytes used as the inner AEAD layer key for session state + media.
/// `SecretBox` provides zeroization on drop and redacts from Debug output.
/// Sourced fresh from the request bearer by [`super::applicant::auth`]; not
/// cached — a wrong key is rejected cryptographically at the state read
/// (`BridgeError::Crypto` → 403), so there is no first-claim table to keep.
pub type ApplicantSessionToken = SecretBox<Vec<u8>>;

pub struct AppState {
    /// The COMPILE boundary the cold path calls: fuse + compile pulled artifact
    /// bytes into a `CompiledBundle`. In-process ([`LocalCompiler`]) today; a
    /// compile-worker CVM behind the same `Arc<dyn Compiler>` later. See
    /// [`crate::compiler`].
    pub compiler: Arc<dyn Compiler>,
    /// The EXECUTE boundary each reducer round drives: run the compiled policy
    /// against the decrypted state + event. In-process ([`LocalExecutor`])
    /// today; an execution-worker CVM behind the same `Arc<dyn Executor>` later.
    /// See [`crate::executor`]. The orchestrator no longer holds a `Runner`
    /// directly — it delegates compile + execute through these two boundaries.
    pub executor: Arc<dyn Executor>,
    /// Two-tier compiled-policy cache (L1 in-RAM + L2 broker-backed sealed
    /// cwasm), keyed by composition hash. `lookup_policy` resolves through
    /// its single `get_or_compute` ladder — L1 → L2 → cold pull+compile —
    /// with request coalescing. See [`PolicyCache`](crate::runtime::PolicyCache).
    pub policy_cache: PolicyCache,
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
        compiler_engine: Arc<EngineCompiler>,
        executor_engine: Arc<EngineExecutor>,
        shuffle_key: Arc<ShuffleKey>,
        tee_seal_key: &[u8; 32],
    ) -> Self {
        // Registry + KBS + cache share the same broker connection (cheap
        // Clone: hyper Client is Arc-backed). The L2 cache seals under an
        // HKDF subkey of the same `tee_seal_key` (domain-separated internally);
        // it holds the execute engine to deserialize cached cwasm.
        let kbs = KbsClient::new(broker.clone());
        let cache_store = CacheStore::new(broker.clone(), tee_seal_key);
        let policy_cache = PolicyCache::new(cache_store, executor_engine.clone());
        // In-process compile + execute boundaries; each swaps to a Remote*
        // (compile-worker / execution-worker CVM) behind the same trait with no
        // caller change. The compile engine (Cranelift) and execute engine
        // (runtime-only) are DISTINCT — a cwasm compiled by the former
        // deserializes on the latter (matching `engine_config`), the in-process
        // proof of the cross-CVM bridge.
        let compiler: Arc<dyn Compiler> = Arc::new(LocalCompiler::new(compiler_engine));
        let executor: Arc<dyn Executor> = Arc::new(LocalExecutor::new(executor_engine));
        Self {
            compiler,
            executor,
            policy_cache,
            session_store,
            registry: RegistryClient::new(broker),
            kbs,
            shuffle_key,
            media_cache: Arc::new(MediaCache::new()),
        }
    }

    /// Connect to broker-client and build state. The compile + execute
    /// engines are passed in (owned by the applicant surface — the client API
    /// never compiles or runs); the policy cache is built here.
    pub async fn init(
        transport_out: &str,
        session_store: Arc<SessionStore>,
        compiler_engine: Arc<EngineCompiler>,
        executor_engine: Arc<EngineExecutor>,
        shuffle_key: Arc<ShuffleKey>,
        tee_seal_key: &[u8; 32],
    ) -> Self {
        let broker = BrokerClient::new(transport_out)
            .await
            .expect("failed to connect to broker");
        Self::new(
            session_store,
            broker,
            compiler_engine,
            executor_engine,
            shuffle_key,
            tee_seal_key,
        )
    }
}
