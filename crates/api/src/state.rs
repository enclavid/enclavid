use std::sync::Arc;

use secrecy::SecretBox;

use hatch_client::{KbsClient, Link, RegistryClient};
use storage_client::{CacheStore, SessionStore};

use crate::boundary::Hatch;
use crate::compiler::{Compiler, connect_compile_worker};
use crate::compositions::Compositions;
use crate::executor::{Executor, connect_execution_worker};
use crate::shuffle::ShuffleKey;
use crate::turns::ConsumerTurns;

/// Applicant key held in TEE memory for the duration of a request. Raw
/// bytes used as the inner AEAD layer key for session state + media.
/// `SecretBox` provides zeroization on drop and redacts from Debug output.
/// Sourced fresh from the request bearer by [`super::applicant::auth`]; not
/// cached — a wrong key is rejected cryptographically at the state read
/// (`StoreError::Crypto` → 403), so there is no first-claim table to keep.
pub type ApplicantSessionToken = SecretBox<Vec<u8>>;

pub struct AppState {
    /// Compiling a composition and keeping it — the COMPILE boundary api drives
    /// over rpc (it never compiles in-process: no Cranelift), L2, the registry
    /// pulls, each consumer's turns, the KBS relay — shared with the client
    /// surface, whose warmups ask for compiles ahead of the rounds that miss. See
    /// [`crate::compositions`].
    pub compositions: Arc<Compositions>,
    /// The EXECUTE boundary each reducer round drives: a client for the remote
    /// execution-worker (started by infrastructure; api [`connect`s]
    /// (connect_execution_worker) to it). api holds NO wasmtime — the round runs
    /// on the worker, which calls back for media / state persistence via the
    /// per-run RemoteCallbacks (api holds the seal key, the worker does not). See
    /// [`crate::executor`]. The orchestrator delegates compile + execute through
    /// these two client boundaries.
    pub executor: Arc<Executor>,
    pub session_store: Arc<SessionStore>,
    /// Per-session `DisplayField` shuffle seeds are HKDF-derived from
    /// this key + the session id at `/connect`-time and threaded
    /// into `engine::RunInputs`. See [`crate::shuffle`] for the
    /// derivation contract and threat model.
    pub shuffle_key: Arc<ShuffleKey>,
}

impl AppState {
    /// `settings` says how long the hatch has to answer a pull and a KBS leg.
    pub fn new(
        session_store: Arc<SessionStore>,
        hatch: Arc<dyn Link<Hatch>>,
        compiler: Arc<Compiler>,
        executor: Arc<Executor>,
        shuffle_key: Arc<ShuffleKey>,
        cache_store: CacheStore,
        settings: &crate::settings::Settings,
    ) -> Self {
        // Registry + KBS share the hatch leg — they are EXTERNAL egress. The L2
        // `cache_store` is built by the caller (`main`) on the storage-CVM and
        // sealed under an HKDF subkey of `tee_seal_key`.
        let kbs = KbsClient::new(hatch.clone(), settings.kbs_deadline);
        // Both boundaries are remote clients connected by the caller (`init`):
        // `compiler` → the compile-worker, `executor` → the execution-worker.
        let compositions = Compositions::new(
            executor.clone(),
            compiler,
            cache_store,
            RegistryClient::new(hatch, settings.pull_deadline),
            ConsumerTurns::new(
                settings.registry_requests_per_consumer,
                settings.pull_deadline,
            ),
            kbs,
        );
        Self {
            compositions: Arc::new(compositions),
            executor,
            session_store,
            shuffle_key,
        }
    }

    /// Connect to both engine workers and build state over the `hatch` leg
    /// `main` holds. BOTH the COMPILE and EXECUTE boundaries are remote clients
    /// dialed here — the workers are separate CVMs started by infrastructure,
    /// NOT spawned by api. api itself links neither Cranelift nor the wasmtime
    /// runtime. The two addresses are `crate::fleet::legs`'; how they are
    /// dialed and held up is `settings`'.
    #[allow(clippy::too_many_arguments)]
    pub async fn init(
        hatch: Arc<dyn Link<Hatch>>,
        compile_addr: String,
        exec_addr: String,
        session_store: Arc<SessionStore>,
        cache_store: CacheStore,
        shuffle_key: Arc<ShuffleKey>,
        attestor: Arc<dyn enclavid_attestation::Attestor>,
        api_health: Arc<crate::health::ApiHealth>,
        settings: &crate::settings::Settings,
    ) -> Self {
        let tuning = settings.leg;
        let compile_leg = crate::fleet::Leg::new();
        {
            let addr = compile_addr.clone();
            let attestor = attestor.clone();
            crate::fleet::supervise(
                crate::health::Peer::CompileWorker,
                compile_addr.clone(),
                settings.leg_dial,
                api_health.clone(),
                move || {
                    let (addr, attestor) = (addr.clone(), attestor.clone());
                    async move { connect_compile_worker(&addr, attestor, tuning).await }
                },
                compile_leg.clone(),
            )
            .await;
        }
        let compiler = Arc::new(Compiler::new(compile_leg));
        let execute_leg = crate::fleet::Leg::new();
        {
            let addr = exec_addr.clone();
            let attestor = attestor.clone();
            let callback_buffer = settings.callback_request_buffer;
            crate::fleet::supervise(
                crate::health::Peer::ExecutionWorker,
                exec_addr.clone(),
                settings.leg_dial,
                api_health,
                move || {
                    let (addr, attestor) = (addr.clone(), attestor.clone());
                    async move {
                        connect_execution_worker(&addr, attestor, tuning, callback_buffer).await
                    }
                },
                execute_leg.clone(),
            )
            .await;
        }
        let executor = Arc::new(Executor::new(execute_leg));
        Self::new(
            session_store,
            hatch,
            compiler,
            executor,
            shuffle_key,
            cache_store,
            settings,
        )
    }
}
