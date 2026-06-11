use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use secrecy::SecretBox;

use enclavid_engine::Runner;
use enclavid_host_bridge::{GrpcChannel, RegistryClient, SessionStore, connect_store};

use crate::ref_key::RefKey;
use crate::runtime::SessionPolicyCache;
use crate::shuffle::ShuffleKey;

/// Applicant key held in TEE memory for the duration of a session.
/// Raw bytes used for AES-256-GCM encryption of session state.
/// `SecretBox` provides zeroization on drop and redacts from Debug output.
pub type ApplicantSessionToken = SecretBox<Vec<u8>>;

/// LRU cache of active session applicant keys.
/// Size-bounded to prevent DoS via unbounded session creation.
/// TTL-bounded to evict stale keys.
pub type ApplicantSessionTokenCache = Cache<String, Arc<ApplicantSessionToken>>;

pub struct AppState {
    /// Shared with the client API state — the engine compiles policy
    /// lazily at first /connect for a session, then reuses the cached
    /// `Component` for subsequent /input rounds.
    pub runner: Arc<Runner>,
    /// Per-session compiled components. Populated lazily by /connect
    /// when first hit; cache miss triggers pull+decrypt+compile from
    /// the client_policy_key persisted in metadata.
    pub policies: SessionPolicyCache,
    pub session_store: Arc<SessionStore>,
    /// Registry client used by /connect for the lazy policy pull.
    /// Same channel as the rest of host-bridge.
    pub registry: RegistryClient,
    pub applicant_session_tokens: ApplicantSessionTokenCache,
    /// Per-session `DisplayField` shuffle seeds are HKDF-derived from
    /// this key + the session id at `/connect`-time and threaded
    /// into `engine::RunInputs`. See [`crate::shuffle`] for the
    /// derivation contract and threat model.
    pub shuffle_key: Arc<ShuffleKey>,
    /// Base key for the engine's `EmbeddedRegistry` ref token
    /// derivation. Per-policy 32-byte ref_keys are HKDF-derived from
    /// this base at `lookup_policy`-time and passed into
    /// `EmbeddedRegistry::builder(ref_key)`. See [`crate::ref_key`]
    /// for the derivation contract and threat model (forgery defence
    /// against a guest WASM synthesising a foreign-slot ref).
    pub ref_key: Arc<RefKey>,
}

impl AppState {
    pub fn new(
        session_store: Arc<SessionStore>,
        channel: GrpcChannel,
        runner: Arc<Runner>,
        policies: SessionPolicyCache,
        shuffle_key: Arc<ShuffleKey>,
        ref_key: Arc<RefKey>,
    ) -> Self {
        let applicant_session_tokens = Cache::builder()
            .max_capacity(10_000)
            .time_to_idle(Duration::from_secs(3600))
            .build();

        Self {
            runner,
            policies,
            session_store,
            registry: RegistryClient::new(channel),
            applicant_session_tokens,
            shuffle_key,
            ref_key,
        }
    }

    /// Connect to host-bridge and build state. The runner and policy
    /// cache are passed in so they can be shared with the client API.
    pub async fn init(
        transport_out: &str,
        session_store: Arc<SessionStore>,
        runner: Arc<Runner>,
        policies: SessionPolicyCache,
        shuffle_key: Arc<ShuffleKey>,
        ref_key: Arc<RefKey>,
    ) -> Self {
        let channel = connect_store(transport_out)
            .await
            .expect("failed to connect store");
        Self::new(session_store, channel, runner, policies, shuffle_key, ref_key)
    }
}
