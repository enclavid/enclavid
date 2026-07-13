use std::sync::Arc;

use secrecy::SecretBox;

use enclavid_engine::Runner;
use broker_client::{BrokerClient, KbsClient, RegistryClient, SessionStore};

use crate::applicant::media_store::MediaCache;
use crate::runtime::SessionPolicyCache;
use crate::shuffle::ShuffleKey;

/// Applicant key held in TEE memory for the duration of a request. Raw
/// bytes used as the inner AEAD layer key for session state + media.
/// `SecretBox` provides zeroization on drop and redacts from Debug output.
/// Sourced fresh from the request bearer by [`super::applicant::auth`]; not
/// cached — a wrong key is rejected cryptographically at the state read
/// (`BridgeError::Crypto` → 403), so there is no first-claim table to keep.
pub type ApplicantSessionToken = SecretBox<Vec<u8>>;

pub struct AppState {
    /// Shared with the client API state — the engine compiles policy
    /// lazily at first /connect for a session, then reuses the cached
    /// `Component` for subsequent /input rounds.
    pub runner: Arc<Runner>,
    /// Per-session compiled components. Populated lazily by /connect
    /// when first hit; cache miss triggers pull+compile from the
    /// pinned policy ref in metadata.
    pub policies: SessionPolicyCache,
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
        runner: Arc<Runner>,
        policies: SessionPolicyCache,
        shuffle_key: Arc<ShuffleKey>,
    ) -> Self {
        // Registry + KBS share the same broker connection (cheap Clone:
        // hyper Client is Arc-backed).
        let kbs = KbsClient::new(broker.clone());
        Self {
            runner,
            policies,
            session_store,
            registry: RegistryClient::new(broker),
            kbs,
            shuffle_key,
            media_cache: Arc::new(MediaCache::new()),
        }
    }

    /// Connect to broker-client and build state. The runner and policy
    /// cache are passed in so they can be shared with the client API.
    pub async fn init(
        transport_out: &str,
        session_store: Arc<SessionStore>,
        runner: Arc<Runner>,
        policies: SessionPolicyCache,
        shuffle_key: Arc<ShuffleKey>,
    ) -> Self {
        let broker = BrokerClient::new(transport_out)
            .await
            .expect("failed to connect to broker");
        Self::new(
            session_store,
            broker,
            runner,
            policies,
            shuffle_key,
        )
    }
}
