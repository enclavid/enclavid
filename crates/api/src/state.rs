use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use secrecy::SecretBox;

use enclavid_engine::Runner;
use enclavid_session_store::{connect_uds, DisclosureStore, MetadataStore, StateStore};

/// Client key held in TEE memory for the duration of a session.
/// Raw bytes used for AES-256-GCM encryption of session state.
/// `SecretBox` provides zeroization on drop and redacts from Debug output.
pub type ClientKey = SecretBox<Vec<u8>>;

/// LRU cache of active session client keys.
/// Size-bounded to prevent DoS via unbounded session creation.
/// TTL-bounded to evict stale keys.
pub type ClientKeyCache = Cache<String, Arc<ClientKey>>;

pub struct AppState {
    pub runner: Runner,
    pub metadata_store: MetadataStore,
    pub state_store: StateStore,
    pub disclosure_store: DisclosureStore,
    pub client_keys: ClientKeyCache,
}

impl AppState {
    pub async fn init(socket_path: &str) -> Self {
        let channel = connect_uds(socket_path)
            .await
            .expect("failed to connect store");

        let client_keys = Cache::builder()
            .max_capacity(10_000)
            .time_to_idle(Duration::from_secs(3600))
            .build();

        Self {
            runner: Runner::new().expect("failed to create runner"),
            metadata_store: MetadataStore::new(channel.clone()),
            state_store: StateStore::new(channel.clone()),
            disclosure_store: DisclosureStore::new(channel),
            client_keys,
        }
    }
}
