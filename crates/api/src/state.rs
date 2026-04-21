use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use secrecy::SecretBox;

use enclavid_engine::wasmtime_shim::component::Component;
use enclavid_engine::Runner;
use enclavid_session_store::{
    connect_uds, DisclosureStore, MetadataStore, ReportStore, StateStore,
};

/// Applicant key held in TEE memory for the duration of a session.
/// Raw bytes used for AES-256-GCM encryption of session state.
/// `SecretBox` provides zeroization on drop and redacts from Debug output.
pub type ApplicantKey = SecretBox<Vec<u8>>;

/// LRU cache of active session applicant keys.
/// Size-bounded to prevent DoS via unbounded session creation.
/// TTL-bounded to evict stale keys.
pub type ApplicantKeyCache = Cache<String, Arc<ApplicantKey>>;

pub struct AppState {
    pub runner: Runner,
    pub policy: Component,
    pub metadata_store: MetadataStore,
    pub state_store: StateStore,
    pub disclosure_store: DisclosureStore,
    pub report_store: ReportStore,
    pub applicant_keys: ApplicantKeyCache,
}

impl AppState {
    pub async fn init(socket_path: &str, policy_bytes: &[u8]) -> Self {
        let channel = connect_uds(socket_path)
            .await
            .expect("failed to connect store");

        let applicant_keys = Cache::builder()
            .max_capacity(10_000)
            .time_to_idle(Duration::from_secs(3600))
            .build();

        let runner = Runner::new().expect("failed to create runner");
        let policy = runner.compile(policy_bytes).expect("failed to compile policy");

        Self {
            runner,
            policy,
            metadata_store: MetadataStore::new(channel.clone()),
            state_store: StateStore::new(channel.clone()),
            disclosure_store: DisclosureStore::new(channel.clone()),
            report_store: ReportStore::new(channel),
            applicant_keys,
        }
    }
}
