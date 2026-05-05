use std::sync::Arc;
use std::time::Duration;

use age::x25519::Identity;
use moka::future::Cache;
use secrecy::SecretBox;

use enclavid_engine::Runner;
use enclavid_host_bridge::{GrpcChannel, RegistryClient, ReportStore, SessionStore, connect_store};

use crate::runtime::SessionPolicyCache;

/// Generate a placeholder age recipient for the platform reports
/// channel. The matching private half is dropped immediately — for
/// Phase B the seal step works (host sees opaque ciphertext), but no
/// component in this codebase decrypts these reports yet. Phase C
/// will replace this with a long-lived platform identity (KMS-bound)
/// whose private key lives outside the TEE so the operator can read
/// what was reported.
fn stub_platform_recipient() -> String {
    Identity::generate().to_public().to_string()
}

/// Applicant key held in TEE memory for the duration of a session.
/// Raw bytes used for AES-256-GCM encryption of session state.
/// `SecretBox` provides zeroization on drop and redacts from Debug output.
pub type ApplicantKey = SecretBox<Vec<u8>>;

/// LRU cache of active session applicant keys.
/// Size-bounded to prevent DoS via unbounded session creation.
/// TTL-bounded to evict stale keys.
pub type ApplicantKeyCache = Cache<String, Arc<ApplicantKey>>;

pub struct AppState {
    /// Shared with the client API state — the engine compiles policy
    /// lazily at first /connect for a session, then reuses the cached
    /// `Component` for subsequent /input rounds.
    pub runner: Arc<Runner>,
    /// Per-session compiled components. Populated lazily by /connect
    /// when first hit; cache miss triggers pull+decrypt+compile from
    /// the K_client persisted in metadata.
    pub policies: SessionPolicyCache,
    pub session_store: Arc<SessionStore>,
    /// Registry client used by /connect for the lazy policy pull.
    /// Same channel as the rest of host-bridge.
    pub registry: RegistryClient,
    pub report_store: ReportStore,
    pub applicant_keys: ApplicantKeyCache,
}

impl AppState {
    pub fn new(
        session_store: Arc<SessionStore>,
        channel: GrpcChannel,
        runner: Arc<Runner>,
        policies: SessionPolicyCache,
    ) -> Self {
        let applicant_keys = Cache::builder()
            .max_capacity(10_000)
            .time_to_idle(Duration::from_secs(3600))
            .build();

        Self {
            runner,
            policies,
            session_store,
            registry: RegistryClient::new(channel.clone()),
            report_store: ReportStore::new(channel, stub_platform_recipient()),
            applicant_keys,
        }
    }

    /// Connect to host-bridge and build state. The runner and policy
    /// cache are passed in so they can be shared with the client API.
    pub async fn init(
        transport_out: &str,
        session_store: Arc<SessionStore>,
        runner: Arc<Runner>,
        policies: SessionPolicyCache,
    ) -> Self {
        let channel = connect_store(transport_out)
            .await
            .expect("failed to connect store");
        Self::new(session_store, channel, runner, policies)
    }
}
