use std::sync::Arc;
use std::time::Duration;

use age::x25519::Identity;
use moka::future::Cache;
use secrecy::SecretBox;

use enclavid_engine::Runner;
use enclavid_host_bridge::{GrpcChannel, ReportStore, SessionStore, connect_store};

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
    /// Shared with the client API state (same Engine compiles policy on
    /// /init, runs it on /input).
    pub runner: Arc<Runner>,
    /// Compiled per-session components, populated by /init in the client
    /// API and read here on every /input. Lookup miss = session not yet
    /// initialized or evicted past TTL.
    pub policies: SessionPolicyCache,
    pub session_store: Arc<SessionStore>,
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
