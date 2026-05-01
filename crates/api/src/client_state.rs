//! State for the client-facing API listener (POST /sessions etc.).
//!
//! Distinct from `AppState` (applicant-facing API): clients authenticate
//! via host-side `AuthClient`, sessions are created here with attestation
//! quotes and ephemeral keypairs. The applicant flow uses BearerKey and
//! continues from a session that this listener already created.
//!
//! `runner` and `policies` are shared with `AppState` — same Engine
//! compiles wasm at /init and runs it at /input.

use std::sync::Arc;
use std::time::Duration;

use age::x25519::Identity;
use moka::future::Cache;

use enclavid_attestation::Attestor;
use enclavid_engine::Runner;
use enclavid_session_store::{
    AuthClient, GrpcChannel, MetadataStore, RegistryClient, connect_store,
};

use crate::runtime::SessionPolicyCache;

/// Cache of per-session ephemeral X25519 identities.
///
/// The private half of each entry NEVER leaves this process. Persisting
/// it would defeat the per-session ephemerality property: a single dump
/// of disk state must not yield the means to decrypt past wrapped K_client
/// values. TTL bounded so stale PendingInit entries are dropped.
pub type EphemeralIdentityCache = Cache<String, Arc<Identity>>;

pub struct ClientState {
    pub auth: AuthClient,
    pub registry: RegistryClient,
    pub metadata_store: MetadataStore,
    pub attestor: Arc<dyn Attestor>,
    pub ephemeral_identities: EphemeralIdentityCache,
    /// Compiles decrypted policy wasm to a `Component` and inserts under
    /// `session_id`. The applicant API reads from the same cache on /input.
    pub runner: Arc<Runner>,
    pub policies: SessionPolicyCache,
}

impl ClientState {
    pub fn new(
        channel: GrpcChannel,
        attestor: Arc<dyn Attestor>,
        runner: Arc<Runner>,
        policies: SessionPolicyCache,
    ) -> Self {
        let ephemeral_identities = Cache::builder()
            .max_capacity(10_000)
            .time_to_idle(Duration::from_secs(900)) // 15 min — well past PENDING_INIT_TTL
            .build();

        Self {
            auth: AuthClient::new(channel.clone()),
            registry: RegistryClient::new(channel.clone()),
            metadata_store: MetadataStore::new(channel),
            attestor,
            ephemeral_identities,
            runner,
            policies,
        }
    }

    pub async fn init(
        transport_out: &str,
        attestor: Arc<dyn Attestor>,
        runner: Arc<Runner>,
        policies: SessionPolicyCache,
    ) -> Self {
        let channel = connect_store(transport_out)
            .await
            .expect("failed to connect store");
        Self::new(channel, attestor, runner, policies)
    }
}
