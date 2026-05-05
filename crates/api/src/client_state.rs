//! State for the client-facing API listener (POST /sessions etc.).
//!
//! Distinct from `AppState` (applicant-facing API): clients authenticate
//! via host-side `AuthClient`, sessions are created here with attestation
//! quotes; the applicant flow uses BearerKey and continues from a session
//! that this listener already created.
//!
//! `runner` and `policies` are shared with `AppState` — the engine
//! lazily compiles policy wasm at applicant /connect and reuses the
//! cached `Component` for subsequent /input rounds. `session_store` is
//! also shared so writes from this side (metadata, status) and reads
//! from the applicant side (state) hit the same backing service.

use std::sync::Arc;

use enclavid_attestation::Attestor;
use enclavid_host_bridge::{AuthClient, GrpcChannel, RegistryClient, SessionStore, connect_store};

pub struct ClientState {
    pub auth: AuthClient,
    pub registry: RegistryClient,
    pub session_store: Arc<SessionStore>,
    pub attestor: Arc<dyn Attestor>,
}

impl ClientState {
    pub fn new(
        session_store: Arc<SessionStore>,
        channel: GrpcChannel,
        attestor: Arc<dyn Attestor>,
    ) -> Self {
        Self {
            auth: AuthClient::new(channel.clone()),
            registry: RegistryClient::new(channel),
            session_store,
            attestor,
        }
    }

    pub async fn init(
        transport_out: &str,
        session_store: Arc<SessionStore>,
        attestor: Arc<dyn Attestor>,
    ) -> Self {
        let channel = connect_store(transport_out)
            .await
            .expect("failed to connect store");
        Self::new(session_store, channel, attestor)
    }
}
