mod applicant;
mod auth;
mod client;
mod client_state;
mod input;
mod policy_pull;
mod runtime;
mod state;
mod transport;

use std::sync::Arc;

use enclavid_attestation::{Attestor, MockAttestor};

use crate::client_state::ClientState;
use crate::state::AppState;

#[tokio::main]
async fn main() {
    let address_out = std::env::var("ENCLAVID_ADDRESS_OUT").expect("ENCLAVID_ADDRESS_OUT not set");

    // Shared per-process runtime: one wasmtime Engine + one cache of
    // compiled policy components, both Arc'd into the two state structs.
    // Compilation happens on /init (client API), instantiation on /input
    // (applicant API). They MUST share the same Engine — components are
    // not portable across engines.
    let runner = runtime::new_runner();
    let policies = runtime::new_policy_cache();

    // Two listeners, two routers, one process. Topology rationale: TLS
    // terminates inside this TEE, so a host-side proxy can only route by
    // SNI on raw TCP. Each surface (clients vs applicants) gets its own
    // certificate, port, optional mTLS posture, and rate-limit policy.
    // Each surface owns its route table — see `client::router` and
    // `applicant::router` for the endpoint inventory.
    let attestor: Arc<dyn Attestor> = Arc::new(MockAttestor::new_random());
    let client_state =
        Arc::new(ClientState::init(&address_out, attestor, runner.clone(), policies.clone()).await);
    let applicant_state = Arc::new(AppState::init(&address_out, runner, policies).await);

    let client_app = client::router(client_state);
    let applicant_app = applicant::router(applicant_state);

    let client_handle = tokio::spawn({
        let addr = std::env::var("ENCLAVID_ADDRESS_IN_CLIENT")
            .expect("ENCLAVID_ADDRESS_IN_CLIENT not set");
        async move {
            transport::serve(client_app, &addr).await;
        }
    });
    let applicant_handle = tokio::spawn({
        let addr = std::env::var("ENCLAVID_ADDRESS_IN_APPLICANT")
            .expect("ENCLAVID_ADDRESS_IN_APPLICANT not set");
        async move {
            transport::serve(applicant_app, &addr).await;
        }
    });

    let _ = tokio::join!(client_handle, applicant_handle);
}
