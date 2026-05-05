mod applicant;
mod client;
mod client_state;
mod input;
mod policy_pull;
mod runtime;
mod state;
mod transport;

use std::sync::Arc;

use enclavid_attestation::{Attestor, MockAttestor};
use enclavid_host_bridge::{SessionStore, connect_store};

use crate::client_state::ClientState;
use crate::state::AppState;

#[tokio::main]
async fn main() {
    let address_out = std::env::var("ENCLAVID_ADDRESS_OUT").expect("ENCLAVID_ADDRESS_OUT not set");

    // Single per-process wasmtime Engine + cache of compiled policy
    // components, owned by the applicant `AppState`. Compilation
    // happens lazily on the first /connect for each session
    // (pulling and decrypting the policy artifact with the K_client
    // persisted in metadata) and is reused for subsequent /input
    // rounds.
    let runner = runtime::new_runner();
    let policies = runtime::new_policy_cache();

    // SessionStore is the host-bridge gRPC client for per-session
    // typed-field storage. Shared between client API (writes
    // metadata/status on /create and /init) and applicant API
    // (reads/writes state on /connect and /input). Wrapped in Arc so
    // the DisclosureStore facade and both state structs hold the same
    // tonic channel underneath.
    //
    // TODO: derive `tee_key` from attestation / KMS rather than env.
    // For Phase A we accept a 32-byte hex from `ENCLAVID_TEE_KEY` (set
    // to a random value per deployment). When attestation-bound key
    // material lands, this becomes derive-on-startup.
    let tee_key = load_tee_key();
    let channel = connect_store(&address_out)
        .await
        .expect("failed to connect host-bridge");
    let session_store = Arc::new(SessionStore::new(channel, tee_key));

    // Two listeners, two routers, one process. Topology rationale: TLS
    // terminates inside this TEE, so a host-side proxy can only route by
    // SNI on raw TCP. Each surface (clients vs applicants) gets its own
    // certificate, port, optional mTLS posture, and rate-limit policy.
    // Each surface owns its route table — see `client::router` and
    // `applicant::router` for the endpoint inventory.
    let attestor: Arc<dyn Attestor> = Arc::new(MockAttestor::new_random());
    let client_state =
        Arc::new(ClientState::init(&address_out, session_store.clone(), attestor).await);
    let applicant_state =
        Arc::new(AppState::init(&address_out, session_store, runner, policies).await);

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

/// Load the 32-byte TEE AEAD key. Phase A: from `ENCLAVID_TEE_KEY`
/// (hex-encoded, 64 chars). Phase B: derive from attestation /
/// KMS-bound material so a process restart with a fresh key cannot
/// read prior session state.
fn load_tee_key() -> [u8; 32] {
    let hex_str = std::env::var("ENCLAVID_TEE_KEY")
        .expect("ENCLAVID_TEE_KEY not set (32-byte hex)");
    let bytes = hex::decode(hex_str).expect("ENCLAVID_TEE_KEY: invalid hex");
    bytes
        .try_into()
        .expect("ENCLAVID_TEE_KEY: must be 32 bytes")
}
