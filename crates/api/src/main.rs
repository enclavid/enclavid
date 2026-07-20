mod applicant;
mod client;
mod client_state;
mod compiler;
mod cwasm_cache;
mod disclosure_hash;
mod dto;
mod error;
mod executor;
mod input;
mod keyprovider;
mod limits;
mod locale;
mod policy_pull;
mod shuffle;
mod state;
mod transport;

use std::sync::Arc;

use enclavid_attestation::{Attestor, SnpDevAttestor};
use hatch_client::{HatchClient, SessionStore};

use crate::client_state::ClientState;
use crate::state::AppState;

#[tokio::main]
async fn main() {
    let address_out = std::env::var("ENCLAVID_ADDRESS_OUT").expect("ENCLAVID_ADDRESS_OUT not set");

    // SessionStore is the hatch-client HTTP-over-vsock client for
    // per-session typed-field storage. Shared between client API
    // (writes metadata/status on /create and /init) and applicant API
    // (reads/writes state on /connect and /input). Wrapped in Arc so
    // the DisclosureStore facade and both state structs hold the same
    // hatch connection underneath.
    //
    // TODO: derive `tee_seal_key` from attestation / KMS rather than env.
    // For Phase A we accept a 32-byte hex from `ENCLAVID_TEE_KEY` (set
    // to a random value per deployment). When attestation-bound key
    // material lands, this becomes derive-on-startup.
    let tee_seal_key = load_tee_seal_key();
    // Derive the process-lifetime shuffle key from the same TEE
    // secret. Domain-separated under a distinct info string so we
    // don't reuse the AEAD key directly for `DisplayField` shuffle
    // PRNG seeding — see `crate::shuffle` for the threat model.
    let shuffle_key = Arc::new(shuffle::ShuffleKey::from_tee_seal_key(&tee_seal_key));
    let hatch = HatchClient::new(&address_out)
        .await
        .expect("failed to connect to hatch");
    let session_store = Arc::new(SessionStore::new(hatch, tee_seal_key));

    // Two listeners, two routers, one process. Topology rationale: TLS
    // terminates inside this TEE, so a host-side proxy can only route by
    // SNI on raw TCP. Each surface (clients vs applicants) gets its own
    // certificate, port, optional mTLS posture, and rate-limit policy.
    // Each surface owns its route table — see `client::router` and
    // `applicant::router` for the endpoint inventory.
    // Dev attestor: real SEV-SNP report FORMAT, signed by a software test
    // key (test trust root). Swaps to the prod `sev-snp` backend
    // (`/dev/sev-guest` + AMD chain) with no caller change. Measurement /
    // key-seed provisioning (so a verifier can pin them) lands with the
    // prod backend; `new_random` is fine while nothing verifies yet.
    let attestor: Arc<dyn Attestor> = Arc::new(SnpDevAttestor::new_random());
    let client_state = Arc::new(
        ClientState::init(&address_out, session_store.clone(), attestor).await,
    );
    let applicant_state = Arc::new(
        AppState::init(&address_out, session_store, shuffle_key, &tee_seal_key).await,
    );

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
fn load_tee_seal_key() -> [u8; 32] {
    let hex_str = std::env::var("ENCLAVID_TEE_KEY")
        .expect("ENCLAVID_TEE_KEY not set (32-byte hex)");
    let bytes = hex::decode(hex_str).expect("ENCLAVID_TEE_KEY: invalid hex");
    bytes
        .try_into()
        .expect("ENCLAVID_TEE_KEY: must be 32 bytes")
}
