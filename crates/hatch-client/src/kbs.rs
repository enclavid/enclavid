//! Client wrapper for the hatch `/kbs/relay` endpoint.
//!
//! The TEE has no outbound network, so it reaches an artifact-key broker
//! (KBS) through the hatch as a semantic HTTP proxy. This is the thin
//! transport primitive: it forwards ONE handshake/key-release leg and
//! returns the KBS response. The KBS attestation state machine (RCAR:
//! auth → challenge → attestation → resource), the ephemeral `TeeKeyPair`,
//! and the JWE response unwrap live one layer up in the api keyprovider —
//! this client just couriers bytes.
//!
//! Trust model: the hatch can drop or stall a leg, but cannot forge the
//! released secret — it is JWE-wrapped to the TEE's ephemeral key, so only
//! the enclave can unwrap it. Caller MUST verify via `.trust(...)` at the
//! keyprovider layer (the unwrap closes AuthN; the RCAR challenge nonce
//! closes Replay).

use hatch_protocol::{KbsRelayRequest, KbsRelayResponse};
use hyper::StatusCode;

use crate::boundary;
use crate::boundary::{AuthN, AuthZ, Exposed, Replay, Untrusted};
use crate::error::BridgeError;
use crate::transport::HatchClient;

/// Client for the hatch `/kbs/relay` endpoint over the shared hatch
/// connection.
#[derive(Clone)]
pub struct KbsClient {
    hatch: HatchClient,
}

impl KbsClient {
    pub fn new(hatch: HatchClient) -> Self {
        Self { hatch }
    }

    /// Forward one KBS leg through the hatch. The request is vouched by
    /// the keyprovider producer (it holds the untrusted `endpoint` and the
    /// HPKE/JWE-protected payload); we just release it. The response is
    /// `Untrusted` — the keyprovider verifies it by unwrapping the JWE
    /// with the ephemeral key.
    pub async fn relay(
        &self,
        req: Exposed<KbsRelayRequest>,
    ) -> Result<Untrusted<KbsRelayResponse, (AuthN, AuthZ, Replay)>, BridgeError> {
        let bytes = hatch_protocol::encode(&req.into_inner())?;
        let resp = self.hatch.post("/kbs/relay", bytes).await?;

        match resp.status {
            StatusCode::OK => {
                let r: KbsRelayResponse = hatch_protocol::decode(&resp.body)?;
                Ok(boundary::inbound::from_untrusted(r))
            }
            s => Err(BridgeError::Transport(format!("kbs relay: status {s}"))),
        }
    }
}
