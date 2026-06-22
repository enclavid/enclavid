//! Client wrapper for the broker `/kbs/relay` endpoint.
//!
//! The TEE has no outbound network, so it reaches an artifact-key broker
//! (KBS) through the broker as a semantic HTTP proxy. This is the thin
//! transport primitive: it forwards ONE handshake/key-release leg and
//! returns the KBS response. The KBS attestation state machine (RCAR:
//! auth → challenge → attestation → resource), the ephemeral `TeeKeyPair`,
//! and the JWE response unwrap live one layer up in the api keyprovider —
//! this client just couriers bytes.
//!
//! Trust model: the broker can drop or stall a leg, but cannot forge the
//! released secret — it is JWE-wrapped to the TEE's ephemeral key, so only
//! the enclave can unwrap it. Caller MUST verify via `.trust(...)` at the
//! keyprovider layer (the unwrap closes AuthN; the RCAR challenge nonce
//! closes Replay).

use broker_protocol::{KbsRelayRequest, KbsRelayResponse};
use hyper::StatusCode;

use crate::boundary;
use crate::boundary::{AuthN, AuthZ, Exposed, Replay, Untrusted};
use crate::error::BridgeError;
use crate::transport::BrokerClient;

/// Client for the broker `/kbs/relay` endpoint over the shared broker
/// connection.
#[derive(Clone)]
pub struct KbsClient {
    broker: BrokerClient,
}

impl KbsClient {
    pub fn new(broker: BrokerClient) -> Self {
        Self { broker }
    }

    /// Forward one KBS leg through the broker. The request is vouched by
    /// the keyprovider producer (it holds the untrusted `endpoint` and the
    /// HPKE/JWE-protected payload); we just release it. The response is
    /// `Untrusted` — the keyprovider verifies it by unwrapping the JWE
    /// with the ephemeral key.
    pub async fn relay(
        &self,
        req: Exposed<KbsRelayRequest>,
    ) -> Result<Untrusted<KbsRelayResponse, (AuthN, AuthZ, Replay)>, BridgeError> {
        let bytes = broker_protocol::encode(&req.into_inner())?;
        let resp = self.broker.post("/kbs/relay", bytes).await?;

        match resp.status {
            StatusCode::OK => {
                let r: KbsRelayResponse = broker_protocol::decode(&resp.body)?;
                Ok(boundary::inbound::from_untrusted(r))
            }
            s => Err(BridgeError::Transport(format!("kbs relay: status {s}"))),
        }
    }
}
