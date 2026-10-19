//! Client for the hatch's KBS relay.
//!
//! api reaches an artifact-key broker (KBS) through the hatch. This is the thin
//! transport primitive: it forwards ONE handshake/key-release leg and returns
//! the broker's answer. The attestation state machine (RCAR: auth → challenge →
//! attestation → resource), the ephemeral `TeeKeyPair` and the JWE unwrap live
//! one layer up in the api keyprovider — this client just couriers bytes.
//!
//! Trust model: the broker's answer can be dropped or stalled on the way, but
//! the released secret cannot be forged — it is JWE-wrapped to api's ephemeral
//! key, so only the enclave can unwrap it. The caller MUST verify via
//! `.trust(...)` at the keyprovider layer (the unwrap closes AuthN; the RCAR
//! challenge nonce closes Replay).

use std::sync::Arc;

use hatch_rpc::{HatchService, KbsRequest, KbsResponse};

use crate::boundary;
use crate::error::BridgeError;
use crate::link::{Link, hatch, within};
use enclavid_boundary::{AuthN, AuthZ, Exposed, Replay, Untrusted};

/// How long the hatch has to answer ONE relayed leg, unless the host says
/// otherwise (api's `kbs-deadline-secs` setting).
///
/// Per leg, not per handshake: a full RCAR exchange is three of these, so the
/// worst case a caller can wait is three times this. Bounded because a relay is
/// reached from api's compile path, which can run inside an applicant round — an
/// unbounded wait here parks a round that is holding that round's captures.
pub const DEFAULT_RELAY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);

/// Client for the hatch's KBS relay.
#[derive(Clone)]
pub struct KbsClient {
    link: Arc<dyn Link>,
    deadline: std::time::Duration,
}

impl KbsClient {
    /// A client whose every relayed leg the hatch has `deadline` to answer.
    pub fn new(link: Arc<dyn Link>, deadline: std::time::Duration) -> Self {
        Self { link, deadline }
    }

    /// Forward one KBS leg through the hatch. The request is vouched by the
    /// keyprovider producer (it holds the untrusted `endpoint` and the
    /// JWE-protected payload); we just release it. The response is
    /// `Untrusted` — the keyprovider verifies it by unwrapping the JWE with the
    /// ephemeral key.
    pub async fn relay(
        &self,
        req: Exposed<KbsRequest>,
    ) -> Result<Untrusted<KbsResponse, (AuthN, AuthZ, Replay)>, BridgeError> {
        let hatch = hatch(self.link.as_ref())?;
        let response = within(self.deadline, "kbs relay", async {
            hatch
                .kbs(req.into_inner())
                .await
                .map_err(|e| BridgeError::Transport(e.to_string()))
        })
        .await?;
        Ok(boundary::inbound::from_untrusted(response))
    }
}
