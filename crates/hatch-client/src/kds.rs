//! Client wrapper for the hatch `/kds/vcek` endpoint.
//!
//! The TEE has no outbound network, so the certificate endorsing its own chip
//! comes through the hatch. This is the thin transport primitive: it names the
//! certificate and returns whatever came back, untrusted.
//!
//! Trust model: the hatch can withhold or corrupt the answer, but cannot make a
//! wrong certificate useful. Authenticity is closed at the use site by the
//! attestor's constructor, which verifies the AMD chain against a compiled-in
//! root and then requires the certificate to verify a report this chip has just
//! produced. A substituted one fails that, and the guest does not start.

use hatch_protocol::{VcekRequest, VcekResponse};
use hyper::StatusCode;

use crate::boundary;
use crate::boundary::{AuthN, AuthZ, Exposed, Replay, Untrusted};
use crate::error::BridgeError;
use crate::transport::HatchClient;

/// How long the hatch has to answer a certificate request.
///
/// This one runs at BOOT, under `endorsement`'s own ladder of retries — and the
/// ladder is the reason the deadline has to exist rather than a reason it could
/// be skipped: without it the first attempt parks for ever and the remaining
/// rungs are never reached, which is the same hole `fleet::dial` closed with
/// its `ATTEMPT_TIMEOUT`. Generous because the fetch behind it may leave the
/// machine and AMD's service rate-limits; the cache in front of it is the
/// hatch's, not ours.
const VCEK_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// Client for the hatch `/kds/vcek` endpoint over the shared hatch connection.
#[derive(Clone)]
pub struct KdsClient {
    hatch: HatchClient,
}

impl KdsClient {
    pub fn new(hatch: HatchClient) -> Self {
        Self { hatch }
    }

    /// Ask for the certificate that endorses this chip at this platform TCB.
    /// The response is `Untrusted` — the caller closes it by verifying the AMD
    /// chain, not by anything this layer does.
    pub async fn vcek(
        &self,
        req: Exposed<VcekRequest>,
    ) -> Result<Untrusted<VcekResponse, (AuthN, AuthZ, Replay)>, BridgeError> {
        let bytes = hatch_protocol::encode(&req.into_inner())?;
        let resp = self.hatch.post("/kds/vcek", bytes, VCEK_DEADLINE).await?;

        match resp.status {
            StatusCode::OK => {
                let r: VcekResponse = hatch_protocol::decode(&resp.body)?;
                Ok(boundary::inbound::from_untrusted(r))
            }
            // A real answer from AMD, not a transport fault: no certificate is
            // issued for this chip at this TCB.
            StatusCode::NOT_FOUND => Err(BridgeError::Transport(
                "vcek: AMD does not endorse this chip at this platform TCB".to_string(),
            )),
            s => Err(BridgeError::Transport(format!("vcek: status {s}"))),
        }
    }
}
