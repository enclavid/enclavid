//! Client wrapper for the broker `/oci/pull` endpoint.
//!
//! Pulls OCI artifacts (policy bundles, plugin components) from
//! whichever registry the supplied OCI reference points at — our Angos
//! by default, but any OCI-compliant registry works. The TEE has no
//! network stack: the broker fetches by pinned-digest reference and
//! forwards bytes over the channel.
//!
//! Trust model: the broker can swap the response to any (manifest,
//! layers) tuple whose digests match the requested reference, but
//! cannot inject arbitrary content. Caller MUST recompute
//! manifest_digest and each layer digest before trusting bytes. See
//! architecture.md → Network Isolation for the full analysis.

use broker_protocol::PullRequest;
use broker_protocol::PullResponse;

use crate::boundary;
use crate::boundary::{AuthN, AuthZ, Replay, Untrusted};
use crate::error::BridgeError;
use crate::reason;
use crate::transport::BrokerChannel;

/// Client for the broker `/oci/pull` endpoint over the shared channel.
#[derive(Clone)]
pub struct RegistryClient {
    channel: BrokerChannel,
}

impl RegistryClient {
    pub fn new(channel: BrokerChannel) -> Self {
        Self { channel }
    }

    /// Pull an OCI artifact (policy bundle or plugin component) by its
    /// full pinned reference.
    ///
    /// `policy_ref` is the pinned ref `<registry>/<repo>@sha256:<hex>`;
    /// `registry_auth` is the opaque bearer payload the broker attaches
    /// as `Authorization` (empty for anonymous pulls). The response is
    /// wrapped in `Untrusted` — caller MUST verify via `.trust(...)`
    /// that the manifest hashes to the requested digest and that each
    /// declared layer's bytes hash to the descriptor's digest before
    /// any wasm loading happens. A 404 from the broker surfaces as the
    /// typed `BridgeError::NotFound`.
    pub async fn pull(
        &self,
        policy_ref: &str,
        registry_auth: &[u8],
    ) -> Result<Untrusted<PullResponse, (AuthN, AuthZ, Replay)>, BridgeError> {
        let req = PullRequest {
            policy_ref: policy_ref.to_string(),
            registry_auth: registry_auth.to_vec(),
        };
        let resp = self
            .channel
            .post("/oci/pull", broker_protocol::encode(&req)?)
            .await?;

        match resp.status {
            200 => {
                let r: PullResponse = broker_protocol::decode(&resp.body)?;
                Ok(boundary::inbound::from_host(r, reason!(r#"
OCI artifact pull response from broker /oci/pull. No work-backed
close at this layer — caller peels with rationale (typical:
AuthN closed by manifest+layer digest verification; AuthZ delegated
to the registry server via the broker-supplied bearer; Replay N/A
since the request is content-addressed by digest).
                "#)))
            }
            404 => Err(BridgeError::NotFound),
            s => Err(BridgeError::Transport(format!("pull: status {s}"))),
        }
    }
}
