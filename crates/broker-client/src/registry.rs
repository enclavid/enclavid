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
use hyper::StatusCode;

use crate::boundary;
use crate::boundary::{AuthN, AuthZ, Exposed, Replay, Untrusted};
use crate::error::BridgeError;
use crate::transport::BrokerClient;

/// Client for the broker `/oci/pull` endpoint over the shared broker
/// connection.
#[derive(Clone)]
pub struct RegistryClient {
    broker: BrokerClient,
}

impl RegistryClient {
    pub fn new(broker: BrokerClient) -> Self {
        Self { broker }
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
        req: Exposed<PullRequest>,
    ) -> Result<Untrusted<PullResponse, (AuthN, AuthZ, Replay)>, BridgeError> {
        // The request arrives vouched by the api producer (which holds
        // the consumer-supplied ref + registry bearer). Courier-
        // forwarding the consumer's bearer to the registry is the
        // producer's call, not ours to self-approve; we just release it.
        let bytes = broker_protocol::encode(&req.into_inner())?;
        let resp = self.broker.post("/oci/pull", bytes).await?;

        match resp.status {
            StatusCode::OK => {
                let r: PullResponse = broker_protocol::decode(&resp.body)?;
                Ok(boundary::inbound::from_untrusted(r))
            }
            StatusCode::NOT_FOUND => Err(BridgeError::NotFound),
            s => Err(BridgeError::Transport(format!("pull: status {s}"))),
        }
    }
}
