//! Client wrapper for the hatch `/oci/pull` endpoint.
//!
//! Pulls OCI artifacts (policy bundles, plugin components) from
//! whichever registry the supplied OCI reference points at — our Angos
//! by default, but any OCI-compliant registry works. The TEE has no
//! network stack: the hatch fetches by pinned-digest reference and
//! forwards bytes over the channel.
//!
//! Trust model: the hatch can swap the response to any (manifest,
//! layers) tuple whose digests match the requested reference, but
//! cannot inject arbitrary content. Caller MUST recompute
//! manifest_digest and each layer digest before trusting bytes. See
//! architecture.md → Network Isolation for the full analysis.

use hatch_protocol::PullRequest;
use hatch_protocol::PullResponse;
use hyper::StatusCode;

use crate::boundary;
use crate::boundary::{AuthN, AuthZ, Exposed, Replay, Untrusted};
use crate::error::BridgeError;
use crate::transport::HatchClient;

/// How long the hatch has to answer a pull.
///
/// The most generous of the four, because it is the only one whose work is
/// unbounded from here: the hatch fetches megabytes from a registry this
/// process cannot see, cannot reach and does not choose. Still bounded, and the
/// reason is where it runs — `cold_compile` is on the applicant round path, so
/// a pull that never returns parks a round holding that round's captures, with
/// nothing beneath it to notice.
const PULL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

/// Client for the hatch `/oci/pull` endpoint over the shared hatch
/// connection.
#[derive(Clone)]
pub struct RegistryClient {
    hatch: HatchClient,
}

impl RegistryClient {
    pub fn new(hatch: HatchClient) -> Self {
        Self { hatch }
    }

    /// Pull an OCI artifact (policy bundle or plugin component) by its
    /// full pinned reference.
    ///
    /// `policy_ref` is the pinned ref `<registry>/<repo>@sha256:<hex>`;
    /// `registry_auth` is the opaque bearer payload the hatch attaches
    /// as `Authorization` (empty for anonymous pulls). The response is
    /// wrapped in `Untrusted` — caller MUST verify via `.trust(...)`
    /// that the manifest hashes to the requested digest and that each
    /// declared layer's bytes hash to the descriptor's digest before
    /// any wasm loading happens. A 404 from the hatch surfaces as the
    /// typed `BridgeError::NotFound`.
    pub async fn pull(
        &self,
        req: Exposed<PullRequest>,
    ) -> Result<Untrusted<PullResponse, (AuthN, AuthZ, Replay)>, BridgeError> {
        // The request arrives vouched by the api producer (which holds
        // the consumer-supplied ref + registry bearer). Courier-
        // forwarding the consumer's bearer to the registry is the
        // producer's call, not ours to self-approve; we just release it.
        let bytes = hatch_protocol::encode(&req.into_inner())?;
        let resp = self.hatch.post("/oci/pull", bytes, PULL_DEADLINE).await?;

        match resp.status {
            StatusCode::OK => {
                let r: PullResponse = hatch_protocol::decode(&resp.body)?;
                Ok(boundary::inbound::from_untrusted(r))
            }
            StatusCode::NOT_FOUND => Err(BridgeError::NotFound),
            s => Err(BridgeError::Transport(format!("pull: status {s}"))),
        }
    }
}
