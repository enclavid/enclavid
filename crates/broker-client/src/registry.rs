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
use crate::boundary::{AuthN, AuthZ, Covert, Replay, Untrusted};
use crate::error::BridgeError;
use crate::reason;
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
        policy_ref: &str,
        registry_auth: &[u8],
    ) -> Result<Untrusted<PullResponse, (AuthN, AuthZ, Replay)>, BridgeError> {
        let req = PullRequest {
            policy_ref: policy_ref.to_string(),
            registry_auth: registry_auth.to_vec(),
        };
        // Egress gate. `policy_ref` is public (digest-pinned);
        // `registry_auth` is the consumer-supplied bearer, courier-
        // forwarded by design to the registry it authenticates.
        let req = boundary::outbound::to_host(
            req,
            reason!("PullRequest → broker POST /oci/pull"),
        )
        .vouch_unchecked::<AuthN, _>(reason!(
            "policy_ref is public (digest-pinned); registry_auth is the CONSUMER-supplied \
             bearer, courier-forwarded by design to the registry it authenticates — \
             not a TEE-held secret"
        ))
        .vouch_unchecked::<AuthZ, _>(reason!(
            "forwarding the supplied bearer to the named registry IS the courier \
             operation; no further release gate"
        ))
        .vouch_unchecked::<Covert, _>(reason!(
            "both fields are consumer-supplied at session create, not policy-controlled \
             at evaluate time"
        ));
        let bytes = broker_protocol::encode(&req.into_inner())?;
        let resp = self.broker.post("/oci/pull", bytes).await?;

        match resp.status {
            StatusCode::OK => {
                let r: PullResponse = broker_protocol::decode(&resp.body)?;
                Ok(boundary::inbound::from_host(r, reason!(r#"
OCI artifact pull response from broker /oci/pull. No work-backed
close at this layer — caller peels with rationale (typical:
AuthN closed by manifest+layer digest verification; AuthZ delegated
to the registry server via the broker-supplied bearer; Replay N/A
since the request is content-addressed by digest).
                "#)))
            }
            StatusCode::NOT_FOUND => Err(BridgeError::NotFound),
            s => Err(BridgeError::Transport(format!("pull: status {s}"))),
        }
    }
}
