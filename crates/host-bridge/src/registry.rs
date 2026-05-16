//! Client wrapper for the host-side `Registry` gRPC service.
//!
//! Pulls OCI artifacts (encrypted policy bundles) from whichever
//! registry the supplied OCI reference points at — our Angos by
//! default, but any OCI-compliant registry works. The TEE has no
//! network stack: host fetches by pinned-digest reference and
//! forwards bytes over vsock.
//!
//! Trust model: host can swap the response to ANY (manifest, layers)
//! tuple whose digests match the requested reference, but cannot inject
//! arbitrary content. Caller MUST recompute manifest_digest and each
//! layer digest before trusting bytes. See proto/registry.proto and
//! architecture.md → Network Isolation for the full analysis.

use enclavid_untrusted::{AuthN, Untrusted, reason};
use tonic::transport::Channel;

use crate::error::BridgeError;
use crate::proto::registry::registry_client::RegistryClient as ProtoRegistryClient;
use crate::proto::registry::{PullManifestResponse, PullRequest, PullResponse};
use crate::transport::GrpcChannel;

/// Client for the host-side `Registry` service exposed over the same
/// vsock channel as the rest of host-bridge.
#[derive(Clone)]
pub struct RegistryClient {
    client: ProtoRegistryClient<Channel>,
}

impl RegistryClient {
    pub fn new(channel: GrpcChannel) -> Self {
        Self {
            client: ProtoRegistryClient::new(channel),
        }
    }

    /// Pull an encrypted policy artifact by its full OCI reference.
    ///
    /// `policy_ref` is the pinned ref `<registry>/<repo>@sha256:<hex>`;
    /// `registry_auth` is the opaque bearer payload the host attaches
    /// as `Authorization` (empty for anonymous pulls). The response is
    /// wrapped in `Untrusted` — caller MUST verify via `.trust(...)`
    /// that the manifest hashes to the requested digest and that each
    /// declared layer's bytes hash to the descriptor's digest before
    /// any decryption or wasm loading happens.
    pub async fn pull(
        &self,
        policy_ref: &str,
        registry_auth: &[u8],
    ) -> Result<Untrusted<PullResponse, (AuthN,)>, BridgeError> {
        let response = self
            .client
            .clone()
            .pull(PullRequest {
                policy_ref: policy_ref.to_string(),
                registry_auth: registry_auth.to_vec(),
            })
            .await?;
        Ok(Untrusted::new(response.into_inner(), reason!(r#"
Bytes the host fetched from a registry; TEE hasn't checked
anything yet. Caller must verify manifest + per-layer digests
to clear AuthN. Replay is N/A: registry pulls are
content-addressed (request is by digest), so an "old" response
for the same digest is identical to the current one. AuthZ
enforced by registry server, not TEE.
        "#)))
    }

    /// Pull only the OCI manifest for the artifact (no layer payloads).
    /// Used by `POST /sessions` to validate the client's K_client via
    /// a small ciphertext token in the manifest annotation, without
    /// paying the full-artifact bandwidth — important when sessions
    /// may be created at high volume and most never reach /connect.
    pub async fn pull_manifest(
        &self,
        policy_ref: &str,
        registry_auth: &[u8],
    ) -> Result<Untrusted<PullManifestResponse, (AuthN,)>, BridgeError> {
        let response = self
            .client
            .clone()
            .pull_manifest(PullRequest {
                policy_ref: policy_ref.to_string(),
                registry_auth: registry_auth.to_vec(),
            })
            .await?;
        Ok(Untrusted::new(response.into_inner(), reason!(r#"
Manifest bytes from the host registry; same trust posture as a
full pull. Caller must verify `manifest_digest` matches the
requested digest before parsing or trusting any annotation.
Replay is N/A — content-addressed by digest.
        "#)))
    }
}
