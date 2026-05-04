//! Client wrapper for the host-side `Registry` gRPC service.
//!
//! Pulls OCI artifacts (encrypted policy bundles) from the configured
//! Enclavid registry. The TEE has no network stack — host fetches by
//! pinned digest reference and forwards bytes over vsock.
//!
//! Trust model: host can swap the response to ANY (manifest, layers)
//! tuple whose digests match the requested reference, but cannot inject
//! arbitrary content. Caller MUST recompute manifest_digest and each
//! layer digest before trusting bytes. See proto/registry.proto and
//! architecture.md → Network Isolation for the full analysis.

use enclavid_untrusted::{AuthN, Replay, Untrusted, reason};
use tonic::transport::Channel;

use crate::error::BridgeError;
use crate::proto::registry::registry_client::RegistryClient as ProtoRegistryClient;
use crate::proto::registry::{PullRequest, PullResponse};
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

    /// Pull an encrypted policy artifact by its logical identity.
    ///
    /// The TEE supplies the abstract triple (workspace, name, digest);
    /// the host translates it into a registry-specific reference. The
    /// response is wrapped in `Untrusted` — caller MUST verify via
    /// `.trust(...)` that the manifest hashes to the requested digest
    /// and that each declared layer's bytes hash to the descriptor's
    /// digest before any decryption or wasm loading happens.
    pub async fn pull(
        &self,
        workspace_id: &str,
        policy_name: &str,
        policy_digest: &str,
    ) -> Result<Untrusted<PullResponse, (AuthN, Replay)>, BridgeError> {
        let response = self
            .client
            .clone()
            .pull(PullRequest {
                workspace_id: workspace_id.to_string(),
                policy_name: policy_name.to_string(),
                policy_digest: policy_digest.to_string(),
            })
            .await?;
        Ok(Untrusted::new(response.into_inner(), reason!(r#"
Bytes the host fetched from a registry; TEE hasn't checked
anything yet. Caller must verify manifest + per-layer digests
to clear AuthN. Replay open (host could serve a stale cache
entry). AuthZ enforced by registry server, not TEE.
        "#)))
    }
}
