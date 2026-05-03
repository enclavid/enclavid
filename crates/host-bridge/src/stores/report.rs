use std::sync::Arc;

use enclavid_untrusted::{Exposed, Untrusted};
use tonic::transport::Channel;

use crate::error::BridgeError;
use crate::proto::report_store::report_store_client::ReportStoreClient;
use crate::proto::report_store::AppendRequest;
use crate::transport::GrpcChannel;

/// Append-only store for anonymous applicant reports against policies.
/// Entries keyed by `policy_digest` so the platform aggregates reports
/// per policy. No session_id is included in the payload — reports are
/// unlinkable to specific applicants by construction at the storage
/// layer.
#[derive(Clone)]
pub struct ReportStore {
    client: ReportStoreClient<Channel>,
    /// Recipient pubkey for sealing reports before exposure to the
    /// host (age recipient: hybrid X25519 + AES). The host stores
    /// opaque ciphertext; only the platform can open these.
    /// Phase A: caller injects (placeholder).
    /// Phase B: derived from attestation / KMS-bound material.
    /// `Arc` so cloning the store stays cheap.
    platform_pubkey: Arc<Vec<u8>>,
}

impl ReportStore {
    pub fn new(channel: GrpcChannel, platform_pubkey: Vec<u8>) -> Self {
        Self {
            client: ReportStoreClient::new(channel),
            platform_pubkey: Arc::new(platform_pubkey),
        }
    }

    /// Caller passes plaintext bytes; the bridge seals them under
    /// `platform_pubkey` and releases the resulting ciphertext to the
    /// host. Symmetric with how `SessionStore` handles state and
    /// metadata — encryption + `Exposed` boundary live inside the
    /// bridge, API consumers stay key-free.
    pub async fn append(
        &self,
        policy_digest: &str,
        payload: Vec<u8>,
    ) -> Result<Untrusted<u64>, BridgeError> {
        // TODO encrypt: hybrid age-encrypt `payload` to
        // `self.platform_pubkey` BEFORE wrapping. This is the seal step
        // that produces the `Exposed<Vec<u8>>` — same shape as
        // WriteField::build_op for SessionStore ops.
        let _ = &self.platform_pubkey;
        let sealed: Exposed<Vec<u8>> = Exposed::expose(payload);

        let response = self
            .client
            .clone()
            .append(AppendRequest {
                policy_digest: policy_digest.to_string(),
                data: sealed.release(),
            })
            .await?;
        Ok(Untrusted::new(response.into_inner().length))
    }
}
