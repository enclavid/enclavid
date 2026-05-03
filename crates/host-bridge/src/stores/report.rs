use enclavid_untrusted::Untrusted;
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
}

impl ReportStore {
    pub fn new(channel: GrpcChannel) -> Self {
        Self {
            client: ReportStoreClient::new(channel),
        }
    }

    pub async fn append(
        &self,
        policy_digest: &str,
        chunk: Vec<u8>,
        _platform_public_key: &[u8],
    ) -> Result<Untrusted<u64>, BridgeError> {
        // TODO: encrypt chunk with platform_public_key (hybrid).
        let encrypted = chunk;
        let response = self
            .client
            .clone()
            .append(AppendRequest {
                policy_digest: policy_digest.to_string(),
                data: encrypted,
            })
            .await?;
        Ok(Untrusted::new(response.into_inner().length))
    }
}
