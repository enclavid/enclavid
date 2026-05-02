use enclavid_untrusted::Untrusted;

use crate::error::BridgeError;
use crate::grpc::{GrpcChannel, GrpcListStore};

/// Append-only store for anonymous user reports against policies.
/// Entries keyed by `policy_id` so the platform can aggregate reports per policy.
/// No session_id is included in the payload — reports are unlinkable to specific users.
#[derive(Clone)]
pub struct ReportStore {
    inner: GrpcListStore,
}

impl ReportStore {
    pub fn new(channel: GrpcChannel) -> Self {
        Self {
            inner: GrpcListStore::new(channel, "report"),
        }
    }

    pub async fn append(
        &self,
        policy_id: &str,
        chunk: Vec<u8>,
        _platform_public_key: &[u8],
    ) -> Result<Untrusted<u64>, BridgeError> {
        // TODO: encrypt chunk with platform_public_key (hybrid)
        let encrypted = chunk;
        self.inner.append(policy_id, encrypted).await
    }
}
