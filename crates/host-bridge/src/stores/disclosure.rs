use enclavid_untrusted::Untrusted;

use crate::error::BridgeError;
use crate::grpc::{GrpcChannel, GrpcListStore};

/// Append-only store for consent-approved data for the client.
/// Each chunk encrypted with the client's public key.
/// TEE cannot read back — only append.
#[derive(Clone)]
pub struct DisclosureStore {
    inner: GrpcListStore,
}

impl DisclosureStore {
    pub fn new(channel: GrpcChannel) -> Self {
        Self {
            inner: GrpcListStore::new(channel, "disclosure"),
        }
    }

    pub async fn append(
        &self,
        session_id: &str,
        chunk: Vec<u8>,
        _client_public_key: &[u8],
    ) -> Result<Untrusted<u64>, BridgeError> {
        // TODO: encrypt chunk with client_public_key (hybrid: AES data + RSA/ECC key)
        let encrypted = chunk;
        self.inner.append(session_id, encrypted).await
    }
}
