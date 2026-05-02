use enclavid_untrusted::Untrusted;
use prost::Message;

use crate::error::BridgeError;
use crate::grpc::{GrpcBlobStore, GrpcChannel};
use crate::proto::state::SessionMetadata;

/// Read/write store for session metadata. The TEE creates entries on
/// session create and updates them as the session progresses through
/// the lifecycle.
#[derive(Clone)]
pub struct MetadataStore {
    inner: GrpcBlobStore,
}

impl MetadataStore {
    pub fn new(channel: GrpcChannel) -> Self {
        Self {
            inner: GrpcBlobStore::new(channel, "session"),
        }
    }

    /// Read metadata from the host's BlobStore. Both the existence
    /// claim AND the decoded fields are host-controlled, so the
    /// `Option<SessionMetadata>` lives inside `Untrusted`. Caller passes
    /// a single predicate to `.trust(...)` that decides whether absence
    /// is acceptable AND verifies content (workspace boundary, status,
    /// etc.) when present. See architecture.md → Network Isolation.
    pub async fn get(
        &self,
        session_id: &str,
    ) -> Result<Untrusted<Option<SessionMetadata>>, BridgeError> {
        // Decode is wire-format parsing, not content verification — the
        // result stays untrusted. We unwrap-then-rewrap because prost
        // decode is fallible (no `Untrusted::try_map` helper today).
        let opt_bytes = self.inner.get(session_id).await?.trust_unchecked();
        let opt = opt_bytes
            .map(|bytes| SessionMetadata::decode(bytes.as_slice()))
            .transpose()?;
        Ok(Untrusted::new(opt))
    }

    pub async fn put(
        &self,
        session_id: &str,
        metadata: &SessionMetadata,
    ) -> Result<Untrusted<()>, BridgeError> {
        self.inner.put(session_id, metadata.encode_to_vec()).await
    }
}
