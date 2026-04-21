//! Concrete stores for each kind of session data.
//! Each encapsulates its own transport + encryption requirements.

use prost::Message;

use crate::error::StoreError;
use crate::grpc::{GrpcBlobStore, GrpcChannel, GrpcListStore};
use crate::proto::state::{SessionMetadata, SessionState};

/// Read-only store for session metadata created by the external service.
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

    pub async fn get(&self, session_id: &str) -> Result<Option<SessionMetadata>, StoreError> {
        match self.inner.get(session_id).await? {
            None => Ok(None),
            Some(bytes) => Ok(Some(SessionMetadata::decode(bytes.as_slice())?)),
        }
    }
}

/// Read/write store for internal session state (replay log).
/// State is double-encrypted: client key (inner) + TEE key (outer).
/// Both keys must be provided on every operation.
#[derive(Clone)]
pub struct StateStore {
    inner: GrpcBlobStore,
}

impl StateStore {
    pub fn new(channel: GrpcChannel) -> Self {
        Self {
            inner: GrpcBlobStore::new(channel, "state"),
        }
    }

    pub async fn get(
        &self,
        session_id: &str,
        _applicant_key: &[u8],
        _tee_key: &[u8],
    ) -> Result<Option<SessionState>, StoreError> {
        match self.inner.get(session_id).await? {
            None => Ok(None),
            Some(_bytes) => {
                // TODO: decrypt with tee_key, then applicant_key
                let decrypted = _bytes;
                Ok(Some(SessionState::decode(decrypted.as_slice())?))
            }
        }
    }

    pub async fn put(
        &self,
        session_id: &str,
        state: &SessionState,
        _applicant_key: &[u8],
        _tee_key: &[u8],
    ) -> Result<(), StoreError> {
        let bytes = state.encode_to_vec();
        // TODO: encrypt with applicant_key, then tee_key
        let encrypted = bytes;
        self.inner.put(session_id, encrypted).await
    }

    pub async fn exists(&self, session_id: &str) -> Result<bool, StoreError> {
        self.inner.exists(session_id).await
    }

    pub async fn delete(&self, session_id: &str) -> Result<(), StoreError> {
        self.inner.delete(session_id).await
    }
}

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
    ) -> Result<(), StoreError> {
        // TODO: encrypt chunk with client_public_key (hybrid: AES data + RSA/ECC key)
        let encrypted = chunk;
        self.inner.append(session_id, encrypted).await
    }
}

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
    ) -> Result<(), StoreError> {
        // TODO: encrypt chunk with platform_public_key (hybrid)
        let encrypted = chunk;
        self.inner.append(policy_id, encrypted).await
    }
}
