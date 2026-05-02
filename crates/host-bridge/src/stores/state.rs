use enclavid_untrusted::Untrusted;
use prost::Message;

use crate::error::BridgeError;
use crate::grpc::{GrpcBlobStore, GrpcChannel};
use crate::proto::state::SessionState;

/// Read/write store for internal session state (replay log).
/// State is double-encrypted: applicant key (inner) + TEE key (outer).
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

    /// Returns `Untrusted<Option<SessionState>>` — the existence claim
    /// is host-controlled (a lying host could hide an existing blob).
    /// The `SessionState` content, once AEAD decryption is in place,
    /// is integrity-verified by the cipher tag, so caller's `.trust()`
    /// closure typically only needs to make a policy call on the
    /// existence side (accept None, or treat absence as an error).
    pub async fn get(
        &self,
        session_id: &str,
        _applicant_key: &[u8],
        _tee_key: &[u8],
    ) -> Result<Untrusted<Option<SessionState>>, BridgeError> {
        let opt_bytes = self.inner.get(session_id).await?.trust_unchecked();
        let opt = opt_bytes
            .map(|bytes| {
                // TODO: decrypt with tee_key, then applicant_key — the
                // AEAD tag check authenticates host-supplied bytes.
                SessionState::decode(bytes.as_slice())
            })
            .transpose()?;
        Ok(Untrusted::new(opt))
    }

    pub async fn put(
        &self,
        session_id: &str,
        state: &SessionState,
        _applicant_key: &[u8],
        _tee_key: &[u8],
    ) -> Result<Untrusted<()>, BridgeError> {
        let bytes = state.encode_to_vec();
        // TODO: encrypt with applicant_key, then tee_key
        let encrypted = bytes;
        self.inner.put(session_id, encrypted).await
    }

    pub async fn exists(
        &self,
        session_id: &str,
    ) -> Result<Untrusted<bool>, BridgeError> {
        self.inner.exists(session_id).await
    }

    pub async fn delete(
        &self,
        session_id: &str,
    ) -> Result<Untrusted<u64>, BridgeError> {
        self.inner.delete(session_id).await
    }
}
