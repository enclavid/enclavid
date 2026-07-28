//! Transport seams under [`SessionStore`](crate::SessionStore) /
//! [`CacheStore`](crate::CacheStore). Each store owns ALL crypto (`build_op` /
//! per-field `decode` / `aead` seal-open, and — for the cache — the
//! identity-hiding `blob_name` derivation) plus the `Exposed`/`Untrusted`
//! boundary gate; the backend is a **dumb byte mover**, exactly as
//! `HatchClient::post` was. Two implementations exist:
//!
//!   * [`HatchBackend`] / [`HatchCacheBackend`] — the legacy HTTP-over-vsock path
//!     to the untrusted host's Redis / object_store cache (mechanical lift of the
//!     bodies that used to be inlined in the stores).
//!   * `StorageCvmBackend` / `CacheCvmBackend` (in `api`) — remoc clients to the
//!     trusted storage-CVM over RA-TLS.
//!
//! The seam is boundary-UNAWARE on purpose: it never sees `Exposed`/`Untrusted`,
//! so nothing here can bypass the egress gate — the stores cross the boundary
//! before calling in.

use hatch_protocol::{
    DeleteResponse, ReadRequest, ReadResponse, Slot, WriteRequest, WriteResponse,
};
use hyper::StatusCode;

use crate::error::BridgeError;
use crate::transport::HatchClient;

/// Transport for the per-session KV. Moves already-serialized `hatch-protocol`
/// DTOs; the store above closes all trust concerns.
#[async_trait::async_trait]
pub trait SessionBackend: Send + Sync {
    /// Read raw slots + version. `version == 0` ⇒ session absent.
    async fn read_raw(&self, id: &str, req: ReadRequest) -> Result<(Vec<Slot>, u64), BridgeError>;

    /// Atomic CAS write. `Ok(new_version)` | `Err(BridgeError::VersionMismatch)`.
    /// `deadline_unix_secs` threads the TEE-side TTL INSIDE the channel — the
    /// storage-CVM enforces it; the Redis-backed [`HatchBackend`] ignores it (no
    /// host-side TTL — that was the plaintext STATUS byte, now dropped).
    async fn write(
        &self,
        id: &str,
        req: WriteRequest,
        deadline_unix_secs: Option<u64>,
    ) -> Result<u64, BridgeError>;

    /// Delete the STATE field + purge media (the `/reset` path). Returns the
    /// state-field delete count.
    async fn delete(&self, id: &str) -> Result<u64, BridgeError>;

    async fn exists(&self, id: &str) -> Result<bool, BridgeError>;
}

/// Transport for the L2 cwasm cache. Moves opaque sealed blobs keyed by the
/// already-derived identity-hiding `blob_name`.
#[async_trait::async_trait]
pub trait CacheBackend: Send + Sync {
    async fn store(&self, blob_name: &str, bytes: Vec<u8>) -> Result<(), BridgeError>;
    /// `Ok(None)` = miss (absent blob).
    async fn load(&self, blob_name: &str) -> Result<Option<Vec<u8>>, BridgeError>;
}

// ---------------------------------------------------------------------------
// Hatch (HTTP-over-vsock → host Redis / object_store) — the legacy path.
// ---------------------------------------------------------------------------

/// `SessionBackend` over the hatch `/sessions/*` HTTP endpoints (host Redis).
pub struct HatchBackend {
    hatch: HatchClient,
}

impl HatchBackend {
    pub fn new(hatch: HatchClient) -> Self {
        Self { hatch }
    }
}

#[async_trait::async_trait]
impl SessionBackend for HatchBackend {
    async fn read_raw(&self, id: &str, req: ReadRequest) -> Result<(Vec<Slot>, u64), BridgeError> {
        let bytes = hatch_protocol::encode(&req)?;
        let resp = self.hatch.post(&format!("/sessions/{id}/read"), bytes).await?;
        match resp.status {
            StatusCode::OK => {
                let r: ReadResponse = hatch_protocol::decode(&resp.body)?;
                Ok((r.slots, r.version))
            }
            s => Err(BridgeError::Transport(format!("read: status {s}"))),
        }
    }

    async fn write(
        &self,
        id: &str,
        req: WriteRequest,
        _deadline_unix_secs: Option<u64>,
    ) -> Result<u64, BridgeError> {
        let bytes = hatch_protocol::encode(&req)?;
        let resp = self.hatch.post(&format!("/sessions/{id}/write"), bytes).await?;
        match resp.status {
            StatusCode::OK => {
                let r: WriteResponse = hatch_protocol::decode(&resp.body)?;
                Ok(r.new_version)
            }
            StatusCode::PRECONDITION_FAILED => Err(BridgeError::VersionMismatch),
            s => Err(BridgeError::Transport(format!("write: status {s}"))),
        }
    }

    async fn delete(&self, id: &str) -> Result<u64, BridgeError> {
        let resp = self.hatch.delete(&format!("/sessions/{id}/state")).await?;
        match resp.status {
            StatusCode::OK => {
                let r: DeleteResponse = hatch_protocol::decode(&resp.body)?;
                Ok(r.deleted)
            }
            s => Err(BridgeError::Transport(format!("delete: status {s}"))),
        }
    }

    async fn exists(&self, id: &str) -> Result<bool, BridgeError> {
        match self.hatch.head(&format!("/sessions/{id}")).await? {
            StatusCode::OK => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            s => Err(BridgeError::Transport(format!("exists: status {s}"))),
        }
    }
}

/// `CacheBackend` over the hatch `/cache/{key}` blob endpoints (host object_store).
pub struct HatchCacheBackend {
    hatch: HatchClient,
}

impl HatchCacheBackend {
    pub fn new(hatch: HatchClient) -> Self {
        Self { hatch }
    }
}

#[async_trait::async_trait]
impl CacheBackend for HatchCacheBackend {
    async fn store(&self, blob_name: &str, bytes: Vec<u8>) -> Result<(), BridgeError> {
        let resp = self.hatch.post(&format!("/cache/{blob_name}"), bytes).await?;
        match resp.status {
            StatusCode::OK => Ok(()),
            s => Err(BridgeError::Transport(format!("cache store: status {s}"))),
        }
    }

    async fn load(&self, blob_name: &str) -> Result<Option<Vec<u8>>, BridgeError> {
        let resp = self.hatch.get(&format!("/cache/{blob_name}")).await?;
        match resp.status {
            StatusCode::OK => Ok(Some(resp.body)),
            StatusCode::NOT_FOUND => Ok(None),
            s => Err(BridgeError::Transport(format!("cache load: status {s}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use crate::CacheStore;

    /// In-memory `CacheBackend` — proves the seam is a real abstraction and lets
    /// `CacheStore`'s seal/open crypto run with no transport. Keyed by the
    /// identity-hiding `blob_name` the store derives.
    #[derive(Default)]
    struct MockCacheBackend {
        blobs: Mutex<HashMap<String, Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl CacheBackend for MockCacheBackend {
        async fn store(&self, blob_name: &str, bytes: Vec<u8>) -> Result<(), BridgeError> {
            self.blobs.lock().unwrap().insert(blob_name.to_string(), bytes);
            Ok(())
        }
        async fn load(&self, blob_name: &str) -> Result<Option<Vec<u8>>, BridgeError> {
            Ok(self.blobs.lock().unwrap().get(blob_name).cloned())
        }
    }

    #[tokio::test]
    async fn cache_store_seals_and_opens_through_the_seam() {
        let backend = Arc::new(MockCacheBackend::default());
        let store = CacheStore::new(backend.clone(), &[7u8; 32]);

        // Round-trips the plaintext through seal → mock → open.
        store.store("comp.v1", b"cwasm-bundle".to_vec()).await.unwrap();
        assert_eq!(store.load("comp.v1").await.unwrap(), Some(b"cwasm-bundle".to_vec()));
        // Miss.
        assert_eq!(store.load("comp.v2").await.unwrap(), None);
        // The backend stored ciphertext, not the plaintext (seal ran TEE-side).
        let stored = backend.blobs.lock().unwrap().values().next().unwrap().clone();
        assert_ne!(stored, b"cwasm-bundle".to_vec());

        // A store built on a DIFFERENT master key cannot open the blob → miss
        // (the seam moves bytes; only the right key opens them).
        let other = CacheStore::new(backend, &[8u8; 32]);
        assert_eq!(other.load("comp.v1").await.unwrap(), None);
    }
}
