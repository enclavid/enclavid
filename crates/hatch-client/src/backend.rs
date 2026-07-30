//! Transport seams under [`SessionStore`](crate::SessionStore) /
//! [`CacheStore`](crate::CacheStore). Each store owns ALL crypto (`build_op` /
//! per-field `decode` / `aead` seal-open, and — for the cache — the
//! identity-hiding `blob_name` derivation) plus the `Exposed`/`Untrusted`
//! boundary gate; the backend is a **dumb byte mover**.
//!
//! The concrete implementation is `SessionCvmBackend` / `CacheCvmBackend` (in
//! `api`) — remoc clients to the trusted storage-CVM over RA-TLS. It lives in
//! `api` (not here) so hatch-client stays remoc-free.
//!
//! The seam is boundary-UNAWARE on purpose: it never sees `Exposed`/`Untrusted`,
//! so nothing here can bypass the egress gate — the stores cross the boundary
//! before calling in.

use hatch_protocol::{ReadRequest, Slot, WriteRequest};

use crate::error::BridgeError;

/// Transport for the per-session KV. Moves already-serialized `hatch-protocol`
/// DTOs; the store above closes all trust concerns.
#[async_trait::async_trait]
pub trait SessionBackend: Send + Sync {
    /// Read raw slots + version. `version == 0` ⇒ session absent.
    async fn read_raw(&self, id: &str, req: ReadRequest) -> Result<(Vec<Slot>, u64), BridgeError>;

    /// Atomic CAS write. `Ok(new_version)` | `Err(BridgeError::VersionMismatch)`.
    /// `deadline_unix_secs` threads the TEE-side absolute TTL INSIDE the channel
    /// — the storage-CVM sweeper enforces it (set once at create; `None` on
    /// updates so the deadline is never refreshed).
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
