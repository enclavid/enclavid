//! The L2 compiled-artifact (cwasm) cache, backed by `object_store`. A blind
//! opaque-blob KV keyed by the identity-hiding `blob_name` the api derives
//! (`hex(HKDF(filename_key, cache_id))`) — the CVM sees only pseudo-random hex,
//! never the composition. Sealed bytes ride the wire; a miss is `Ok(None)` (not
//! an error) so the orchestrator recompiles. Kept on `object_store` (not redb) to
//! keep multi-MiB cwasm blobs off the session B-tree behind a backend-agnostic
//! blob interface (local filesystem today). The blobs are sealed under the
//! writer's chip-bound `tee_seal_key`, so the cache is per-instance — a cold
//! compile on another instance is a clean miss, not a shared-key dependency.

use std::sync::Arc;

use object_store::ObjectStore;
use object_store::path::Path as ObjPath;

use storage_rpc::CacheError;

fn internal(e: impl std::fmt::Display) -> CacheError {
    CacheError(e.to_string())
}

/// Max accepted key length — a hex SHA-256 label is 64 chars; allow headroom
/// without permitting an unbounded name.
const MAX_KEY_LEN: usize = 128;

/// Validate `key` is non-empty bounded hex and map it to an object path. The
/// alphabet excludes `/`, `.`, `\`, so the location cannot traverse out of the
/// store prefix. Mirrors the hatch's guard: the api always emits lowercase hex,
/// but the CVM re-validates (defence-in-depth — never trust a wire-supplied path
/// segment even from an attested peer).
fn object_path(key: &str) -> Result<ObjPath, CacheError> {
    if key.is_empty() || key.len() > MAX_KEY_LEN {
        return Err(CacheError("cache key length".to_string()));
    }
    if !key.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CacheError(
            "cache key must be hex (path-traversal guard)".to_string(),
        ));
    }
    Ok(ObjPath::from(key))
}

/// The cache blob store — cheap to clone (the `ObjectStore` handle is Arc-backed).
#[derive(Clone)]
pub struct CacheBlobs {
    store: Arc<dyn ObjectStore>,
}

impl CacheBlobs {
    pub fn new(store: Arc<dyn ObjectStore>) -> Self {
        Self { store }
    }

    /// Store the (sealed, opaque) `bytes` under `key`, overwriting any existing
    /// blob (the api key is content+format-addressed, so a re-write is identical
    /// bytes or a fresh compile replacing a stale one).
    pub async fn store(&self, key: &str, bytes: Vec<u8>) -> Result<(), CacheError> {
        let path = object_path(key)?;
        self.store
            .put(&path, bytes.into())
            .await
            .map_err(internal)?;
        Ok(())
    }

    /// Load the blob for `key`. `Ok(None)` = miss (absent); `Err` only on a
    /// genuine store failure.
    pub async fn load(&self, key: &str) -> Result<Option<Vec<u8>>, CacheError> {
        let path = object_path(key)?;
        match self.store.get(&path).await {
            Ok(res) => {
                let bytes = res.bytes().await.map_err(internal)?;
                Ok(Some(bytes.to_vec()))
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(internal(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;

    #[tokio::test]
    async fn store_load_roundtrip_and_miss() {
        let cache = CacheBlobs::new(Arc::new(InMemory::new()));
        let key = "deadbeef".repeat(8); // 64 hex chars
        assert_eq!(cache.load(&key).await.unwrap(), None);
        cache.store(&key, b"cwasm-bytes".to_vec()).await.unwrap();
        assert_eq!(
            cache.load(&key).await.unwrap(),
            Some(b"cwasm-bytes".to_vec())
        );
    }

    #[tokio::test]
    async fn rejects_non_hex_key() {
        let cache = CacheBlobs::new(Arc::new(InMemory::new()));
        assert!(cache.load("../etc/passwd").await.is_err());
        assert!(cache.store("a/b", b"x".to_vec()).await.is_err());
    }
}
