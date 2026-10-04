//! The L2 compiled-artifact (cwasm) cache, backed by `object_store`. A blind
//! opaque-blob KV keyed by the identity-hiding `blob_name` the api derives
//! (`hex(HKDF(filename_key, cache_id))`), re-derived here against the calling
//! peer's launch digest (the crate-private `scope` module) — the CVM sees only
//! pseudo-random hex, never the composition. Sealed bytes ride the wire; a miss is `Ok(None)` (not
//! an error) so the orchestrator recompiles. Kept on `object_store` (not redb) to
//! keep multi-MiB cwasm blobs off the session B-tree behind a backend-agnostic
//! blob interface (local filesystem today). The blobs are sealed under the
//! writer's chip-bound `tee_seal_key`, so the cache is per-instance — a cold
//! compile on another instance is a clean miss, not a shared-key dependency.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

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
/// store prefix. Nothing on the served path can fail this any more — a key
/// reaches this store only as a [`crate::scope::Name`], which is hex by
/// construction — but the store is a plain type that will take any string, and
/// this is the check that makes that safe.
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
    /// When each blob was last loaded by this process — what keeps a blob in
    /// use when [`evict_to`](Self::evict_to) has to drop some. A restart
    /// forgets it and each blob counts from when it was written, which can
    /// only cost a bundle still in use one recompile.
    used: Arc<Mutex<HashMap<String, SystemTime>>>,
}

impl CacheBlobs {
    pub fn new(store: Arc<dyn ObjectStore>) -> Self {
        Self {
            store,
            used: Arc::default(),
        }
    }

    fn used(&self) -> std::sync::MutexGuard<'_, HashMap<String, SystemTime>> {
        self.used.lock().unwrap_or_else(|e| e.into_inner())
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
                self.used().insert(path.to_string(), SystemTime::now());
                Ok(Some(bytes.to_vec()))
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(internal(e)),
        }
    }

    /// Bring the cache under `budget` bytes, dropping first the blobs used
    /// least recently — loaded, or else written. Returns how many it dropped.
    ///
    /// The cache shares its volume with the session store and nothing else
    /// ever removes a blob, so without this it grows until session writes
    /// fail. A blob dropped while still wanted costs a miss and a recompile;
    /// the clock it is judged by is the host's, so skewing it can only make
    /// that happen sooner.
    pub async fn evict_to(&self, budget: u64) -> Result<usize, CacheError> {
        let listed = self
            .store
            .list_with_delimiter(None)
            .await
            .map_err(internal)?;
        let mut total: u64 = listed.objects.iter().map(|m| m.size).sum();
        if total <= budget {
            return Ok(0);
        }
        let mut blobs: Vec<_> = {
            let used = self.used();
            listed
                .objects
                .into_iter()
                .map(|m| {
                    let written = SystemTime::from(m.last_modified);
                    let last = used
                        .get(m.location.as_ref())
                        .map_or(written, |&loaded| loaded.max(written));
                    (last, m)
                })
                .collect()
        };
        blobs.sort_by_key(|(last, _)| *last);
        let mut dropped = 0;
        for (_, meta) in blobs {
            if total <= budget {
                break;
            }
            match self.store.delete(&meta.location).await {
                Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
                Err(e) => return Err(internal(e)),
            }
            self.used().remove(meta.location.as_ref());
            total = total.saturating_sub(meta.size);
            dropped += 1;
        }
        Ok(dropped)
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

    /// Over budget, the blob nobody has asked for since it was written goes
    /// first; one just loaded stays, however long ago it was written.
    #[tokio::test]
    async fn eviction_drops_the_least_recently_used_first() {
        let cache = CacheBlobs::new(Arc::new(InMemory::new()));
        let keys: Vec<String> = ["aa", "bb", "cc"].iter().map(|k| k.repeat(32)).collect();
        for key in &keys {
            cache.store(key, vec![0u8; 100]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(cache.load(&keys[0]).await.unwrap().is_some());

        assert_eq!(cache.evict_to(200).await.unwrap(), 1);
        assert!(cache.load(&keys[0]).await.unwrap().is_some());
        assert_eq!(cache.load(&keys[1]).await.unwrap(), None);
        assert!(cache.load(&keys[2]).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn a_cache_within_budget_is_left_alone() {
        let cache = CacheBlobs::new(Arc::new(InMemory::new()));
        let key = "ab".repeat(32);
        cache.store(&key, vec![0u8; 100]).await.unwrap();
        assert_eq!(cache.evict_to(100).await.unwrap(), 0);
        assert!(cache.load(&key).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn rejects_non_hex_key() {
        let cache = CacheBlobs::new(Arc::new(InMemory::new()));
        assert!(cache.load("../etc/passwd").await.is_err());
        assert!(cache.store("a/b", b"x".to_vec()).await.is_err());
    }
}
