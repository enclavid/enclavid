//! Host media store the engine calls for `blob::from-blob-ref` — a
//! **pull-through cache** over the sealed broker backing store, with an in-TEE
//! **gate** on the read key.
//!
//! `blob::from-blob-ref` mints a COLD handle (no load); the engine calls
//! [`MediaStore::load`] LAZILY on the first `bytes()` read of that handle. This:
//!   1. serves a **cache hit** with no host IO;
//!   2. **gates** an unknown hash — a ref not in the session's captured set is a
//!      fabricated key, refused IN-TEE with no broker read (the engine then
//!      traps, since `from-blob-ref` has no miss branch);
//!   3. **pulls** a real-but-uncached blob from the backing store
//!      ([`SessionStore::load_media`]), decrypts, populates the cache, and
//!      returns the shared `Arc`.
//!
//! Covert-channel role (defence-in-depth; primary defence is attestation +
//! consent-gate). The read KEY (`blob_hash`) goes to the host in plaintext, and
//! each read is a host-observable event. Left unguarded, a colluding policy
//! could encode data into the key (32 B/call) or into the count/pattern of
//! calls (Morse). The gate kills the arbitrary-key variant (only real captures
//! ever reach the host — whose hashes it already logged at write). The cache
//! bounds the count variant to **≤1 host read per distinct blob** (the first
//! pull); repeats produce no IO. The irreducible residual — which of a few
//! captures is pulled, and when — is fuel-bounded and host-compromise-gated,
//! the same class as APSI query counts.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use broker_client::{Replay, SessionStore, public_session_id, reason};
use enclavid_engine::{MediaStore, RunError, RunResult};

/// Per-session pull-through cache of rehydrated media blobs, shared across
/// rounds via `AppState`. Populated on a `from-blob-ref` READ miss (never at
/// write), so it holds only blobs the policy actually re-reads — rare in the
/// current flow (media is processed at capture → verdict in state), so RAM
/// stays small. It is host-side heap, so the wasm store memory limit does NOT
/// bound it; its budget is explicit — purge on `/reset` and finalize today, an
/// LRU is a scale follow-up.
#[derive(Default)]
pub struct MediaCache {
    map: Mutex<HashMap<String, HashMap<[u8; 32], Arc<Vec<u8>>>>>,
}

impl MediaCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn get(&self, session_id: &str, hash: &[u8; 32]) -> Option<Arc<Vec<u8>>> {
        self.map.lock().unwrap().get(session_id)?.get(hash).cloned()
    }

    fn insert(&self, session_id: &str, hash: [u8; 32], bytes: Arc<Vec<u8>>) {
        self.map
            .lock()
            .unwrap()
            .entry(session_id.to_string())
            .or_default()
            .insert(hash, bytes);
    }

    /// Drop a session's cached blobs — called when its media is purged
    /// (`/reset`, finalize).
    pub fn purge(&self, session_id: &str) {
        self.map.lock().unwrap().remove(session_id);
    }
}

pub(super) struct BrokerMediaStore {
    pub session_store: Arc<SessionStore>,
    pub session_id: String,
    /// Applicant bearer token — the inner AEAD layer's key. A `/reset`
    /// discards it, after which all this session's media is unreadable.
    pub applicant_session_token: Vec<u8>,
    /// Pull-through cache (shared, cross-round). Repeat rehydrates hit here, so
    /// the host sees at most one broker read per distinct blob.
    pub cache: Arc<MediaCache>,
    /// GATE — the session's captured blob hashes (from sealed metadata, prior
    /// rounds). A rehydrate for a hash NOT in here is a fabricated ref, refused
    /// in-TEE with no broker read, so the plaintext read key can't carry data.
    pub captured: HashSet<[u8; 32]>,
}

impl MediaStore for BrokerMediaStore {
    fn load<'a>(
        &'a self,
        blob_hash: &'a [u8; 32],
    ) -> Pin<Box<dyn Future<Output = RunResult<Option<Arc<Vec<u8>>>>> + Send + 'a>> {
        // 1. Cache hit — served in-TEE, no host IO.
        if let Some(hit) = self.cache.get(&self.session_id, blob_hash) {
            return Box::pin(async move { Ok(Some(hit)) });
        }
        // 2. Gate — an unknown hash is a fabricated ref: refuse in-TEE with no
        //    broker read. The engine traps on the `None` (no miss branch).
        if !self.captured.contains(blob_hash) {
            return Box::pin(async { Ok(None) });
        }
        // 3. Pull-through — fetch the sealed blob, decrypt, cache, share.
        Box::pin(async move {
            let id = public_session_id(&self.session_id);
            let loaded = self
                .session_store
                .load_media(id, blob_hash, &self.applicant_session_token)
                .await
                .map_err(|e| RunError::msg(format!("media load failed: {e}")))?
                .trust_unchecked::<Replay, _>(reason!(
                    "media blob is content-addressed by BLAKE3; a stale or reordered read \
                     can only return identical bytes"
                ))
                .into_inner();
            Ok(loaded.map(|vec| {
                let arc = Arc::new(vec);
                self.cache.insert(&self.session_id, *blob_hash, arc.clone());
                arc
            }))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_cache_hit_isolation_and_purge() {
        let cache = MediaCache::new();
        let (h1, h2) = ([1u8; 32], [2u8; 32]);

        // Miss on an empty cache.
        assert!(cache.get("s1", &h1).is_none());

        // Insert then hit — and the hit shares the SAME allocation (no copy).
        let bytes = Arc::new(vec![10u8, 20, 30]);
        cache.insert("s1", h1, bytes.clone());
        let hit = cache.get("s1", &h1).expect("hit");
        assert!(Arc::ptr_eq(&hit, &bytes), "cache serves the shared Arc");

        // Session isolation: same hash under a different session misses.
        assert!(cache.get("s2", &h1).is_none());
        // Unknown hash misses.
        assert!(cache.get("s1", &h2).is_none());

        // Purge drops the whole session.
        cache.purge("s1");
        assert!(cache.get("s1", &h1).is_none());
    }
}
