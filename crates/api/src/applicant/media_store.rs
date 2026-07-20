//! Host media store the keyless execution-worker calls BACK for
//! `blob::from-blob-ref` (via `CallbackService::media_load`) — a **pull-through
//! cache** over the sealed broker backing store, with a **gate** on the read
//! key. It runs orchestrator-side because it holds the seal key + applicant
//! token the worker must never see.
//!
//! `blob::from-blob-ref` mints a COLD handle (no load); the worker calls
//! [`load`](BrokerMediaStore::load) LAZILY on the first `bytes()` read of that
//! handle, which forwards to this callback. This:
//!   1. serves a **cache hit** with no host IO;
//!   2. **gates** an unknown hash — a ref not in the session's captured set is a
//!      fabricated key, refused here with no broker read (the worker then traps,
//!      since `from-blob-ref` has no miss branch);
//!   3. **pulls** a real-but-uncached blob from the backing store
//!      ([`SessionStore::load_media`]), decrypts, populates the cache, and
//!      returns the bytes.
//!
//! Covert-channel role (defence-in-depth; primary defence is attestation +
//! consent-gate). The read KEY (`blob_hash`) goes to the host in plaintext, and
//! each read is a host-observable event. Left unguarded, a colluding policy
//! could encode data into the key (32 B/call) or into the count/pattern of
//! calls (Morse). The gate kills the arbitrary-key variant (only real captures
//! ever reach the host — whose hashes it already logged at write). The cache
//! bounds the count variant to **≤1 host read per distinct blob while it stays
//! resident** (the first pull; repeats hit in-TEE). Cache eviction under the
//! byte budget (or idle expiry) can drop a blob, so a later re-read re-pulls —
//! but eviction is driven by aggregate cross-session load / elapsed time, not by
//! the policy, so it hands the policy no controllable signal. The irreducible
//! residual — which of a few captures is pulled, and when — is fuel-bounded and
//! host-compromise-gated, the same class as APSI query counts.

use std::collections::HashSet;
use std::sync::{Arc, Weak};
use std::time::Duration;

use broker_client::{Replay, SessionStore, public_session_id, reason};
use moka::future::Cache;
use rpc::CallbackError;
use secrecy::{ExposeSecret, SecretBox};

/// Byte budget for the pull-through media cache — a soft RAM ceiling (moka
/// enforces `max_capacity` via background maintenance, so the weighed size can
/// briefly overshoot under a burst before eviction catches up) weighed by blob
/// length, not entry count, since blobs vary in size. Blobs are cached only on a
/// `from-blob-ref` READ (never at write) and re-reads are rare in the current
/// flow, so the cache normally sits far below this — it is a backstop, not a
/// working-set target.
const MEDIA_CACHE_MAX_BYTES: u64 = 128 * 1024 * 1024;

/// Idle expiry for a cached blob. The covert-channel defence the cache provides
/// is collapsing REPEAT reads of the same blob into ≤1 host-observable broker
/// read; the repeats a colluding policy can actually drive happen WITHIN one
/// `handle` invocation — it has no clock and cannot sleep (WASI clocks are
/// virt-baked, and fuel bounds execution) — i.e. sub-second, so any short idle
/// window preserves the defence. 1 minute is therefore ample: `time_to_idle`
/// resets on each read, so a blob stays warm while actively used, and the
/// decrypted biometric plaintext leaves host RAM ~1 minute after its last touch —
/// tight data-minimization. It is NOT a session/token-tied boundary: a genuine
/// re-read in a much-later round simply re-pulls once (benign; the cross-round
/// gap is applicant-timed, not policy-controllable, so it is no covert lever).
const MEDIA_CACHE_TTI: Duration = Duration::from_secs(60);

/// Bounded pull-through cache of rehydrated media blobs, shared across rounds via
/// `AppState`. A [`moka`] cache keyed GLOBALLY by `(session_id, blob_hash)`, so
/// the [byte budget](MEDIA_CACHE_MAX_BYTES) and [idle expiry](MEDIA_CACHE_TTI)
/// bound total host RAM no matter how many sessions are live — an abandoned
/// session can no longer pin decrypted blobs without bound. Populated on a
/// `from-blob-ref` READ miss (never at write), so it holds only blobs the policy
/// actually re-reads. It is host-side heap, so the wasm store memory limit does
/// NOT bound it — the budget/TTI plus the per-session `purge` on `/reset` +
/// finalize are the budget. An evicted blob is simply re-pulled and re-cached on
/// the next read; correctness is preserved (see the module-level covert note).
/// moka is the api's established cache idiom (compiled policies + applicant
/// tokens both use it, session-keyed, with `max_capacity` + `time_to_idle`).
pub struct MediaCache {
    cache: Cache<(String, [u8; 32]), Arc<Vec<u8>>>,
}

impl MediaCache {
    pub fn new() -> Self {
        Self::with_budget(MEDIA_CACHE_MAX_BYTES, MEDIA_CACHE_TTI)
    }

    fn with_budget(max_bytes: u64, tti: Duration) -> Self {
        Self {
            cache: Cache::builder()
                // Weigh each entry by its byte length so `max_capacity` is a RAM
                // budget, not an entry count. A blob past `u32::MAX` is clamped —
                // it can't exist (state/upload limits are far smaller).
                .weigher(|_key, bytes: &Arc<Vec<u8>>| bytes.len().try_into().unwrap_or(u32::MAX))
                .max_capacity(max_bytes)
                .time_to_idle(tti)
                .build(),
        }
    }

    async fn get(&self, session_id: &str, hash: &[u8; 32]) -> Option<Arc<Vec<u8>>> {
        // `get` refreshes the entry's idle timer and access frequency, so an
        // actively-reloaded blob outlives idle ones under eviction.
        self.cache.get(&(session_id.to_string(), *hash)).await
    }

    async fn insert(&self, session_id: &str, hash: [u8; 32], bytes: Arc<Vec<u8>>) {
        self.cache.insert((session_id.to_string(), hash), bytes).await;
    }

    /// Drop a session's cached blobs — called when its media is purged
    /// (`/reset`, finalize). Prompt per-key `invalidate` (mirrors the
    /// applicant-session-token cache's `invalidate` on reset), so decrypted bytes
    /// leave RAM at session end rather than only at the idle backstop. Removes
    /// exactly this session's entries; other sessions' blobs are untouched.
    /// O(live entries), which the budget bounds.
    pub async fn purge(&self, session_id: &str) {
        let stale: Vec<Arc<(String, [u8; 32])>> = self
            .cache
            .iter()
            .filter(|(key, _)| key.0 == session_id)
            .map(|(key, _)| key)
            .collect();
        for key in stale {
            self.cache.invalidate(&*key).await;
        }
    }
}

pub(super) struct BrokerMediaStore {
    pub session_store: Arc<SessionStore>,
    pub session_id: String,
    /// WEAK handle to the applicant bearer — the inner AEAD layer's key,
    /// needed to OPEN a sealed media blob on load. `Weak` (not owned): the
    /// per-round `SessionRunCtx` is the sole strong owner, so this store
    /// borrows the token in the moment (`upgrade` while the run is live) but
    /// can never PIN the plaintext — its lifetime is exactly the round. A
    /// `None` upgrade means the run outlived its context (a lifetime bug),
    /// surfaced as a trap.
    pub applicant_session_token: Weak<SecretBox<Vec<u8>>>,
    /// Pull-through cache (shared, cross-round). Repeat rehydrates hit here, so
    /// the host sees at most one broker read per distinct blob.
    pub cache: Arc<MediaCache>,
    /// GATE — the session's captured blob hashes (from sealed metadata, prior
    /// rounds). A rehydrate for a hash NOT in here is a fabricated ref, refused
    /// in-TEE with no broker read, so the plaintext read key can't carry data.
    pub captured: HashSet<[u8; 32]>,
}

impl BrokerMediaStore {
    /// Rehydrate one stored blob by content hash — the api side of the keyless
    /// executor's `CallbackService::media_load`. Returns owned bytes for the
    /// wire (`None` = miss / gated), so the worker's `from-blob-ref` traps on a
    /// `None` exactly as the in-process store did. The seal key never leaves
    /// this side — the worker only ever receives the decrypted bytes it asked
    /// for by an already-captured hash.
    pub(super) async fn load(
        &self,
        blob_hash: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, CallbackError> {
        // 1. Cache hit — served here, no host IO. Clone the bytes for the wire.
        if let Some(hit) = self.cache.get(&self.session_id, blob_hash).await {
            return Ok(Some(hit.as_ref().clone()));
        }
        // 2. Gate — an unknown hash is a fabricated ref: refuse with no broker
        //    read. The worker traps on the `None` (from-blob-ref has no miss branch).
        if !self.captured.contains(blob_hash) {
            return Ok(None);
        }
        // 3. Pull-through — fetch the sealed blob, decrypt, cache, return.
        //    Borrow the token from the per-round owner for the moment of the
        //    open. A `None` upgrade means the run outlived its context.
        let token = self.applicant_session_token.upgrade().ok_or_else(|| {
            CallbackError(
                "media load: applicant token owner dropped (run outlived its context)".into(),
            )
        })?;
        let id = public_session_id(&self.session_id);
        let loaded = self
            .session_store
            .load_media(id, blob_hash, token.expose_secret())
            .await
            .map_err(|e| CallbackError(format!("media load failed: {e}")))?
            .trust_unchecked::<Replay, _>(reason!(
                "media blob is content-addressed by BLAKE3; a stale or reordered read \
                 can only return identical bytes"
            ))
            .into_inner();
        let Some(vec) = loaded else {
            return Ok(None);
        };
        let arc = Arc::new(vec);
        self.cache
            .insert(&self.session_id, *blob_hash, arc.clone())
            .await;
        Ok(Some(arc.as_ref().clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn media_cache_hit_isolation_and_purge() {
        let cache = MediaCache::new();
        let (h1, h2) = ([1u8; 32], [2u8; 32]);

        // Miss on an empty cache.
        assert!(cache.get("s1", &h1).await.is_none());

        // Insert then hit — and the hit shares the SAME allocation (no copy).
        let bytes = Arc::new(vec![10u8, 20, 30]);
        cache.insert("s1", h1, bytes.clone()).await;
        let hit = cache.get("s1", &h1).await.expect("hit");
        assert!(Arc::ptr_eq(&hit, &bytes), "cache serves the shared Arc");

        // Session isolation: same hash under a different session misses.
        assert!(cache.get("s2", &h1).await.is_none());
        // Unknown hash misses.
        assert!(cache.get("s1", &h2).await.is_none());

        // Purge drops the whole session.
        cache.purge("s1").await;
        assert!(cache.get("s1", &h1).await.is_none());
    }

    #[tokio::test]
    async fn media_cache_purge_is_per_session() {
        // Purge removes only the named session's blobs; a co-resident session's
        // entries survive.
        let cache = MediaCache::new();
        let h = [7u8; 32];
        cache.insert("keep", h, Arc::new(vec![1])).await;
        cache.insert("drop", h, Arc::new(vec![2])).await;

        cache.purge("drop").await;

        assert!(cache.get("drop", &h).await.is_none(), "purged session gone");
        assert!(cache.get("keep", &h).await.is_some(), "other session kept");
    }

    #[tokio::test]
    async fn media_cache_bounds_total_bytes() {
        // The byte budget is a RAM ceiling, not an entry count: inserting past it
        // evicts, keeping the weighed size within cap. An evicted blob is simply
        // re-pulled on the next read (correctness preserved).
        let cache = MediaCache::with_budget(100, MEDIA_CACHE_TTI);
        for i in 0..10u8 {
            cache.insert("s", [i; 32], Arc::new(vec![0u8; 30])).await;
        }
        cache.cache.run_pending_tasks().await;
        assert!(
            cache.cache.weighted_size() <= 100,
            "byte budget enforced, weighted_size = {}",
            cache.cache.weighted_size()
        );
    }
}
