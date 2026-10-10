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
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bytes::Bytes;
use futures::stream::BoxStream;
use futures::{Stream, StreamExt, TryStreamExt};
use object_store::path::Path as ObjPath;
use object_store::{GetResultPayload, ObjectStore, WriteMultipart};

use storage_rpc::CacheError;

fn internal(e: impl std::fmt::Display) -> CacheError {
    CacheError(e.to_string())
}

/// The first `len` bytes of `file`, in pieces of `piece` bytes, each read off
/// the runtime's threads.
fn file_pieces(
    file: std::fs::File,
    len: u64,
    piece: NonZeroUsize,
) -> BoxStream<'static, Result<Bytes, CacheError>> {
    use std::os::unix::fs::FileExt;
    let file = Arc::new(file);
    futures::stream::try_unfold(0u64, move |at| {
        let file = file.clone();
        async move {
            if at >= len {
                return Ok(None);
            }
            let take = piece.get().min((len - at) as usize);
            let piece = tokio::task::spawn_blocking(move || {
                let mut piece = vec![0u8; take];
                file.read_exact_at(&mut piece, at).map(|()| piece)
            })
            .await
            .map_err(internal)?
            .map_err(internal)?;
            Ok(Some((Bytes::from(piece), at + take as u64)))
        }
    })
    .boxed()
}

/// Max accepted key length — a hex SHA-256 label is 64 chars; allow headroom
/// without permitting an unbounded name.
const MAX_KEY_LEN: usize = 128;

/// What a blob being stored is written to disk in: pieces of this size, at most
/// [`PIECES_WRITING`] at a time. So a store holds about 16 MiB of a blob however
/// large it is, and waits for the disk when the stream outpaces it.
const PIECE_BYTES: usize = 8 * 1024 * 1024;
const PIECES_WRITING: usize = 2;

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
    /// The most the blobs, and the blobs being written, may take together.
    budget: u64,
    /// What a blob being loaded is read from disk in, and so the pieces it
    /// streams to its caller in. The store's own reader takes 8 KiB at a time,
    /// each on a thread of its own, and each piece then crossed the leg as a
    /// frame of its own — so a large blob cost its pieces rather than its bytes.
    read_piece: NonZeroUsize,
    /// What the blobs being written will take once written: a blob being
    /// written aside is not among those the store lists, so this is what counts
    /// it.
    writing: Arc<AtomicU64>,
    /// Held while room is made, so that two blobs making room at once do not
    /// both count the same room as theirs.
    making_room: Arc<tokio::sync::Mutex<()>>,
    /// When each blob was last loaded by this process — what keeps a blob in
    /// use when room has to be made. A restart forgets it and each blob counts
    /// from when it was written, which can only cost a bundle still in use one
    /// recompile.
    used: Arc<Mutex<HashMap<String, SystemTime>>>,
}

/// The room one blob being written holds in the budget, given back when the
/// write ends, however it ends.
struct Room {
    writing: Arc<AtomicU64>,
    length: u64,
}

impl Drop for Room {
    fn drop(&mut self) {
        self.writing.fetch_sub(self.length, Ordering::Relaxed);
    }
}

impl CacheBlobs {
    /// A cache in `store` that keeps within `budget` bytes, and reads a blob it
    /// loads in pieces of `read_piece` bytes.
    pub fn new(store: Arc<dyn ObjectStore>, budget: u64, read_piece: NonZeroUsize) -> Self {
        Self {
            store,
            budget,
            read_piece,
            writing: Arc::default(),
            making_room: Arc::default(),
            used: Arc::default(),
        }
    }

    fn used(&self) -> std::sync::MutexGuard<'_, HashMap<String, SystemTime>> {
        self.used.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Store the (sealed, opaque) blob `pieces` yield under `key`, in place of
    /// any blob before it (the api key is content+format-addressed, so a
    /// re-write is identical bytes or a fresh compile replacing a stale one).
    ///
    /// Room for its `length` is made before its first byte, by dropping the
    /// blobs used least recently, and held until it is written, so the cache
    /// is within its budget at every moment rather than once a sweep has run.
    /// A blob that does not fit even in an empty cache — or beside the blobs
    /// being written — is refused, and nothing is dropped for it.
    ///
    /// Written aside and put in place only once `pieces` has ended: a blob whose
    /// pieces fail, or a store dropped part-way, leaves what was there, and what
    /// was written aside goes with it.
    pub async fn store<S, E>(&self, key: &str, length: u64, mut pieces: S) -> Result<(), CacheError>
    where
        S: Stream<Item = Result<Bytes, E>> + Unpin,
        E: std::fmt::Display,
    {
        let path = object_path(key)?;
        let _room = self.make_room(length).await?;
        let upload = self.store.put_multipart(&path).await.map_err(internal)?;
        let mut writer = WriteMultipart::new_with_chunk_size(upload, PIECE_BYTES);
        while let Some(piece) = pieces.next().await {
            let written = match piece {
                Ok(piece) => {
                    writer.put(piece);
                    writer
                        .wait_for_capacity(PIECES_WRITING)
                        .await
                        .map_err(internal)
                }
                Err(e) => Err(internal(e)),
            };
            if let Err(e) = written {
                let _ = writer.abort().await;
                return Err(e);
            }
        }
        writer.finish().await.map_err(internal)?;
        Ok(())
    }

    /// The blob for `key`, as its length and its pieces. `Ok(None)` = miss
    /// (absent); `Err` only on a genuine store failure.
    #[allow(clippy::type_complexity)]
    pub async fn load(
        &self,
        key: &str,
    ) -> Result<Option<(u64, BoxStream<'static, Result<Bytes, CacheError>>)>, CacheError> {
        let path = object_path(key)?;
        match self.store.get(&path).await {
            Ok(res) => {
                self.used().insert(path.to_string(), SystemTime::now());
                let size = res.meta.size;
                let pieces = match res.payload {
                    GetResultPayload::File(file, _) => file_pieces(file, size, self.read_piece),
                    GetResultPayload::Stream(pieces) => pieces.map_err(internal).boxed(),
                };
                Ok(Some((size, pieces)))
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(internal(e)),
        }
    }

    /// Drop the blob for `key`, if there is one.
    pub async fn remove(&self, key: &str) -> Result<(), CacheError> {
        let path = object_path(key)?;
        match self.store.delete(&path).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
            Err(e) => return Err(internal(e)),
        }
        self.used().remove(path.as_ref());
        Ok(())
    }

    /// Room in the budget for a blob of `length` bytes, beside the blobs there
    /// and the blobs being written; held until the [`Room`] is dropped.
    async fn make_room(&self, length: u64) -> Result<Room, CacheError> {
        let _making = self.making_room.lock().await;
        let writing = self.writing.load(Ordering::Relaxed);
        let within = self
            .budget
            .checked_sub(writing)
            .and_then(|left| left.checked_sub(length))
            .ok_or_else(|| CacheError("no room in the cache for a blob this long".into()))?;
        self.drop_until(within).await?;
        self.writing.fetch_add(length, Ordering::Relaxed);
        Ok(Room {
            writing: self.writing.clone(),
            length,
        })
    }

    /// Bring the cache within its budget, beside the blobs being written —
    /// what a budget lowered since the blobs were written needs. Returns how
    /// many blobs it dropped.
    pub async fn evict(&self) -> Result<usize, CacheError> {
        let _making = self.making_room.lock().await;
        let within = self
            .budget
            .saturating_sub(self.writing.load(Ordering::Relaxed));
        self.drop_until(within).await
    }

    /// Bring the blobs under `within` bytes, dropping first the ones used
    /// least recently — loaded, or else written. Returns how many it dropped.
    ///
    /// The cache shares its volume with the session store and nothing else
    /// ever removes a blob, so without this it grows until session writes
    /// fail. A blob dropped while still wanted costs a miss and a recompile;
    /// the clock it is judged by is the host's, so skewing it can only make
    /// that happen sooner.
    async fn drop_until(&self, within: u64) -> Result<usize, CacheError> {
        let listed = self
            .store
            .list_with_delimiter(None)
            .await
            .map_err(internal)?;
        let mut total: u64 = listed.objects.iter().map(|m| m.size).sum();
        if total <= within {
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
            if total <= within {
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

    /// `bytes` as a stream of `piece`-sized pieces.
    fn pieces(bytes: &[u8], piece: usize) -> impl Stream<Item = Result<Bytes, CacheError>> + Unpin {
        futures::stream::iter(
            bytes
                .chunks(piece)
                .map(|p| Ok(Bytes::copy_from_slice(p)))
                .collect::<Vec<_>>(),
        )
    }

    /// A budget no test here reaches unless it means to.
    const ROOMY: u64 = 64 * 1024 * 1024;

    /// What the tests read a blob on disk in: small, so a test blob spans
    /// several pieces.
    const READ_PIECE: NonZeroUsize = NonZeroUsize::new(64 * 1024).unwrap();

    fn cache(budget: u64) -> CacheBlobs {
        CacheBlobs::new(Arc::new(InMemory::new()), budget, READ_PIECE)
    }

    async fn put(cache: &CacheBlobs, key: &str, bytes: &[u8]) {
        cache
            .store(key, bytes.len() as u64, pieces(bytes, 1000))
            .await
            .unwrap();
    }

    /// The blob under `key`, read whole, checked against the length it came with.
    async fn get(cache: &CacheBlobs, key: &str) -> Option<Vec<u8>> {
        let (len, pieces) = cache.load(key).await.unwrap()?;
        let bytes: Vec<u8> = pieces
            .try_fold(Vec::new(), |mut all, p| async move {
                all.extend_from_slice(&p);
                Ok(all)
            })
            .await
            .unwrap();
        assert_eq!(bytes.len() as u64, len);
        Some(bytes)
    }

    #[tokio::test]
    async fn store_load_roundtrip_and_miss() {
        let cache = cache(ROOMY);
        let key = "deadbeef".repeat(8); // 64 hex chars
        assert_eq!(get(&cache, &key).await, None);
        let blob: Vec<u8> = (0..20 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        cache
            .store(&key, blob.len() as u64, pieces(&blob, 65_536))
            .await
            .unwrap();
        assert_eq!(get(&cache, &key).await, Some(blob));
    }

    /// A blob on disk comes back whole across several read pieces and a short
    /// last one.
    #[tokio::test]
    async fn a_blob_on_disk_loads_whole_in_pieces() {
        let dir = tempfile::tempdir().unwrap();
        let store = object_store::local::LocalFileSystem::new_with_prefix(dir.path()).unwrap();
        let cache = CacheBlobs::new(Arc::new(store), ROOMY, READ_PIECE);
        let key = "ef".repeat(32);
        let blob: Vec<u8> = (0..READ_PIECE.get() * 2 + 12_345)
            .map(|i| (i % 253) as u8)
            .collect();
        put(&cache, &key, &blob).await;
        assert_eq!(get(&cache, &key).await, Some(blob));
    }

    /// A blob whose pieces fail part-way never takes the place of the one before.
    #[tokio::test]
    async fn a_store_that_fails_part_way_leaves_what_was_there() {
        let cache = cache(ROOMY);
        let key = "ab".repeat(32);
        put(&cache, &key, b"old").await;
        let failing = futures::stream::iter(vec![
            Ok(Bytes::from_static(b"ne")),
            Err(CacheError("the stream broke".into())),
        ]);
        assert!(cache.store(&key, 3, failing).await.is_err());
        assert_eq!(get(&cache, &key).await, Some(b"old".to_vec()));
        assert_eq!(
            cache.writing.load(Ordering::Relaxed),
            0,
            "its room is given back"
        );
    }

    #[tokio::test]
    async fn a_removed_blob_is_a_miss() {
        let cache = cache(ROOMY);
        let key = "cd".repeat(32);
        put(&cache, &key, b"x").await;
        cache.remove(&key).await.unwrap();
        assert_eq!(get(&cache, &key).await, None);
        cache
            .remove(&key)
            .await
            .expect("removing a miss is not an error");
    }

    /// A full cache makes room for a new blob before writing it: the blob
    /// nobody has asked for since it was written goes first, and one just
    /// loaded stays, however long ago it was written.
    #[tokio::test]
    async fn a_store_makes_room_dropping_the_least_recently_used_first() {
        let cache = cache(300);
        let keys: Vec<String> = ["aa", "bb", "cc", "dd"]
            .iter()
            .map(|k| k.repeat(32))
            .collect();
        for key in &keys[..3] {
            put(&cache, key, &[0u8; 100]).await;
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(get(&cache, &keys[0]).await.is_some());

        put(&cache, &keys[3], &[0u8; 100]).await;
        assert!(get(&cache, &keys[0]).await.is_some());
        assert_eq!(get(&cache, &keys[1]).await, None);
        assert!(get(&cache, &keys[2]).await.is_some());
        assert!(get(&cache, &keys[3]).await.is_some());
    }

    /// A blob that would not fit even alone is refused before anything is
    /// dropped for it.
    #[tokio::test]
    async fn a_blob_longer_than_the_cache_is_refused_and_drops_nothing() {
        let cache = cache(100);
        let kept = "ab".repeat(32);
        put(&cache, &kept, &[0u8; 100]).await;
        let long = [0u8; 101];
        assert!(
            cache
                .store(&"cd".repeat(32), 101, pieces(&long, 1000))
                .await
                .is_err()
        );
        assert!(get(&cache, &kept).await.is_some());
    }

    /// The room a blob being written holds counts against the next one, and is
    /// given back once it is written.
    #[tokio::test]
    async fn a_blob_being_written_holds_its_room() {
        let cache = cache(200);
        let (tx, rx) = futures::channel::mpsc::unbounded::<Result<Bytes, CacheError>>();
        let writing = tokio::spawn({
            let cache = cache.clone();
            async move { cache.store(&"aa".repeat(32), 150, rx).await }
        });
        while cache.writing.load(Ordering::Relaxed) != 150 {
            tokio::task::yield_now().await;
        }
        let beside = [0u8; 100];
        assert!(
            cache
                .store(&"bb".repeat(32), 100, pieces(&beside, 1000))
                .await
                .is_err(),
            "100 bytes do not fit beside 150 being written in 200"
        );

        tx.unbounded_send(Ok(Bytes::from(vec![0u8; 150]))).unwrap();
        drop(tx);
        writing.await.unwrap().unwrap();
        assert_eq!(cache.writing.load(Ordering::Relaxed), 0);
        put(&cache, &"cc".repeat(32), &[0u8; 50]).await;
    }

    /// A budget lowered since the blobs were written is reached by the sweep.
    #[tokio::test]
    async fn the_sweep_brings_the_cache_within_a_lowered_budget() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let before = CacheBlobs::new(store.clone(), 300, READ_PIECE);
        for key in ["aa", "bb", "cc"] {
            put(&before, &key.repeat(32), &[0u8; 100]).await;
        }
        let after = CacheBlobs::new(store, 200, READ_PIECE);
        assert_eq!(after.evict().await.unwrap(), 1);
        assert_eq!(after.evict().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_cache_within_budget_is_left_alone() {
        let cache = cache(100);
        let key = "ab".repeat(32);
        put(&cache, &key, &[0u8; 100]).await;
        assert_eq!(cache.evict().await.unwrap(), 0);
        assert!(get(&cache, &key).await.is_some());
    }

    #[tokio::test]
    async fn rejects_non_hex_key() {
        let cache = cache(ROOMY);
        assert!(cache.load("../etc/passwd").await.is_err());
        assert!(cache.store("a/b", 1, pieces(b"x", 1)).await.is_err());
        assert!(cache.remove("a/b").await.is_err());
    }
}
