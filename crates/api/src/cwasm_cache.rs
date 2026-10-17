//! L2 cwasm-cache: best-effort store / open of a compiled bundle.
//!
//! This is the fleet's DURABLE cache tier and the orchestrator's ONLY compiled
//! artifact store — [`storage_client::CacheStore`], sealed under `tee_seal_key`,
//! over the storage-CVM backend api dials at boot. It survives a TEE restart.
//! There is no api-side in-RAM component cache; the sole in-memory L1 lives on
//! the execution-worker, which on a miss says so (`RunOutcome::CacheMiss`) and
//! lets api open one from here. A compiled bundle is a pure function of the
//! pinned artifacts, so a cold compile stores it once and every later boot or
//! worker miss reloads it without re-pulling or re-compiling.
//!
//! ## What an entry holds
//!
//! In this order: the cwasm's SHA-256 and the metadata as the execute hop
//! streams it, each a CBOR byte string, then the cwasm, raw, to the entry's end.
//! The CBOR heads say where each string ends, and so where the cwasm starts and
//! how long it is. A hit reads the digest and the metadata, both small, and
//! names the cwasm to the worker before a byte of it is read; the cwasm then
//! goes from the cache to the worker a piece at a time, and api never holds it
//! whole.
//!
//! ## Compatibility / invalidation — guards
//!
//! A stale on-disk bundle after a code update must never load wrong:
//!   1. `compat_token` + [`CACHE_FORMAT_VERSION`] folded into `cache_id` — the
//!      token is the execution-worker's cwasm ABI id (wasmtime version + config +
//!      target), so a fleet runtime bump gives the new worker a new key ⇒ a MISS
//!      (recompile) instead of a stale, incompatible cwasm; a change to the entry
//!      or to the metadata's layout does the same via the format epoch. Old blobs
//!      are never addressed by the new binary/runtime. A preparation names the
//!      token the way a round does: by the worker's miss.
//!   2. The worker decodes the metadata under `deny_unknown_fields` and no
//!      `#[serde(default)]`, so even if a version bump is forgotten, ANY
//!      struct-shape drift refuses the bundle rather than misreading it.
//!   3. wasmtime's own compatibility header — the execution-worker's
//!      `deserialize_component` returns `Err` on a residual ABI skew. api can't
//!      pre-check that (no wasmtime), so it surfaces as a run failure; but guard 1
//!      makes it unreachable as long as the `compat_token` faithfully tracks the
//!      ABI. (The semantic case — same field shape, changed meaning — is caught
//!      only by guard 1.)
//!
//! ## What the seal bounds, and what it does not
//!
//! The seal binds a stored bundle to its `cache_id` under a key the host cannot
//! hold, so the host cannot substitute one composition's cwasm for another's or
//! forge an entry. That is the whole of it.
//!
//! It says nothing about whether the bytes are the right compilation of the
//! pinned artifacts, because api performs the seal — over whatever the
//! compile-worker returned. The binding runs from api's key to api's name, and a
//! compiler that returned something else would have that sealed just as faithfully.
//! Nothing on the compile leg closes that (see `crate::compiler`, where the
//! accepted risk is written); the store is not where it could be closed.
//!
//! Store and open are BEST-EFFORT: a miss, a transport failure, or an entry
//! that does not open all degrade to the cold compile path. The cache is a pure
//! optimization; correctness never depends on it.

use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use futures::{StreamExt, TryStreamExt};

use engine_rpc::{
    BundleSource, CompatToken, CompositionKey, MAX_BUNDLE_META_BYTES, MAX_CWASM_BYTES,
};
use storage_client::{BlobPieces, CacheStore, StoreError};

use crate::compiler::Compiled;

/// Bumped whenever an entry's layout changes — what precedes the cwasm, or the
/// metadata's encoding (a field of `BundleMeta` added / removed / retyped, or a
/// nested serde type's shape changes). A bump re-partitions the cache: old
/// entries get a different `cache_id` and are never read (guard 1).
const CACHE_FORMAT_VERSION: u32 = 3;

/// What an entry's first read takes, before where its metadata ends is known:
/// one sealed segment. What precedes the metadata is in it, and an ordinary
/// metadata is all in it.
const FIRST_READ: usize = enclavid_crypto::sealed_stream::SEGMENT_BYTES;

/// What precedes an entry's metadata: the cwasm's digest, and the head of the
/// metadata's string, `meta_len` bytes long — each as CBOR writes it.
fn front(cwasm_sha256: &[u8; 32], meta_len: usize) -> Vec<u8> {
    let mut front = string_head(cwasm_sha256.len());
    front.extend_from_slice(cwasm_sha256);
    front.extend(string_head(meta_len));
    front
}

/// Where an entry's parts are, read off its first bytes: the cwasm's digest, and
/// the span of the metadata, which may run past what was read. The cwasm is what
/// follows the metadata, to the entry's end.
struct Front {
    cwasm_sha256: [u8; 32],
    meta: Range<usize>,
    cwasm_len: u64,
}

impl Front {
    /// The front of an entry `length` bytes long, from `start`, its first bytes
    /// — the digest's string and the metadata's head in full. Held to the bounds
    /// the execute hop takes.
    fn read(start: &[u8], length: u64) -> Result<Self, StoreError> {
        let digest = string_at(start, 0)?;
        let cwasm_sha256 = start
            .get(digest.clone())
            .and_then(|digest| digest.try_into().ok())
            .ok_or_else(not_an_entry)?;
        let meta = string_at(start, digest.end)?;
        let cwasm_len = length
            .checked_sub(meta.end as u64)
            .ok_or_else(not_an_entry)?;
        if meta.len() as u64 > MAX_BUNDLE_META_BYTES || cwasm_len > MAX_CWASM_BYTES {
            return Err(not_an_entry());
        }
        Ok(Self {
            cwasm_sha256,
            meta,
            cwasm_len,
        })
    }
}

/// Where the byte string whose CBOR head is at `at` in `start` lies — the head
/// read by ciborium's own decoder, which is what knows how long a head is and
/// what it says. The string itself may run past `start`.
fn string_at(start: &[u8], at: usize) -> Result<Range<usize>, StoreError> {
    let mut decoder = ciborium_ll::Decoder::from(start.get(at..).unwrap_or_default());
    match decoder.pull() {
        Ok(ciborium_ll::Header::Bytes(Some(len))) => {
            let from = at + decoder.offset();
            Ok(from..from.checked_add(len).ok_or_else(not_an_entry)?)
        }
        _ => Err(not_an_entry()),
    }
}

/// The CBOR head of a byte string `len` bytes long.
fn string_head(len: usize) -> Vec<u8> {
    let mut head = Vec::new();
    ciborium_ll::Encoder::from(&mut head)
        .push(ciborium_ll::Header::Bytes(Some(len)))
        .expect("CBOR into memory fails only on a write, and a Vec refuses none");
    head
}

fn not_an_entry() -> StoreError {
    StoreError::Codec("an L2 entry not laid out as one".into())
}

/// Opaque cache key: the composition hash scoped by the runtime ABI
/// (`compat_token`) and the entry-format epoch. [`CacheStore`] uses it as both
/// the seal's AAD and the filename-label input, so a runtime bump OR a format
/// bump invalidates cleanly.
///
/// Both halves are types rather than strings, which is what makes the join
/// unambiguous: the first is 64 hex characters and the second cannot be empty, so
/// no two distinct pairs render to one id. As bare strings the second half was a
/// worker-chosen value of any length going straight into a name.
fn cache_id(composition_key: &CompositionKey, compat_token: &CompatToken) -> String {
    format!("{composition_key}.{compat_token}.v{CACHE_FORMAT_VERSION}")
}

/// Keep `compiled` in L2 under `(composition_key, compat_token)`, its cwasm
/// passing through as it comes. Best-effort: a failure is logged and swallowed;
/// a broken cache never breaks a session. A cwasm that fails part-way, or is not
/// the length it was named, is not kept.
pub async fn store(
    cache: &CacheStore,
    composition_key: &CompositionKey,
    compat_token: &CompatToken,
    compiled: Compiled,
) {
    let front = front(&compiled.cwasm_sha256, compiled.meta.len());
    let length = (front.len() + compiled.meta.len()) as u64 + compiled.cwasm_len;
    let pieces = futures::stream::iter([Ok(Bytes::from(front)), Ok(Bytes::from(compiled.meta))])
        .chain(
            compiled.cwasm.map_err(|()| {
                StoreError::Transport("the cwasm stopped part-way; not stored".into())
            }),
        );
    if let Err(e) = cache
        .store(
            &cache_id(composition_key, compat_token),
            length,
            pieces.boxed(),
        )
        .await
    {
        safe_logger::debug!("cwasm_cache: L2 store failed (non-fatal): {e}");
    }
}

/// An L2 hit, ready for the worker: the bundle, its cwasm streaming from the
/// cache as the worker reads it, and whether that stream found the entry bad.
pub struct Hit {
    pub source: BundleSource,
    pub found_bad: FoundBad,
}

/// Whether a hit's cwasm stream ended because the entry did not open, or did not
/// hold what its start said — not because the leg under it failed. An entry
/// found bad stays bad, so it is dropped rather than read again.
pub struct FoundBad(Arc<AtomicBool>);

impl FoundBad {
    pub fn get(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Open the L2 entry for `(composition_key, compat_token)`. Returns `None` on a
/// miss, a transport failure, or an entry whose start does not open or is not
/// laid out as one — all before the worker is called, so the caller takes the
/// cold path with nothing sent.
pub async fn open(
    cache: &CacheStore,
    composition_key: &CompositionKey,
    compat_token: &CompatToken,
) -> Option<Hit> {
    let (length, pieces) = match cache.load(&cache_id(composition_key, compat_token)).await {
        Ok(Some(entry)) => entry,
        Ok(None) => return None,
        Err(e) => {
            safe_logger::debug!("cwasm_cache: L2 load transport error (cold path): {e}");
            return None;
        }
    };
    let (meta, front, cwasm) = match split(pieces, length).await {
        Ok(split) => split,
        Err(e) => {
            safe_logger::debug!("cwasm_cache: L2 entry did not open (cold path): {e}");
            return None;
        }
    };
    let bad = Arc::new(AtomicBool::new(false));
    let flag = bad.clone();
    let cwasm = cwasm
        .try_filter(|piece| std::future::ready(!piece.is_empty()))
        .inspect_err(move |e| {
            if matches!(e, StoreError::Crypto(_) | StoreError::Codec(_)) {
                flag.store(true, Ordering::Relaxed);
            }
        });
    let source = BundleSource::streamed(front.cwasm_len, front.cwasm_sha256, meta, cwasm)?;
    Some(Hit {
        source,
        found_bad: FoundBad(bad),
    })
}

/// An entry's `pieces`, `length` bytes in all, taken apart: its metadata, its
/// front, and its cwasm, still to stream. What of the first read is past the
/// metadata is the cwasm's start; a metadata past the first read goes on in the
/// pieces after it.
async fn split(
    mut pieces: BlobPieces,
    length: u64,
) -> Result<(Vec<u8>, Front, BlobPieces), StoreError> {
    let mut rest = Bytes::new();
    let first = FIRST_READ.min(usize::try_from(length).unwrap_or(usize::MAX));
    let first = Bytes::from(take(&mut pieces, &mut rest, first).await?);
    let front = Front::read(&first, length)?;
    let (meta, cwasm_start) = match first.get(front.meta.clone()) {
        Some(meta) => (meta.to_vec(), first.slice(front.meta.end..)),
        None => {
            let mut meta = first[front.meta.start..].to_vec();
            let more = front.meta.end - first.len();
            meta.extend(take(&mut pieces, &mut rest, more).await?);
            (meta, Bytes::new())
        }
    };
    let cwasm = futures::stream::iter([Ok(cwasm_start), Ok(rest)])
        .chain(pieces)
        .boxed();
    Ok((meta, front, cwasm))
}

/// Drop the L2 entry for `(composition_key, compat_token)`. Best-effort, like
/// the rest: an entry that stays is found bad again and dropped then.
pub async fn remove(
    cache: &CacheStore,
    composition_key: &CompositionKey,
    compat_token: &CompatToken,
) {
    if let Err(e) = cache.remove(&cache_id(composition_key, compat_token)).await {
        safe_logger::debug!("cwasm_cache: L2 remove failed (non-fatal): {e}");
    }
}

/// The first `n` bytes of `pieces`, with `rest` what the last piece read held
/// past them.
async fn take(pieces: &mut BlobPieces, rest: &mut Bytes, n: usize) -> Result<Vec<u8>, StoreError> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        if rest.is_empty() {
            *rest = pieces
                .next()
                .await
                .ok_or_else(|| StoreError::Codec("an L2 entry shorter than it says".into()))??;
            continue;
        }
        let part = rest.split_to((n - out.len()).min(rest.len()));
        out.extend_from_slice(&part);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> CompositionKey {
        CompositionKey::from_digest([byte; 32])
    }

    fn token(s: &str) -> CompatToken {
        CompatToken::parse(s).expect("a legal token shape")
    }

    #[test]
    fn cache_id_scopes_by_composition_token_and_format() {
        assert_eq!(
            cache_id(&key(0xAB), &token("tok")),
            format!("{}.tok.v{CACHE_FORMAT_VERSION}", key(0xAB))
        );
        // Composition, token, and format each partition the key.
        assert_ne!(
            cache_id(&key(0xAB), &token("tok")),
            cache_id(&key(0xAC), &token("tok"))
        );
        assert_ne!(
            cache_id(&key(0xAB), &token("tok")),
            cache_id(&key(0xAB), &token("tok2"))
        );
    }

    /// The two halves cannot be made to render as one another's: the first is a
    /// fixed 64 characters, so no token can push the boundary and land a pair on
    /// another pair's id. As bare strings that argument rested on the shapes
    /// nobody was checking.
    #[test]
    fn no_token_can_forge_another_pairs_id() {
        let honest = cache_id(&key(0xAB), &token("wt46-cm-fuel"));
        for forged in ["a", "a.b", &format!("x.{}", key(0xAC))] {
            let Ok(t) = CompatToken::parse(forged) else {
                continue;
            };
            assert_ne!(cache_id(&key(0xAC), &t), honest);
        }
    }

    /// Pieces of `piece` bytes.
    fn pieces(bytes: &[u8], piece: usize) -> BlobPieces {
        let pieces: Vec<_> = bytes
            .chunks(piece)
            .map(|p| Ok(Bytes::copy_from_slice(p)))
            .collect();
        futures::stream::iter(pieces).boxed()
    }

    /// `take` reads across pieces of any size and keeps what it does not need.
    #[tokio::test]
    async fn take_reads_across_pieces_and_keeps_the_rest() {
        let bytes: Vec<u8> = (0..100).collect();
        let mut from = pieces(&bytes, 7);
        let mut rest = Bytes::new();
        assert_eq!(take(&mut from, &mut rest, 10).await.unwrap(), bytes[..10]);
        assert_eq!(
            take(&mut from, &mut rest, 0).await.unwrap(),
            Vec::<u8>::new()
        );
        assert_eq!(take(&mut from, &mut rest, 30).await.unwrap(), bytes[10..40]);
        assert_eq!(rest[..], bytes[40..42]);
        assert!(
            take(&mut from, &mut rest, 100).await.is_err(),
            "past the end"
        );
    }

    /// A cache in memory, under the real store's seal.
    #[derive(Default)]
    struct Blobs {
        held: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl storage_client::CacheBackend for Blobs {
        async fn store(
            &self,
            name: &str,
            length: u64,
            pieces: BlobPieces,
        ) -> Result<(), StoreError> {
            let blob = read(pieces).await?;
            assert_eq!(blob.len() as u64, length);
            self.held.lock().unwrap().insert(name.to_string(), blob);
            Ok(())
        }

        async fn load(&self, name: &str) -> Result<Option<(u64, BlobPieces)>, StoreError> {
            let Some(blob) = self.held.lock().unwrap().get(name).cloned() else {
                return Ok(None);
            };
            Ok(Some((blob.len() as u64, pieces(&blob, 4096))))
        }

        async fn remove(&self, name: &str) -> Result<(), StoreError> {
            self.held.lock().unwrap().remove(name);
            Ok(())
        }
    }

    async fn read(pieces: BlobPieces) -> Result<Vec<u8>, StoreError> {
        pieces
            .try_fold(Vec::new(), |mut all, p| async move {
                all.extend_from_slice(&p);
                Ok(all)
            })
            .await
    }

    fn cwasm(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// A compile of `meta` and `cwasm`, the cwasm passing through in pieces.
    fn entry(meta: &[u8], cwasm: &[u8]) -> Compiled {
        Compiled {
            meta: meta.to_vec(),
            cwasm_len: cwasm.len() as u64,
            cwasm_sha256: fleet_stream::BlobHeader::<MAX_CWASM_BYTES>::of(cwasm)
                .unwrap()
                .sha256(),
            cwasm: pieces(cwasm, 10_000).map_err(|_| ()).boxed(),
        }
    }

    /// What `store` writes is the digest and the metadata, each a CBOR byte
    /// string, then the cwasm — as CBOR itself reads it back — and `open` takes
    /// it as such, sending nothing back as bad.
    #[tokio::test]
    async fn an_entry_holds_its_digest_its_metadata_then_its_cwasm() {
        let cache = CacheStore::new(Arc::new(Blobs::default()), &[3; 32]);
        let (meta, cwasm) = (b"the metadata".to_vec(), cwasm(300_000));
        let stored = entry(&meta, &cwasm);
        let sha256 = stored.cwasm_sha256;
        store(&cache, &key(1), &token("tok"), stored).await;

        let (length, plain) = cache
            .load(&cache_id(&key(1), &token("tok")))
            .await
            .unwrap()
            .unwrap();
        let entry = read(plain).await.unwrap();
        assert_eq!(entry.len() as u64, length);
        let mut rest = &entry[..];
        let string = |rest: &mut &[u8]| match ciborium::from_reader(rest).unwrap() {
            ciborium::Value::Bytes(bytes) => bytes,
            other => panic!("not a byte string: {other:?}"),
        };
        assert_eq!(string(&mut rest), sha256);
        assert_eq!(string(&mut rest), meta);
        assert!(rest == &cwasm[..]);

        let hit = open(&cache, &key(1), &token("tok")).await.expect("a hit");
        assert!(!hit.found_bad.get());
        assert!(
            open(&cache, &key(2), &token("tok")).await.is_none(),
            "a miss"
        );
    }

    /// An entry laid out as `store` lays one out.
    fn laid_out(meta: &[u8], cwasm: &[u8]) -> Vec<u8> {
        let mut entry = front(&[9; 32], meta.len());
        entry.extend_from_slice(meta);
        entry.extend_from_slice(cwasm);
        entry
    }

    /// The largest entry the execute hop's bounds allow, sealed, fits what the
    /// storage leg carries — its front as `store` writes it — and a first read
    /// holds that front, as `Front::read` needs.
    #[test]
    fn the_largest_entry_fits_the_storage_leg() {
        let front = front(&[0; 32], MAX_BUNDLE_META_BYTES as usize).len();
        let entry = front as u64 + MAX_BUNDLE_META_BYTES + MAX_CWASM_BYTES;
        assert!(
            enclavid_crypto::sealed_stream::sealed_len(entry) <= storage_rpc::MAX_CACHE_BLOB_BYTES
        );
        assert!(front <= FIRST_READ);
    }

    /// An entry comes apart into its metadata and its cwasm in pieces of any
    /// size, its metadata inside the first read or running past it.
    #[tokio::test]
    async fn an_entry_comes_apart_into_its_metadata_and_its_cwasm() {
        for meta_len in [0, 12, FIRST_READ - 60, FIRST_READ, 3 * FIRST_READ + 5] {
            let meta = cwasm(meta_len);
            let wasm: Vec<u8> = cwasm(200_000).into_iter().rev().collect();
            let entry = laid_out(&meta, &wasm);
            for piece in [7, 4096, 100_003] {
                let (got, front, rest) = split(pieces(&entry, piece), entry.len() as u64)
                    .await
                    .unwrap();
                assert!(got == meta, "{meta_len} in pieces of {piece}");
                assert_eq!(front.cwasm_sha256, [9; 32]);
                assert_eq!(front.cwasm_len, wasm.len() as u64);
                assert!(
                    read(rest).await.unwrap() == wasm,
                    "{meta_len} in pieces of {piece}"
                );
            }
        }
    }

    /// An entry not laid out as one — its first item not a byte string, a
    /// digest of another length, a metadata running past the entry — is a miss
    /// before the worker is called.
    #[tokio::test]
    async fn an_entry_not_laid_out_as_one_is_a_miss() {
        let cache = CacheStore::new(Arc::new(Blobs::default()), &[3; 32]);
        let mut not_a_string = Vec::new();
        ciborium::into_writer(&5u64, &mut not_a_string).unwrap();
        not_a_string.extend(laid_out(b"meta", b"cwasm"));
        let mut short_digest = string_head(31);
        short_digest.extend_from_slice(&[9; 31]);
        short_digest.extend(string_head(4));
        short_digest.extend_from_slice(b"meta");
        let mut meta_past_the_end = string_head(32);
        meta_past_the_end.extend_from_slice(&[9; 32]);
        meta_past_the_end.extend(string_head(1000));
        meta_past_the_end.extend_from_slice(b"meta");
        let id = cache_id(&key(1), &token("tok"));
        for entry in [not_a_string, short_digest, meta_past_the_end] {
            cache
                .store(&id, entry.len() as u64, pieces(&entry, 7))
                .await
                .unwrap();
            assert!(open(&cache, &key(1), &token("tok")).await.is_none());
        }
    }

    /// A cwasm that stops part-way is not kept, and leaves no entry to hit.
    #[tokio::test]
    async fn a_cwasm_that_stops_part_way_is_not_stored() {
        let cache = CacheStore::new(Arc::new(Blobs::default()), &[3; 32]);
        let mut stored = entry(b"the metadata", &cwasm(50_000));
        stored.cwasm = futures::stream::iter([Ok(Bytes::from(cwasm(10_000))), Err(())]).boxed();
        store(&cache, &key(1), &token("tok"), stored).await;
        assert!(open(&cache, &key(1), &token("tok")).await.is_none());
    }

    /// An entry removed is a miss after.
    #[tokio::test]
    async fn a_removed_entry_is_a_miss() {
        let cache = CacheStore::new(Arc::new(Blobs::default()), &[3; 32]);
        store(&cache, &key(1), &token("tok"), entry(b"m", &cwasm(1000))).await;
        assert!(open(&cache, &key(1), &token("tok")).await.is_some());
        remove(&cache, &key(1), &token("tok")).await;
        assert!(open(&cache, &key(1), &token("tok")).await.is_none());
    }
}
