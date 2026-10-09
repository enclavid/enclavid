//! L2 cwasm-cache: best-effort store / open of a compiled bundle.
//!
//! This is the fleet's DURABLE cache tier and the orchestrator's ONLY compiled
//! artifact store — [`hatch_client::CacheStore`], sealed under `tee_seal_key`,
//! over the storage-CVM backend api dials at boot. It survives a TEE restart.
//! There is no api-side in-RAM component cache; the sole in-memory L1 lives on
//! the execution-worker, which on a miss says so (`RunOutcome::CacheMiss`) and
//! lets api open one from here. A compiled bundle is a pure function of the
//! pinned artifacts, so a cold compile stores it once and every later boot or
//! worker miss reloads it without re-pulling or re-compiling.
//!
//! ## What an entry holds
//!
//! In this order: a header — the metadata's length, the cwasm's length and its
//! SHA-256 — then the metadata as the execute hop streams it, then the cwasm. So
//! a hit reads the header and the metadata, both small, and names the cwasm to
//! the worker before a byte of it is read; the cwasm then goes from the cache to
//! the worker a piece at a time, and api never holds it whole.
//!
//! ## Compatibility / invalidation — guards
//!
//! A stale on-disk bundle after a code update must never load wrong:
//!   1. `compat_token` + [`CACHE_FORMAT_VERSION`] folded into `cache_id` — the
//!      token is the execution-worker's cwasm ABI id (wasmtime version + config +
//!      target), so a fleet runtime bump gives the new worker a new key ⇒ a MISS
//!      (recompile) instead of a stale, incompatible cwasm; a change to the entry
//!      or to the metadata's layout does the same via the format epoch. Old blobs
//!      are never addressed by the new binary/runtime.
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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use futures::stream::BoxStream;
use futures::{StreamExt, TryStreamExt};

use enclavid_crypto::sealed_stream::sealed_len;
use engine_rpc::{
    BundleSource, CompatToken, CompositionKey, MAX_BUNDLE_META_BYTES, MAX_CWASM_BYTES,
};
use hatch_client::{BlobPieces, BridgeError, CacheStore};

/// Bumped whenever an entry's layout changes — its header, or the metadata's
/// encoding (a field of `BundleMeta` added / removed / retyped, or a nested serde
/// type's shape changes). A bump re-partitions the cache: old entries get a
/// different `cache_id` and are never read (guard 1).
const CACHE_FORMAT_VERSION: u32 = 2;

/// An entry's header: the metadata's length, the cwasm's length, the cwasm's
/// SHA-256.
const ENTRY_HEADER_BYTES: usize = 8 + 8 + 32;

// The largest entry the execute hop's bounds allow, sealed, fits what the
// storage leg carries.
const _: () = assert!(
    sealed_len(ENTRY_HEADER_BYTES as u64 + MAX_BUNDLE_META_BYTES + MAX_CWASM_BYTES)
        <= storage_rpc::MAX_CACHE_BLOB_BYTES
);

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

/// What an entry is made of: the metadata, encoded as the execute hop streams
/// it, and the cwasm — its length, its digest, and its pieces as they come.
pub struct Entry<'a> {
    pub meta: &'a [u8],
    pub cwasm_len: u64,
    pub cwasm_sha256: [u8; 32],
    pub cwasm: BoxStream<'static, Result<Bytes, ()>>,
}

/// Store `entry` to L2 under `(composition_key, compat_token)`, its cwasm
/// passing through as it comes. Best-effort: a failure is logged and swallowed;
/// a broken cache never breaks a session. A cwasm that fails part-way, or is not
/// the length it was named, is not kept.
pub async fn store(
    cache: &CacheStore,
    composition_key: &CompositionKey,
    compat_token: &CompatToken,
    entry: Entry<'_>,
) {
    let mut header = Vec::with_capacity(ENTRY_HEADER_BYTES);
    header.extend_from_slice(&(entry.meta.len() as u64).to_be_bytes());
    header.extend_from_slice(&entry.cwasm_len.to_be_bytes());
    header.extend_from_slice(&entry.cwasm_sha256);
    let length = (ENTRY_HEADER_BYTES + entry.meta.len()) as u64 + entry.cwasm_len;
    let pieces = futures::stream::iter([
        Ok(Bytes::from(header)),
        Ok(Bytes::copy_from_slice(entry.meta)),
    ])
    .chain(
        entry
            .cwasm
            .map_err(|()| BridgeError::Transport("the cwasm stopped part-way; not stored".into())),
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
/// hold what its header said — not because the leg under it failed. An entry
/// found bad stays bad, so it is dropped rather than read again.
pub struct FoundBad(Arc<AtomicBool>);

impl FoundBad {
    pub fn get(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Open the L2 entry for `(composition_key, compat_token)`. Returns `None` on a
/// miss, a transport failure, or an entry whose header or metadata does not
/// open — all before the worker is called, so the caller takes the cold path
/// with nothing sent.
pub async fn open(
    cache: &CacheStore,
    composition_key: &CompositionKey,
    compat_token: &CompatToken,
) -> Option<Hit> {
    let (length, mut pieces) = match cache.load(&cache_id(composition_key, compat_token)).await {
        Ok(Some(entry)) => entry,
        Ok(None) => return None,
        Err(e) => {
            safe_logger::debug!("cwasm_cache: L2 load transport error (cold path): {e}");
            return None;
        }
    };
    let opened = async {
        let mut rest = Bytes::new();
        let header = take(&mut pieces, &mut rest, ENTRY_HEADER_BYTES).await?;
        let meta_len = u64::from_be_bytes(header[0..8].try_into().expect("8 bytes"));
        let cwasm_len = u64::from_be_bytes(header[8..16].try_into().expect("8 bytes"));
        let cwasm_sha256: [u8; 32] = header[16..48].try_into().expect("32 bytes");
        if meta_len > MAX_BUNDLE_META_BYTES
            || cwasm_len > MAX_CWASM_BYTES
            || ENTRY_HEADER_BYTES as u64 + meta_len + cwasm_len != length
        {
            return Err(BridgeError::Codec(
                "an L2 entry whose header does not fit it".into(),
            ));
        }
        let meta = take(&mut pieces, &mut rest, meta_len as usize).await?;
        Ok((meta, cwasm_len, cwasm_sha256, rest))
    };
    let (meta, cwasm_len, cwasm_sha256, rest) = match opened.await {
        Ok(opened) => opened,
        Err(e) => {
            safe_logger::debug!("cwasm_cache: L2 entry did not open (cold path): {e}");
            return None;
        }
    };
    let bad = Arc::new(AtomicBool::new(false));
    let flag = bad.clone();
    let cwasm = futures::stream::iter([Ok(rest)])
        .chain(pieces)
        .try_filter(|piece| std::future::ready(!piece.is_empty()))
        .inspect_err(move |e| {
            if matches!(e, BridgeError::Crypto(_) | BridgeError::Codec(_)) {
                flag.store(true, Ordering::Relaxed);
            }
        });
    let source = BundleSource::streamed(cwasm_len, cwasm_sha256, meta, cwasm)?;
    Some(Hit {
        source,
        found_bad: FoundBad(bad),
    })
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
async fn take(pieces: &mut BlobPieces, rest: &mut Bytes, n: usize) -> Result<Vec<u8>, BridgeError> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        if rest.is_empty() {
            *rest = pieces.next().await.ok_or_else(|| {
                BridgeError::Codec("an L2 entry shorter than its header".into())
            })??;
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
    struct Blobs(std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>);

    #[async_trait::async_trait]
    impl hatch_client::CacheBackend for Blobs {
        async fn store(
            &self,
            name: &str,
            length: u64,
            pieces: BlobPieces,
        ) -> Result<(), BridgeError> {
            let blob = read(pieces).await?;
            assert_eq!(blob.len() as u64, length);
            self.0.lock().unwrap().insert(name.to_string(), blob);
            Ok(())
        }

        async fn load(&self, name: &str) -> Result<Option<(u64, BlobPieces)>, BridgeError> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .get(name)
                .map(|blob| (blob.len() as u64, pieces(blob, 4096))))
        }

        async fn remove(&self, name: &str) -> Result<(), BridgeError> {
            self.0.lock().unwrap().remove(name);
            Ok(())
        }
    }

    async fn read(pieces: BlobPieces) -> Result<Vec<u8>, BridgeError> {
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

    /// An entry of `meta` and `cwasm`, the cwasm passing through in pieces.
    fn entry<'a>(meta: &'a [u8], cwasm: &[u8]) -> Entry<'a> {
        Entry {
            meta,
            cwasm_len: cwasm.len() as u64,
            cwasm_sha256: fleet_stream::BlobHeader::<MAX_CWASM_BYTES>::of(cwasm)
                .unwrap()
                .sha256(),
            cwasm: pieces(cwasm, 10_000).map_err(|_| ()).boxed(),
        }
    }

    /// What `store` writes is the header, the metadata, then the cwasm — and
    /// `open` takes it as such, sending nothing back as bad.
    #[tokio::test]
    async fn an_entry_holds_its_header_its_metadata_then_its_cwasm() {
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
        let meta_len = meta.len();
        assert_eq!(entry[0..8], (meta_len as u64).to_be_bytes());
        assert_eq!(entry[8..16], 300_000u64.to_be_bytes());
        assert_eq!(entry[16..48], sha256);
        assert_eq!(entry[48..48 + meta_len], meta[..]);
        assert!(entry[48 + meta_len..] == cwasm[..]);

        let hit = open(&cache, &key(1), &token("tok")).await.expect("a hit");
        assert!(!hit.found_bad.get());
        assert!(
            open(&cache, &key(2), &token("tok")).await.is_none(),
            "a miss"
        );
    }

    /// An entry whose header does not fit what it holds is a miss before the
    /// worker is called.
    #[tokio::test]
    async fn an_entry_whose_header_does_not_fit_it_is_a_miss() {
        let cache = CacheStore::new(Arc::new(Blobs::default()), &[3; 32]);
        let mut entry = Vec::new();
        entry.extend_from_slice(&5u64.to_be_bytes());
        entry.extend_from_slice(&5u64.to_be_bytes());
        entry.extend_from_slice(&[0; 32]);
        entry.extend_from_slice(b"meta.");
        let id = cache_id(&key(1), &token("tok"));
        cache
            .store(&id, entry.len() as u64, pieces(&entry, 7))
            .await
            .unwrap();
        assert!(open(&cache, &key(1), &token("tok")).await.is_none());
    }

    /// A cwasm that stops part-way is not kept, and leaves no entry to hit.
    #[tokio::test]
    async fn a_cwasm_that_stops_part_way_is_not_stored() {
        let cache = CacheStore::new(Arc::new(Blobs::default()), &[3; 32]);
        let meta = b"m".to_vec();
        let mut stored = entry(&meta, &cwasm(50_000));
        stored.cwasm = futures::stream::iter([Ok(Bytes::from(cwasm(10_000))), Err(())]).boxed();
        store(&cache, &key(1), &token("tok"), stored).await;
        assert!(open(&cache, &key(1), &token("tok")).await.is_none());
    }
}
