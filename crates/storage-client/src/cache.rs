//! L2 compiled-artifact (`cwasm`) cache client.
//!
//! Talks to the storage-CVM's cache through the storage leg, at [`Storage`].
//! Unlike the session store, a cache entry is NOT session- or applicant-scoped: it is a
//! compiled composition shared across every session (and restart) of THIS TEE
//! instance, so it is sealed under a **single** TEE-only key (an HKDF subkey of
//! `tee_seal_key`), never the double-AEAD / applicant-token layering that would
//! pin it to one session.
//!
//! Two HKDF subkeys, domain-separated from each other and from the AEAD
//! usage of `tee_seal_key`:
//!   * **seal key** — seals the bundle; the host stores opaque ciphertext it
//!     cannot read.
//!   * **filename key** — names the blob `HKDF(filename_key, cache_id)`, an
//!     identity-hiding name so the host can't tie a blob to a composition by
//!     its name.
//!
//! `cache_id` is an OPAQUE string the api layer owns (composition hash +
//! cache-format epoch). This client never parses it — it is the AAD and
//! the filename-label input, so ANY change to it (new composition, bumped
//! format version) yields a different blob name AND a different AAD,
//! cleanly partitioning incompatible entries.
//!
//! A blob is sealed and opened as a stream
//! ([`enclavid_crypto::sealed_stream`]), a segment at a time, so neither
//! direction holds a bundle whole. Reading is **best-effort**: an absent blob,
//! or one whose length no sealed stream has, is a MISS (`Ok(None)`). One that
//! does not open — foreign, stale-epoch, host tamper — is found out as it is
//! read: its pieces end in an error at the first segment that fails, or at an
//! end it was not sealed to have, and nothing after that is handed on. The
//! compile is always re-derivable from the cold path.

use std::sync::Arc;

use bytes::Bytes;
use futures::stream::BoxStream;
use futures::{StreamExt, TryStreamExt};
use secrecy::{ExposeSecret, SecretBox};

use enclavid_crypto::derive_key;
use enclavid_crypto::sealed_stream::{self, Opener, SEGMENT_BYTES, Sealer};
use fleet_stream::{Incoming, StreamLen};
use storage_rpc::{BlobName, BlobStream, CACHE_STREAM_DEADLINE, CACHE_STREAM_IDLE, CacheBlob};

use crate::boundary::Storage;
use crate::error::StoreError;
use crate::link::{Link, storage};
use enclavid_boundary::{AuthN, Exposed};

/// A blob's pieces as a store takes and gives them, in order. An error ends the
/// blob, and what came before it is not the blob.
pub type BlobPieces = BoxStream<'static, Result<Bytes, StoreError>>;

/// HKDF info label for the seal subkey.
const SEAL_INFO: &[u8] = b"enclavid.cwasm-cache.seal.v1";
/// HKDF info label for the blob-name subkey.
const FILENAME_INFO: &[u8] = b"enclavid.cwasm-cache.filename.v1";

/// The two derived subkeys plus the labelling logic — no transport, so it is
/// unit-testable in isolation. Each subkey is a `SecretBox` (zeroize-on-drop,
/// Debug-redacted); not `Clone`/`Copy` on purpose, so [`CacheStore`] shares one
/// instance behind an `Arc`.
struct CacheKeys {
    seal_key: SecretBox<[u8; 32]>,
    filename_key: SecretBox<[u8; 32]>,
}

impl CacheKeys {
    fn from_master(tee_seal_key: &[u8; 32]) -> Self {
        Self {
            seal_key: SecretBox::new(Box::new(derive_key(tee_seal_key, SEAL_INFO))),
            filename_key: SecretBox::new(Box::new(derive_key(tee_seal_key, FILENAME_INFO))),
        }
    }

    /// Identity-hiding blob name for `cache_id`: `HKDF(filename_key,
    /// cache_id)`. A keyed PRF, so whoever reads it sees only pseudo-random
    /// bytes it cannot invert to the composition — the work that lets it leave.
    fn blob_name(&self, cache_id: &str) -> Exposed<BlobName, (), Storage> {
        let Ok(name) =
            Storage::expose_builder::<BlobName, _>(cache_id).vouch_with(AuthN::Verified, |id| {
                Ok::<_, std::convert::Infallible>(BlobName(derive_key(
                    self.filename_key.expose_secret(),
                    id.as_bytes(),
                )))
            });
        name.build()
    }
}

/// L2 cache client. Cheap to clone (the link + keys are Arc-shared).
#[derive(Clone)]
pub struct CacheStore {
    /// The storage leg, at [`Storage`]. All crypto (seal/open +
    /// identity-hiding `blob_name`) stays HERE; the leg moves opaque sealed
    /// blobs by the already-derived name.
    link: Arc<dyn Link>,
    /// One shared `CacheKeys` behind an `Arc` — `SecretBox` is not `Clone`, so
    /// cloning the store shares the keys rather than copying them.
    keys: Arc<CacheKeys>,
}

impl CacheStore {
    pub fn new(link: Arc<dyn Link>, tee_seal_key: &[u8; 32]) -> Self {
        Self {
            link,
            keys: Arc::new(CacheKeys::from_master(tee_seal_key)),
        }
    }

    /// Seal the `length` bytes `plain` yields and store them under `cache_id`,
    /// in place of any blob before (content-addressed: same bytes, or a fresh
    /// compile replacing a stale one). `plain` yielding more or fewer bytes than
    /// `length` fails the store, and nothing is kept.
    pub async fn store(
        &self,
        cache_id: &str,
        length: u64,
        plain: BlobPieces,
    ) -> Result<(), StoreError> {
        let (sealer, header) = Sealer::new(self.keys.seal_key.expose_secret(), cache_id.as_bytes());
        // [`Storage`] answers AuthZ and Covert for every blob stream; the seal
        // answers AuthN and builds the stream — under a TEE-only HKDF subkey of
        // tee_seal_key, so the host stores opaque ciphertext it cannot read.
        // A piece that fails abandons the blob, and the store keeps nothing of it;
        // why it failed stays here.
        let stream = Storage::expose_builder::<BlobStream, _>(plain)
            .vouch_with(AuthN::Verified, |plain| {
                let sealed_len =
                    StreamLen::new(sealed_stream::sealed_len(length)).ok_or_else(|| {
                        StoreError::Transport(
                            "a blob past what the storage leg carries; not stored".into(),
                        )
                    })?;
                Ok::<_, StoreError>(BlobStream {
                    length: sealed_len,
                    pieces: seal(header, sealer, length, plain).map_err(|_| ()).boxed(),
                })
            })?
            .build();
        storage(self.link.as_ref())?
            .store(self.keys.blob_name(cache_id), stream)
            .await?;
        Ok(())
    }

    /// The blob for `cache_id`, opened: its plaintext length and its plaintext
    /// pieces. `Ok(None)` = miss; `Err` only on genuine transport failure. A
    /// blob that does not open ends its pieces in an error (see the module doc),
    /// and so does one whose stream does not come up.
    pub async fn load(&self, cache_id: &str) -> Result<Option<(u64, BlobPieces)>, StoreError> {
        let loaded = storage(self.link.as_ref())?
            .load(self.keys.blob_name(cache_id))
            .await?;
        let opener = Opener::new(self.keys.seal_key.expose_secret(), cache_id.as_bytes());
        // AuthN by the open itself: every piece is handed on only once its
        // segment opened under the TEE-only cache seal key, and a stream cut
        // short, reordered or spliced ends in an error, so only bytes this TEE
        // sealed come out. A miss opens to a miss, and so does a length no sealed
        // stream has — it cannot open, known before a byte is read.
        loaded
            .trust_with(AuthN::Verified, |blob| {
                Ok::<_, StoreError>(blob.and_then(|CacheBlob { length, body }| {
                    let sealed_len = length.get();
                    let plain_len = sealed_stream::plain_len(sealed_len)?;
                    let sealed =
                        futures::stream::once(Incoming::open(body, sealed_len, CACHE_STREAM_IDLE))
                            .map_ok(|incoming| incoming.into_pieces(CACHE_STREAM_DEADLINE, None))
                            .try_flatten()
                            .map_err(|e| StoreError::Transport(format!("storage-cvm: {e}")))
                            .boxed();
                    Some((plain_len, open(opener, plain_len, sealed)))
                }))
            })
            .map(|opened| opened.into_inner())
    }

    /// Drop the blob for `cache_id`, if there is one.
    pub async fn remove(&self, cache_id: &str) -> Result<(), StoreError> {
        storage(self.link.as_ref())?
            .remove(self.keys.blob_name(cache_id))
            .await?;
        Ok(())
    }
}

/// What [`seal`] and [`open`] carry from one piece to the next: the piece being
/// worked through, what is left of the length, and the sealer or opener until
/// the end has been sealed or opened.
struct Step<S> {
    crypt: Option<S>,
    from: BlobPieces,
    piece: Bytes,
    left: u64,
}

/// `header`, then `plain` sealed by `sealer`: one segment's worth of plaintext
/// at a time, so what each piece yields stays a segment or two however large
/// `plain`'s pieces are.
fn seal(header: Vec<u8>, sealer: Sealer, length: u64, plain: BlobPieces) -> BlobPieces {
    let body = futures::stream::try_unfold(
        Step {
            crypt: Some(sealer),
            from: plain,
            piece: Bytes::new(),
            left: length,
        },
        |mut s| async move {
            loop {
                let Some(sealer) = s.crypt.as_mut() else {
                    return Ok(None);
                };
                if s.piece.is_empty() {
                    match s.from.next().await {
                        Some(piece) => {
                            s.piece = piece?;
                            s.left = s
                                .left
                                .checked_sub(s.piece.len() as u64)
                                .ok_or_else(|| uneven("longer"))?;
                            continue;
                        }
                        None if s.left != 0 => return Err(uneven("shorter")),
                        None => {
                            let last = s.crypt.take().expect("checked above").finish()?;
                            return Ok(Some((Bytes::from(last), s)));
                        }
                    }
                }
                let part = s.piece.split_to(s.piece.len().min(SEGMENT_BYTES));
                let sealed = sealer.push(&part)?;
                if !sealed.is_empty() {
                    return Ok(Some((Bytes::from(sealed), s)));
                }
            }
        },
    );
    futures::stream::once(async { Ok(Bytes::from(header)) })
        .chain(body)
        .boxed()
}

/// `sealed`, opened by `opener` a segment at a time, and held to `length`.
fn open(opener: Opener, length: u64, sealed: BlobPieces) -> BlobPieces {
    futures::stream::try_unfold(
        Step {
            crypt: Some(opener),
            from: sealed,
            piece: Bytes::new(),
            left: length,
        },
        |mut s| async move {
            loop {
                let Some(opener) = s.crypt.as_mut() else {
                    return Ok(None);
                };
                let plain = if s.piece.is_empty() {
                    match s.from.next().await {
                        Some(piece) => {
                            s.piece = piece?;
                            continue;
                        }
                        None => s.crypt.take().expect("checked above").finish()?,
                    }
                } else {
                    let part = s.piece.split_to(s.piece.len().min(SEGMENT_BYTES));
                    opener.push(&part)?
                };
                s.left = s
                    .left
                    .checked_sub(plain.len() as u64)
                    .ok_or_else(|| uneven("longer"))?;
                if s.crypt.is_none() && s.left != 0 {
                    return Err(uneven("shorter"));
                }
                if !plain.is_empty() {
                    return Ok(Some((Bytes::from(plain), s)));
                }
            }
        },
    )
    .boxed()
}

fn uneven(than: &str) -> StoreError {
    StoreError::Codec(format!("a cache blob {than} than its length"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::Disk;

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    /// `bytes` as pieces of `piece` bytes.
    fn pieces(bytes: &[u8], piece: usize) -> BlobPieces {
        let pieces: Vec<_> = bytes
            .chunks(piece)
            .map(|p| Ok(Bytes::copy_from_slice(p)))
            .collect();
        futures::stream::iter(pieces).boxed()
    }

    async fn read(pieces: BlobPieces) -> Result<Vec<u8>, StoreError> {
        pieces
            .try_fold(Vec::new(), |mut all, p| async move {
                all.extend_from_slice(&p);
                Ok(all)
            })
            .await
    }

    /// A store under the master `master`, on `disk`.
    async fn store_on(disk: &Arc<Disk>, master: u8) -> CacheStore {
        CacheStore::new(disk.connect().await, &[master; 32])
    }

    /// The name `store` keeps `cache_id`'s blob under.
    fn name(store: &CacheStore, cache_id: &str) -> BlobName {
        store.keys.blob_name(cache_id).into_inner()
    }

    #[test]
    fn blob_name_deterministic_and_scoped() {
        let k = CacheKeys::from_master(&[1u8; 32]);
        let name = |k: &CacheKeys, id| k.blob_name(id).into_inner();
        let a = name(&k, "comp-x.v1");
        // Deterministic (cross-session / cross-restart sharing depends on it).
        assert_eq!(a, name(&k, "comp-x.v1"));
        // A different composition or a bumped format epoch → different name.
        assert_ne!(a, name(&k, "comp-y.v1"));
        assert_ne!(a, name(&k, "comp-x.v2"));
        // A different instance master → different name (no cross-instance
        // name collision that could leak which composition is cached).
        assert_ne!(a, name(&CacheKeys::from_master(&[2u8; 32]), "comp-x.v1"));
    }

    #[test]
    fn seal_key_and_filename_key_are_independent() {
        // The public filename must not reveal the seal key: they are
        // separate HKDF labels off the master.
        let k = CacheKeys::from_master(&[5u8; 32]);
        assert_ne!(k.seal_key.expose_secret(), k.filename_key.expose_secret());
    }

    /// A bundle of several segments, given in pieces that line up with nothing,
    /// round-trips through seal → leg → open, and only ciphertext reaches the
    /// volume.
    #[tokio::test]
    async fn a_blob_seals_and_opens_over_the_leg() {
        let disk = Arc::new(Disk::default());
        let store = store_on(&disk, 7).await;
        let plain = pattern(3 * SEGMENT_BYTES + 11);
        store
            .store("comp.v1", plain.len() as u64, pieces(&plain, 100_003))
            .await
            .unwrap();

        let (len, opened) = store.load("comp.v1").await.unwrap().unwrap();
        assert_eq!(len, plain.len() as u64);
        assert!(read(opened).await.unwrap() == plain);

        let stored = disk.blobs.lock().unwrap()[&name(&store, "comp.v1")].clone();
        assert!(!stored.windows(64).any(|w| w == &plain[..64]));
        assert!(store.load("comp.v2").await.unwrap().is_none(), "a miss");
    }

    #[tokio::test]
    async fn an_empty_blob_round_trips() {
        let disk = Arc::new(Disk::default());
        let store = store_on(&disk, 7).await;
        store.store("comp.v1", 0, pieces(&[], 1)).await.unwrap();
        let (len, opened) = store.load("comp.v1").await.unwrap().unwrap();
        assert_eq!(len, 0);
        assert!(read(opened).await.unwrap().is_empty());
    }

    /// Pieces that do not add up to the declared length are refused, and the
    /// volume keeps nothing.
    #[tokio::test]
    async fn plaintext_off_its_length_is_not_stored() {
        let disk = Arc::new(Disk::default());
        let store = store_on(&disk, 7).await;
        let plain = pattern(5000);
        for declared in [4999u64, 5001] {
            assert!(
                store
                    .store("comp.v1", declared, pieces(&plain, 777))
                    .await
                    .is_err()
            );
        }
        assert!(disk.blobs.lock().unwrap().is_empty());
    }

    /// Another instance's key, another `cache_id` under the same name, or a
    /// byte the host flipped: the pieces end in an error, never in the bundle.
    #[tokio::test]
    async fn a_blob_that_does_not_open_ends_in_an_error() {
        let disk = Arc::new(Disk::default());
        let store = store_on(&disk, 7).await;
        let plain = pattern(2 * SEGMENT_BYTES + 3);
        store
            .store("comp.v1", plain.len() as u64, pieces(&plain, 4096))
            .await
            .unwrap();

        let ours = name(&store, "comp.v1");
        let blob = disk.blobs.lock().unwrap()[&ours].clone();

        // Another instance names it differently too; under its own name, its
        // key still does not open it.
        let foreign = store_on(&disk, 8).await;
        disk.blobs
            .lock()
            .unwrap()
            .insert(name(&foreign, "comp.v1"), blob.clone());
        let (_, opened) = foreign.load("comp.v1").await.unwrap().unwrap();
        assert!(read(opened).await.is_err());

        disk.blobs
            .lock()
            .unwrap()
            .insert(name(&store, "comp.v2"), blob.clone());
        let (_, relabelled) = store.load("comp.v2").await.unwrap().unwrap();
        assert!(read(relabelled).await.is_err());

        let mut flipped = blob;
        let at = flipped.len() - 5;
        flipped[at] ^= 1;
        disk.blobs.lock().unwrap().insert(ours, flipped);
        let (_, tampered) = store.load("comp.v1").await.unwrap().unwrap();
        assert!(read(tampered).await.is_err());
    }

    /// A blob cut to a length some sealed stream has opens to no bundle; cut to
    /// one none has, it is a miss before anything is read.
    #[tokio::test]
    async fn a_blob_cut_short_never_opens() {
        let disk = Arc::new(Disk::default());
        let store = store_on(&disk, 7).await;
        let plain = pattern(2 * SEGMENT_BYTES + 3);
        store
            .store("comp.v1", plain.len() as u64, pieces(&plain, 4096))
            .await
            .unwrap();
        let ours = name(&store, "comp.v1");
        let blob = disk.blobs.lock().unwrap()[&ours].clone();

        let at_a_segment = sealed_stream::sealed_len(2 * SEGMENT_BYTES as u64) as usize;
        disk.blobs
            .lock()
            .unwrap()
            .insert(ours, blob[..at_a_segment].to_vec());
        let (_, cut) = store.load("comp.v1").await.unwrap().unwrap();
        assert!(read(cut).await.is_err());

        disk.blobs.lock().unwrap().insert(ours, blob[..40].to_vec());
        assert!(store.load("comp.v1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_removed_blob_is_a_miss() {
        let disk = Arc::new(Disk::default());
        let store = store_on(&disk, 7).await;
        store.store("comp.v1", 3, pieces(b"abc", 3)).await.unwrap();
        store.remove("comp.v1").await.unwrap();
        assert!(store.load("comp.v1").await.unwrap().is_none());
    }
}
