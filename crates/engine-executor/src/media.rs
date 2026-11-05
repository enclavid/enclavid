//! The host-owned `enclavid:host/media` resources: `photo` and `video`. Their
//! pictures, which a decode in a process of its own gives, are
//! [`crate::image`]'s.
//!
//! Each is one stored capture — a photo's JPEG, a video's WebM — held the
//! same way and told apart by its type alone. The runtime mints a handle per
//! capture when it builds `event::media` from the applicant's `/input` bytes
//! (see [`runner::convert::event_to_wit`]); the policy receives one capture per
//! step of the spec, forwards it to a verification plugin (fused into the same
//! store), which pulls the bytes via `bytes`. The bytes therefore enter a
//! component's linear memory only at the point of use — never the policy's,
//! which is a pure router.
//!
//! Each capture also carries its own `media-hash` (the 32-byte BLAKE3 of its
//! bytes). The policy stashes the hashes it wants in the sealed `state`, and
//! rehydrates a capture in a later round through its type's constructor —
//! which returns a COLD handle (no host IO). The sealed bytes are pulled
//! LAZILY from the injected [`MediaStore`](crate::media_store::MediaStore) on
//! the first `bytes()` and memoized, so a handle the policy makes but never
//! reads costs nothing. Live handles are meaningless across rounds (dropped
//! with the Store); only the value `media-hash` survives.
//!
//! Data-minimization tradeoff: the runtime stores EVERY capture, AEAD-sealed,
//! host-side for the session lifetime (the api's `MediaStore` impl seals each
//! under the double-AEAD layers and co-commits it with the reducer state). This
//! is more retained data than the old process-and-drop model (frames lived in
//! TEE memory for one round), and is the deliberate cost of reloadable media.
//! Under host-alone compromise the captures stay unreadable (both seal keys are
//! TEE-only); they're purged on `/reset` and, once it lands, session TTL.

use std::marker::PhantomData;
use std::sync::Arc;

use wasmtime::component::Resource;

use enclavid_media::protocol::Kind;

use crate::enclavid::host::media::{Frame, HostPhoto, HostVideo, MediaHash};
use crate::image::{Capture, Decoded, ImageRep};
use crate::state::HostState;

// The media interface carries no functions of its own beside its resources'.
impl crate::enclavid::host::media::Host for HostState {}

/// The kind of a `photo` handle's capture.
pub enum Photo {}
/// The kind of a `video` handle's capture.
pub enum Video {}

/// Backing rep for a `photo` handle.
pub type PhotoRep = Held<Photo>;
/// Backing rep for a `video` handle.
pub type VideoRep = Held<Video>;

/// Backing rep for a capture handle: its content hash plus, once materialized,
/// the bytes. Owned by the run's
/// [`ResourceTable`](wasmtime::component::ResourceTable); a component only ever
/// holds an unforgeable handle to it. `K` is the capture's kind, so a photo's
/// rep and a video's are two types, as their resources are: one could not be
/// served as the other.
///
/// `bytes` is `Some` for a fresh capture (the `/input` bytes are in hand at
/// ingest) and `None` for one REHYDRATED through its constructor — the latter
/// is a COLD handle whose bytes are pulled lazily on the first `bytes()` call
/// and memoized back here. So constructing a capture from a hash does no host
/// IO; the load (and its gate / trap) happens only if the bytes are actually
/// read. When present, the `Arc` is shared with the store's cache / the
/// persist-staging path, so a capture isn't copied host-side.
pub struct Held<K> {
    pub bytes: Option<Arc<Vec<u8>>>,
    pub content_hash: [u8; 32],
    kind: PhantomData<K>,
}

impl<K> Held<K> {
    /// A fresh capture, its bytes in hand.
    pub fn warm(bytes: Vec<u8>) -> Self {
        Self {
            content_hash: blake3::hash(&bytes).into(),
            bytes: Some(Arc::new(bytes)),
            kind: PhantomData,
        }
    }
}

impl HostState {
    /// A capture's bytes, host-side. For a cold (rehydrated) one this is where
    /// the LAZY pull happens: hit the injected store and memoize the `Arc` back
    /// into the rep. A store miss TRAPS — a cold handle whose hash resolves to
    /// nothing is a fabricated / never-stored hash, never a legitimate outcome
    /// (see the covert rationale in `media_store`).
    async fn held<K: Send + 'static>(
        &mut self,
        handle: &Resource<Held<K>>,
    ) -> wasmtime::Result<Arc<Vec<u8>>> {
        // Fast path: already materialized (ingest, or a prior pull).
        if let Some(bytes) = &self.table.get(handle)?.bytes {
            return Ok(bytes.clone());
        }
        // Cold: pull now (this is the lazy load) and memoize. The hash is
        // `Copy`, so the read borrow ends before the `.await`; `media_store` is
        // cloned out likewise.
        let hash = self.table.get(handle)?.content_hash;
        let store = self.media_store.clone();
        let Some(bytes) = store.load(&hash).await? else {
            return Err(wasmtime::Error::msg(
                "media bytes: no capture for this hash in the session store \
                 (fabricated or never-stored hash)",
            ));
        };
        self.table.get_mut(handle)?.bytes = Some(bytes.clone());
        Ok(bytes)
    }

    /// Materialize a capture's bytes into the caller's linear memory. The one
    /// unavoidable copy (host→wasm) is here, not at handle construction.
    async fn held_bytes<K: Send + 'static>(
        &mut self,
        handle: &Resource<Held<K>>,
    ) -> wasmtime::Result<Vec<u8>> {
        Ok(self.held(handle).await?.as_ref().clone())
    }

    /// Mint a COLD handle for a stored content hash — a constructor. No host IO
    /// here: the bytes are pulled lazily on the first `bytes()` (which also runs
    /// the captured-hash gate and traps on a fabricated hash). Only a malformed
    /// / wrong-length hash is rejected up front, since it can't be a real
    /// 32-byte content hash. Own-session only — the injected store keys
    /// captures under the session and AEAD-binds them to it, so a hash from
    /// another session (or a fabricated one) misses at `bytes()`.
    fn held_cold<K: Send + 'static>(
        &mut self,
        hash: MediaHash,
    ) -> wasmtime::Result<Resource<Held<K>>> {
        // Decode the hex token back to the 32-byte content hash; malformed hex /
        // wrong length can't be a real hash → trap (a fabricated hash is never a
        // legitimate outcome). Everything downstream is `[u8;32]`.
        let Ok(decoded) = blake3::Hash::from_hex(hash.as_bytes()) else {
            return Err(wasmtime::Error::msg(
                "media constructor: hash is not a 64-char hex content hash",
            ));
        };
        Ok(self.table.push(Held {
            bytes: None,
            content_hash: *decoded.as_bytes(),
            kind: PhantomData,
        })?)
    }

    /// Hex-encode a capture's 32-byte content hash into the opaque string token
    /// the policy stashes in `state`. String (not raw bytes) for cross-language
    /// ergonomics; internally the hash stays `[u8;32]`, hex only at this seam.
    fn held_hash<K: Send + 'static>(
        &mut self,
        handle: &Resource<Held<K>>,
    ) -> wasmtime::Result<MediaHash> {
        Ok(
            blake3::Hash::from_bytes(self.table.get(handle)?.content_hash)
                .to_hex()
                .to_string(),
        )
    }

    /// The capture `handle` holds, decoded as a capture of `kind`, and what
    /// the round's open of it found, the first time any handle to it asked —
    /// the one time its bytes are pulled for it.
    async fn held_decoded<K: Send + 'static>(
        &mut self,
        handle: &Resource<Held<K>>,
        kind: Kind,
    ) -> wasmtime::Result<(Capture, Decoded)> {
        let capture = (kind, self.table.get(handle)?.content_hash);
        if let Some(decoded) = self.decodes.get(&capture) {
            return Ok((capture, decoded));
        }
        let bytes = self.held(handle).await?;
        Ok((capture, crate::image::open(self, capture, bytes).await?))
    }
}

impl HostPhoto for HostState {
    async fn new(&mut self, hash: MediaHash) -> wasmtime::Result<Resource<PhotoRep>> {
        self.held_cold(hash)
    }

    async fn bytes(&mut self, self_: Resource<PhotoRep>) -> wasmtime::Result<Vec<u8>> {
        self.held_bytes(&self_).await
    }

    async fn hash(&mut self, self_: Resource<PhotoRep>) -> wasmtime::Result<MediaHash> {
        self.held_hash(&self_)
    }

    async fn image(
        &mut self,
        self_: Resource<PhotoRep>,
    ) -> wasmtime::Result<Option<Resource<ImageRep>>> {
        Ok(match self.held_decoded(&self_, Kind::Photo).await? {
            (capture, Decoded::Photo(size)) => {
                Some(self.table.push(ImageRep::photo(capture, size))?)
            }
            _ => None,
        })
    }

    async fn drop(&mut self, rep: Resource<PhotoRep>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl HostVideo for HostState {
    async fn new(&mut self, hash: MediaHash) -> wasmtime::Result<Resource<VideoRep>> {
        self.held_cold(hash)
    }

    async fn bytes(&mut self, self_: Resource<VideoRep>) -> wasmtime::Result<Vec<u8>> {
        self.held_bytes(&self_).await
    }

    async fn hash(&mut self, self_: Resource<VideoRep>) -> wasmtime::Result<MediaHash> {
        self.held_hash(&self_)
    }

    async fn frames(
        &mut self,
        self_: Resource<VideoRep>,
        first: u32,
        last: u32,
    ) -> wasmtime::Result<Vec<Frame>> {
        let (capture, Decoded::Video(size, listed)) =
            self.held_decoded(&self_, Kind::Video).await?
        else {
            return Ok(Vec::new());
        };
        let end = listed.len().min((last as usize).saturating_add(1));
        listed
            .get(first as usize..end)
            .unwrap_or_default()
            .iter()
            .zip(first..)
            .map(|(info, index)| {
                Ok(Frame {
                    index,
                    timestamp_ms: info.timestamp_ms,
                    keyframe: info.keyframe,
                    image: self.table.push(ImageRep::frame(capture, index, size))?,
                })
            })
            .collect()
    }

    async fn drop(&mut self, rep: Resource<VideoRep>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}
