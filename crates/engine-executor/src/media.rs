//! The host-owned `enclavid:host/types.blob` resource.
//!
//! A `blob` is one stored byte-blob — a captured JPEG frame today, an uploaded
//! document / PDF later; the host owns and hands them out identically. The
//! runtime mints a handle per captured frame when it builds `event::media` from
//! the applicant's `/input` bytes (see [`runner::convert::event_to_wit`]); the
//! policy receives a `clip` record bundling the handles, forwards one to a
//! verification plugin (fused into the same store), which pulls the pixels via
//! [`bytes`](HostBlob::bytes). The bytes therefore enter a component's linear
//! memory only at the point of use — never the policy's, which is a pure router.
//!
//! Each blob also carries its own `blob-ref` (the 32-byte BLAKE3 of its bytes).
//! The policy stashes the refs it wants in the sealed `state`, and rehydrates a
//! blob in a later round via [`from-blob-ref`](HostBlob::from_blob_ref) — which
//! returns a COLD handle (no host IO). The sealed bytes are pulled LAZILY from
//! the injected [`MediaStore`](crate::media_store::MediaStore) on the first
//! [`bytes()`](HostBlob::bytes) and memoized, so a handle the policy makes but
//! never reads costs nothing. Live handles are meaningless across rounds
//! (dropped with the Store); only the value `blob-ref` survives.
//!
//! Data-minimization tradeoff: the runtime stores EVERY captured frame,
//! AEAD-sealed, host-side for the session lifetime (the api's `MediaStore`
//! impl seals each blob under the double-AEAD layers and co-commits it with
//! the reducer state). This is more retained data than the old
//! process-and-drop model (frames lived in TEE memory for one round), and is
//! the deliberate cost of reloadable media. Under host-alone compromise the
//! blobs stay unreadable (both seal keys are TEE-only); they're purged on
//! `/reset` and, once it lands, session TTL.

use std::sync::Arc;

use wasmtime::component::Resource;

use crate::enclavid::host::types::BlobHash;
use crate::state::HostState;

/// Backing rep for a `blob` handle: its content hash plus, once materialized,
/// the bytes. Owned by the run's
/// [`ResourceTable`](wasmtime::component::ResourceTable); a component only ever
/// holds an unforgeable handle to it.
///
/// `bytes` is `Some` for a freshly-captured blob (the `/input` bytes are in hand
/// at ingest) and `None` for one REHYDRATED via the `blob` constructor — the
/// latter is a COLD handle whose bytes are pulled lazily on the first `bytes()`
/// call and memoized back here. So constructing a blob from a hash does no host
/// IO; the load (and its gate / trap) happens only if the bytes are actually
/// read. When present, the `Arc` is shared with the store's cache / the
/// persist-staging path, so a blob isn't copied host-side.
pub struct BlobRep {
    pub bytes: Option<Arc<Vec<u8>>>,
    pub content_hash: [u8; 32],
}

impl crate::enclavid::host::types::HostBlob for HostState {
    /// Materialize the bytes into the caller's linear memory. For a cold
    /// (rehydrated) blob this is where the LAZY pull happens: hit the injected
    /// store, memoize the `Arc` back into the rep, and copy out. A store miss
    /// TRAPS — a cold handle whose ref resolves to nothing is a fabricated /
    /// never-stored ref, never a legitimate outcome (see the covert rationale in
    /// `media_store`). The one unavoidable copy (host→wasm) is here, not at
    /// handle construction.
    async fn bytes(&mut self, self_: Resource<BlobRep>) -> wasmtime::Result<Vec<u8>> {
        // Fast path: already materialized (ingest, or a prior `bytes()`).
        if let Some(bytes) = &self.table.get(&self_)?.bytes {
            return Ok(bytes.as_ref().clone());
        }
        // Cold: pull now (this is the lazy load), memoize, copy out. The hash is
        // `Copy`, so the read borrow ends before the `.await`; `media_store` is
        // cloned out likewise.
        let hash = self.table.get(&self_)?.content_hash;
        let store = self.media_store.clone();
        let Some(bytes) = store.load(&hash).await? else {
            return Err(wasmtime::Error::msg(
                "blob::bytes: no blob for this ref in the session store \
                 (fabricated or never-stored ref)",
            ));
        };
        let out = bytes.as_ref().clone();
        self.table.get_mut(&self_)?.bytes = Some(bytes);
        Ok(out)
    }

    /// Mint a COLD blob handle for a stored content hash — the `blob`
    /// constructor. No host IO here: the bytes are pulled lazily on the first
    /// `bytes()` (which also runs the captured-hash gate and traps on a
    /// fabricated hash). Only a malformed / wrong-length hash is rejected up
    /// front, since it can't be a real 32-byte content hash. Own-session only —
    /// the injected store keys blobs under the session and AEAD-binds them to
    /// it, so a hash from another session (or a fabricated one) misses at
    /// `bytes()`.
    async fn new(&mut self, hash: BlobHash) -> wasmtime::Result<Resource<BlobRep>> {
        // Decode the hex token back to the 32-byte content hash; malformed hex /
        // wrong length can't be a real hash → trap (a fabricated hash is never a
        // legitimate outcome). Everything downstream is `[u8;32]`.
        let Ok(decoded) = blake3::Hash::from_hex(hash.as_bytes()) else {
            return Err(wasmtime::Error::msg(
                "blob constructor: hash is not a 64-char hex content hash",
            ));
        };
        Ok(self.table.push(BlobRep {
            bytes: None,
            content_hash: *decoded.as_bytes(),
        })?)
    }

    async fn hash(&mut self, self_: Resource<BlobRep>) -> wasmtime::Result<BlobHash> {
        // Hex-encode the 32-byte content hash into the opaque string token the
        // policy stashes in `state`. String (not raw bytes) for cross-language
        // ergonomics; internally the hash stays `[u8;32]`, hex only at this seam.
        Ok(blake3::Hash::from_bytes(self.table.get(&self_)?.content_hash)
            .to_hex()
            .to_string())
    }

    async fn drop(&mut self, rep: Resource<BlobRep>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}
