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
//! blob in a later round via [`from-blob-ref`](HostBlob::from_blob_ref), which
//! reads the sealed bytes back from the injected
//! [`MediaStore`](crate::media_store::MediaStore). Live handles are meaningless
//! across rounds (dropped with the Store); only the value `blob-ref` survives.
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

use crate::enclavid::host::types::{BlobRef, LoadError};
use crate::state::HostState;

/// Backing rep for a `blob` handle: one stored blob's bytes plus its content
/// ref. Owned by the run's
/// [`ResourceTable`](wasmtime::component::ResourceTable); a component only ever
/// holds an unforgeable handle to it. Bytes are `Arc`-shared with the
/// persist-staging path so a captured blob isn't copied to reach the seal.
pub struct BlobRep {
    pub bytes: Arc<Vec<u8>>,
    pub blob_ref: [u8; 32],
}

impl crate::enclavid::host::types::HostBlob for HostState {
    async fn bytes(&mut self, self_: Resource<BlobRep>) -> wasmtime::Result<Vec<u8>> {
        Ok(self.table.get(&self_)?.bytes.as_ref().clone())
    }

    async fn blob_ref(&mut self, self_: Resource<BlobRep>) -> wasmtime::Result<BlobRef> {
        Ok(BlobRef {
            hash: self.table.get(&self_)?.blob_ref.to_vec(),
        })
    }

    /// Rehydrate one stored frame by its ref. Own-session only — the injected
    /// store keys blobs under the session and AEAD-binds them to it, so a ref
    /// from another session (or a fabricated one) misses. A miss / wrong-length
    /// ref is a benign `not-found`; a transport failure traps (bubbles as the
    /// outer `Err`). The store `Arc` is cloned before the `.await` so the
    /// borrow of `self` is released before the `self.table.push`.
    async fn from_blob_ref(
        &mut self,
        r: BlobRef,
    ) -> wasmtime::Result<Result<Resource<BlobRep>, LoadError>> {
        let Ok(hash): Result<[u8; 32], _> = r.hash.try_into() else {
            return Ok(Err(LoadError::NotFound));
        };
        let store = self.media_store.clone();
        match store.load(&hash).await? {
            Some(bytes) => {
                let rep = BlobRep {
                    bytes: Arc::new(bytes),
                    blob_ref: hash,
                };
                Ok(Ok(self.table.push(rep)?))
            }
            None => Ok(Err(LoadError::NotFound)),
        }
    }

    async fn drop(&mut self, rep: Resource<BlobRep>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}
