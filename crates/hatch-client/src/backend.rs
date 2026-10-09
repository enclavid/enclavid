//! Transport seams under [`SessionStore`](crate::SessionStore) /
//! [`CacheStore`](crate::CacheStore). Each store owns ALL crypto (`build_op` /
//! per-field `decode` / `aead` seal-open, and — for the cache — the
//! identity-hiding `blob_name` derivation) plus the `Exposed`/`Untrusted`
//! boundary gate; the backend is a **dumb byte mover**.
//!
//! The concrete implementation is `SessionCvmBackend` / `CacheCvmBackend` (in
//! `api`) — remoc clients to the trusted storage-CVM over RA-TLS. It lives in
//! `api` (not here) so hatch-client stays remoc-free.
//!
//! The seam is boundary-UNAWARE on purpose: it never sees `Exposed`/`Untrusted`,
//! so nothing here can bypass the egress gate — the stores cross the boundary
//! before calling in.

use bytes::Bytes;
use futures::stream::BoxStream;

use hatch_protocol::{ReadRequest, Slot, WriteRequest};

use crate::error::BridgeError;

/// A blob's pieces as they cross the cache seam, in order. An error ends the
/// blob, and what came before it is not the blob.
pub type BlobPieces = BoxStream<'static, Result<Bytes, BridgeError>>;

/// Transport for the per-session KV. Moves already-serialized `hatch-protocol`
/// DTOs; the store above closes all trust concerns.
#[async_trait::async_trait]
pub trait SessionBackend: Send + Sync {
    /// Read raw slots + version. `version == 0` ⇒ session absent.
    async fn read_raw(&self, id: &str, req: ReadRequest) -> Result<(Vec<Slot>, u64), BridgeError>;

    /// Atomic CAS write. `Ok(new_version)` | `Err(BridgeError::VersionMismatch)`.
    /// `deadline_unix_secs` threads the TEE-side absolute TTL INSIDE the channel
    /// — the storage-CVM sweeper enforces it (set once at create; `None` on
    /// updates so the deadline is never refreshed).
    async fn write(
        &self,
        id: &str,
        req: WriteRequest,
        deadline_unix_secs: Option<u64>,
    ) -> Result<u64, BridgeError>;

    async fn exists(&self, id: &str) -> Result<bool, BridgeError>;
}

/// Transport for the L2 cwasm cache. Moves opaque sealed blobs keyed by the
/// already-derived identity-hiding `blob_name`, a piece at a time, so no blob
/// is held whole on this side of the seam.
#[async_trait::async_trait]
pub trait CacheBackend: Send + Sync {
    /// Keep the `length`-byte blob `pieces` yields under `blob_name`, in place
    /// of any before it, once all of it has arrived. A blob whose pieces fail is
    /// not kept, and the one before it stays.
    async fn store(
        &self,
        blob_name: &str,
        length: u64,
        pieces: BlobPieces,
    ) -> Result<(), BridgeError>;

    /// The blob under `blob_name` as its length and its pieces, the pieces held
    /// to the length. `Ok(None)` = miss (absent blob).
    async fn load(&self, blob_name: &str) -> Result<Option<(u64, BlobPieces)>, BridgeError>;

    /// Drop the blob under `blob_name`, if there is one.
    async fn remove(&self, blob_name: &str) -> Result<(), BridgeError>;
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use futures::{StreamExt, TryStreamExt};

    /// In-memory `CacheBackend` — proves the seam is a real abstraction and lets
    /// `CacheStore`'s seal/open crypto run with no transport. Keyed by the
    /// identity-hiding `blob_name` the store derives. It hands a blob back in
    /// pieces of 1000 bytes, which line up with nothing the store wrote.
    #[derive(Default)]
    pub(crate) struct MockCacheBackend {
        pub(crate) blobs: Mutex<HashMap<String, Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl CacheBackend for MockCacheBackend {
        async fn store(
            &self,
            blob_name: &str,
            length: u64,
            pieces: BlobPieces,
        ) -> Result<(), BridgeError> {
            let blob: Vec<u8> = pieces
                .try_fold(Vec::new(), |mut all, p| async move {
                    all.extend_from_slice(&p);
                    Ok(all)
                })
                .await?;
            assert_eq!(
                blob.len() as u64,
                length,
                "a blob of the length it declared"
            );
            self.blobs
                .lock()
                .unwrap()
                .insert(blob_name.to_string(), blob);
            Ok(())
        }

        async fn load(&self, blob_name: &str) -> Result<Option<(u64, BlobPieces)>, BridgeError> {
            let Some(blob) = self.blobs.lock().unwrap().get(blob_name).cloned() else {
                return Ok(None);
            };
            let pieces: Vec<_> = blob
                .chunks(1000)
                .map(|p| Ok(Bytes::copy_from_slice(p)))
                .collect();
            Ok(Some((
                blob.len() as u64,
                futures::stream::iter(pieces).boxed(),
            )))
        }

        async fn remove(&self, blob_name: &str) -> Result<(), BridgeError> {
            self.blobs.lock().unwrap().remove(blob_name);
            Ok(())
        }
    }
}
