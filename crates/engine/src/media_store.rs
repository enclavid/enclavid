//! Outbound contract for the host-side sealed blob store.
//!
//! Applicant uploads (camera frames today, documents/PDFs later) are stored
//! host-side, content-addressed and AEAD-sealed, keyed by the 32-byte BLAKE3 of
//! the blob. The engine holds only a handle to this trait — the runtime's I/O
//! layer (the api crate) implements it against the broker session store and
//! owns the seal keys, so engine stays free of `SessionStore` / AEAD-key
//! knowledge (mirrors [`SessionListener`](crate::listener::SessionListener)).
//!
//! Reads are lazy and per-round: the policy's [`blob::from-blob-ref`](crate::
//! media::BlobRep) calls [`load`](MediaStore::load) mid-`handle` to rehydrate
//! a stored blob. Writes are NOT on this trait — the runtime always stores a
//! capture's blobs by handing them to the listener (`SessionChange.media`) so
//! they co-commit atomically with the reducer state.

use std::future::Future;
use std::pin::Pin;

/// Loads one sealed blob's plaintext bytes by its content hash. `Ok(None)` = no
/// such blob in this session (unknown / never-stored ref) — surfaced to the
/// policy as `load-error::not-found`. `Err` = a genuine transport / decrypt
/// failure, which traps the round.
///
/// Boxed future rather than `async fn` so the trait stays object-safe — engine
/// holds `Arc<dyn MediaStore>` and dispatches dynamically. Error type is
/// `wasmtime::Result` because the call originates inside a wasmtime host fn
/// body and any failure has to surface as a trap.
pub trait MediaStore: Send + Sync {
    fn load<'a>(
        &'a self,
        blob_hash: &'a [u8; 32],
    ) -> Pin<Box<dyn Future<Output = wasmtime::Result<Option<Vec<u8>>>> + Send + 'a>>;
}
