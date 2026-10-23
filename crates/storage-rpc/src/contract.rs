//! The storage contracts, as remoc serves them.
//!
//! Nothing here is exported but what an end that serves the leg declares
//! (`RemoteSessionStoreServes`, `RemoteCacheServes`) and the contracts as their
//! server sees them at a declared end (`RemoteSessionStoreAt`, `RemoteCacheAt`).
//! What an end that calls it declares is read off the doors it calls through, in
//! [`crate::leg`]. The raw traits, the clients and servers remoc writes from them,
//! and the adapters between them are reached through `leg` alone, so no crate
//! outside this one can name them.

use remoc::codec::Ciborium;
use serde::{Deserialize, Serialize};

use crate::{
    BlobName, CacheBlob, CacheError, Dropped, Kept, ReadRequest, ReadResponse, RecordName,
    SessionError, WriteRequest, WriteResponse,
};

/// A session's record: its state, media and disclosures, one record per
/// session. Method payloads are the [`session`](crate::session) DTOs.
///
/// `#[protocol]` writes what its serving end declares
/// (`RemoteSessionStoreServes`) and how its server receives
/// (`RemoteSessionStoreAt`), which is the only shape `serve_storage` serves it in.
/// The calling end's doors ([`StorageLeg`](crate::StorageLeg)) build both
/// requests and take both responses apart.
#[enclavid_boundary_macros::protocol]
#[remoc::rtc::remote]
pub trait RemoteSessionStore {
    /// Batched typed read. Empty `req.fields` is a version probe; version 0 in
    /// the response means no record goes by `record`.
    async fn read(
        &self,
        record: RecordName,
        req: ReadRequest,
    ) -> Result<ReadResponse, SessionError>;

    /// Atomic CAS write. `req.expected_version`: `None` = must-not-exist
    /// (create), `Some(v)` = the record's version must equal `v`; otherwise
    /// [`SessionError::VersionMismatch`]. A create carries its deadline in `req`,
    /// committed with the record; a `/reset` is a write too (`Op::Reset`), so it
    /// is version-checked like any other.
    async fn write(
        &self,
        record: RecordName,
        req: WriteRequest,
    ) -> Result<WriteResponse, SessionError>;
}

/// The L2 compiled-artifact (cwasm) cache — a blind opaque-blob KV under the
/// names api derives, which the store derives again under the calling peer's own
/// scope before it touches a blob.
///
/// Sealed bytes ride the wire, each blob streamed beside its call as a
/// [`CacheBlob`], so no call carries one and no blob is held whole on either
/// end. A miss is `Ok(None)`, not an error, so the orchestrator recompiles.
///
/// `#[protocol]` writes what its serving end declares (`RemoteCacheServes`) and
/// how its server receives (`RemoteCacheAt`). The calling end's doors frame a
/// blob they are handed into the stream that crosses.
#[enclavid_boundary_macros::protocol]
#[remoc::rtc::remote]
pub trait RemoteCache {
    /// Keep the blob streaming beside the call under `blob`, in place of any
    /// before it. It is in place only once all of it has arrived: a stream that
    /// fails leaves what was there.
    async fn store(&self, blob: BlobName, body: CacheBlob) -> Result<Kept, CacheError>;

    /// The blob under `blob`, streaming beside the reply, or `None`.
    async fn load(&self, blob: BlobName) -> Result<Option<CacheBlob>, CacheError>;

    /// Drop the blob under `blob`, if there is one.
    async fn remove(&self, blob: BlobName) -> Result<Dropped, CacheError>;
}

/// The base-channel handshake value: on connect the storage-CVM sends the
/// orchestrator BOTH service clients over the one remoc connection, so a single
/// RA-TLS dial reaches both stores.
#[derive(Serialize, Deserialize)]
pub(crate) struct StorageClients {
    pub(crate) session: RemoteSessionStoreClient<Ciborium>,
    pub(crate) cache: RemoteCacheClient<Ciborium>,
}
