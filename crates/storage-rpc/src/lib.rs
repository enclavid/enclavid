//! `storage-rpc` — the storage-tier RPC contract: remote trait calls (remoc
//! `rtc`) between the orchestrator (api) and the **storage-CVM**, over an RA-TLS
//! tunnel. Two services live behind one connection because they share the same
//! *trust* tier (both blind ciphertext KV, one orchestrator) even though their
//! load profiles diverge:
//!
//!   * the session store — per-session state / media / disclosures, backed by
//!     one SQLite file per record (write-heavy, CAS, TTL);
//!   * the cache — the L2 compiled-artifact (cwasm) cache, backed by
//!     `object_store` (write-once, read-mostly).
//!
//! The storage-CVM is a **blind ciphertext KV**, and api takes it for the
//! volume it keeps everything on: every payload is already sealed TEE-side (in
//! storage-client's `SessionStore` / `CacheStore`), and every name is one api
//! derived under a key only api holds — a [`RecordName`], a [`MediaName`], a
//! [`BlobName`] — so the CVM never holds a key, a plaintext or a session id.
//!
//! One leg — [`StorageLeg`] at api's end, [`serve_storage`] at the storage-CVM's.
//! Each end declares how it judges what crosses it: api's in `storage_client`,
//! beside the seals; the storage-CVM's in `enclavid_storage`. A read, a write
//! and a stored blob reach api's doors as their answered parts — [`Fields`],
//! [`Ops`] of each kind, [`Expected`], a [`BlobStream`] — and cross as what the
//! doors build of them.
//!
//! A SEPARATE crate from `engine-rpc` on purpose: the storage-CVM is a distinct
//! fleet role with its own measured image; it must not link the engine
//! compile/execute contract. The session store's payloads are in [`session`].

mod session;

use std::time::Duration;

use serde::{Deserialize, Serialize};

use fleet_stream::{StreamLen, bin};

pub use session::{
    BlobField, BlobWrite, FieldSelector, ListAppend, ListField, ListSlot, MediaWrite, Op,
    ReadRequest, ReadResponse, ScalarSlot, Slot, WriteRequest, WriteResponse,
};

mod ops;
pub use ops::{
    BlobStream, DisclosureOp, Expected, Fields, MediaOp, MetadataOp, Ops, ResetOp, StateOp,
};

/// The longest blob the cache takes or gives, in bytes: 2 GiB.
///
/// Above the largest one api seals into it — a cwasm at the execute hop's bound
/// (1.5 GiB) with its metadata and the seal's overhead — which api holds itself
/// to where it writes one.
pub const MAX_CACHE_BLOB_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// How long a cache blob may go without a new byte, on either end: the patience
/// a leg gives silence by default. Both ends stream from what they hold, the
/// store from its disk and api from its seal, and neither has reason to pause.
pub const CACHE_STREAM_IDLE: Duration = Duration::from_secs(20);

/// How long a whole cache blob may take to cross. The idle deadline bounds a
/// stall, not a trickle; this carries a blob at [`MAX_CACHE_BLOB_BYTES`] at about
/// 17 MiB/s, far below what the leg runs at.
pub const CACHE_STREAM_DEADLINE: Duration = Duration::from_secs(120);

/// The name a session's record is kept under: derived in api from the session
/// id, under a key only api holds. The store files the record under a digest
/// of this and of its caller's measurement; neither the store nor its volume
/// ever holds the session id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecordName(#[serde(with = "serde_bytes")] pub [u8; 32]);

/// The name a record keeps one media blob under: derived in api from the
/// session and what the blob is a capture of, under a key only api holds, so
/// it differs for the same capture in two sessions and never is the capture's
/// own hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MediaName(#[serde(with = "serde_bytes")] pub [u8; 32]);

/// The name a cache blob is kept under: derived in api from what the blob is a
/// compile of, under a key only api holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlobName(#[serde(with = "serde_bytes")] pub [u8; 32]);

/// A record's version as the store read it back or bumped it: 0 for a record
/// that does not exist. It crosses as a field of [`ReadResponse`] and
/// [`WriteResponse`]; api's end of the leg is handed it as this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Version(pub u64);

/// A cache blob crossing the leg: its exact length in the call, its bytes on a
/// `bin` channel beside it.
///
/// No digest. api seals every blob it stores and opens it again a segment at a
/// time, refusing a segment the store or the wire changed and a stream that ends
/// anywhere but where it was sealed to end, so a digest here would check the
/// same thing again with less to go on. What the length and the one finished
/// message give is that a store keeps only a blob that arrived whole.
#[derive(Serialize, Deserialize)]
pub struct CacheBlob {
    pub length: StreamLen<MAX_CACHE_BLOB_BYTES>,
    pub body: bin::Receiver,
}

/// The store's answer that a blob is kept: the whole of it arrived, and it is in
/// place of any before it.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Kept;

/// The store's answer that no blob is kept under a name any more, whether or not
/// one was.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Dropped;

/// A session-store RPC failure. `VersionMismatch` is the CAS precondition (the
/// session's stored version did not match `expected_version`, or a must-not-exist
/// create found an existing session) — the api client maps it back to
/// `StoreError::VersionMismatch`.
/// `Internal` is an opaque store / transport failure. This is the SESSION error:
/// the L2 cache has no CAS, so `VersionMismatch` lives only here.
/// `TooLarge` is a write the calling end's door refused before sending it,
/// because it would not fit the one call it crosses in; the store never saw it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionError {
    VersionMismatch,
    Internal(String),
    TooLarge,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::VersionMismatch => write!(f, "version mismatch"),
            SessionError::Internal(m) => write!(f, "session store internal: {m}"),
            SessionError::TooLarge => write!(f, "a write past what the storage leg carries"),
        }
    }
}
impl std::error::Error for SessionError {}
impl From<remoc::rtc::CallError> for SessionError {
    fn from(err: remoc::rtc::CallError) -> Self {
        SessionError::Internal(format!("session store rpc failed: {err}"))
    }
}

/// A cache RPC failure. The L2 cwasm cache has no CAS and one opaque failure mode
/// (object_store / key validation / transport), so — unlike [`SessionError`] —
/// this type deliberately cannot express `VersionMismatch`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheError(pub String);

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cache store internal: {}", self.0)
    }
}
impl std::error::Error for CacheError {}
impl From<remoc::rtc::CallError> for CacheError {
    fn from(err: remoc::rtc::CallError) -> Self {
        CacheError(format!("cache store rpc failed: {err}"))
    }
}

// The contracts, and the clients and servers remoc writes from them, are NOT
// exported: no crate outside this one can name a generated client, let alone
// call it, and none can serve a raw contract. Both ends reach the leg through
// `leg`, each at the end its role declares: `*Serves` is what a serving end
// declares, and `*At` a contract as its server sees it there; `*Calls`, read
// off the doors, is what a calling end declares.
mod contract;
pub use contract::{
    RemoteCacheAt, RemoteCacheServes, RemoteSessionStoreAt, RemoteSessionStoreServes,
};

mod leg;
pub use leg::{
    LegError, RemoteCacheCalls, RemoteSessionStoreCalls, StorageLeg, connect_storage, serve_storage,
};

/// What a role sets of its end of the leg — the same as of every fleet leg (see
/// `fleet_stream`).
pub use fleet_stream::LegSettings;
