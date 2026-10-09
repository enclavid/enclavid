//! `storage-rpc` — the storage-tier RPC contract: remote trait calls (remoc
//! `rtc`) between the orchestrator (api) and the trusted **storage-CVM**, over an
//! RA-TLS tunnel. Two services live behind one connection because they share the
//! same *trust* tier (both blind ciphertext KV, one orchestrator) even though
//! their load profiles diverge:
//!
//!   * [`SessionStoreService`] — per-session state / media / disclosures, backed
//!     by one SQLite file per record (write-heavy, CAS, TTL). Replaces the
//!     hatch `/sessions/*` + Redis path.
//!   * [`CacheService`] — the L2 compiled-artifact (cwasm) cache, backed by
//!     `object_store` (write-once, read-mostly). Replaces the hatch `/cache/*`
//!     path.
//!
//! The storage-CVM is a **blind ciphertext KV**: every payload is already
//! AEAD-sealed under `tee_seal_key` TEE-side (in hatch-client's `SessionStore` /
//! `CacheStore`), so the CVM never holds a key or plaintext PII. RA-TLS is the
//! second layer that hides the access pattern + key from the untrusted host.
//!
//! A SEPARATE crate from `engine-rpc` on purpose: the storage-CVM is a distinct
//! fleet role with its own measured image; it must not link the engine
//! compile/execute contract. The session-store wire DTOs are reused verbatim
//! from `hatch-protocol` as the remoc payloads, so the CVM and the legacy hatch
//! path speak the same shapes.

use std::time::Duration;

use remoc::codec::Ciborium;
use serde::{Deserialize, Serialize};

use fleet_stream::{StreamLen, bin};
use hatch_protocol::{ReadRequest, ReadResponse, WriteRequest, WriteResponse};

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

/// A session-store RPC failure. `VersionMismatch` is the CAS precondition (the
/// session's stored version did not match `expected_version`, or a must-not-exist
/// create found an existing session) — the api client maps it back to
/// `BridgeError::VersionMismatch` (the same 412 the hatch path produced).
/// `Internal` is an opaque store / transport failure. This is the SESSION error:
/// the L2 cache has no CAS, so `VersionMismatch` lives only here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionError {
    VersionMismatch,
    Internal(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::VersionMismatch => write!(f, "version mismatch"),
            SessionError::Internal(m) => write!(f, "session store internal: {m}"),
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

/// Per-session state / media / disclosures. Method payloads are the
/// `hatch-protocol` wire DTOs reused verbatim. `deadline_unix_secs` on
/// [`write`](SessionStoreService::write) threads the sliding TTL INSIDE the
/// RA-TLS channel (the plaintext host STATUS byte is gone) — the CVM commits it
/// atomically with the version bump and its sweeper enforces it.
#[remoc::rtc::remote]
pub trait SessionStoreService {
    /// Batched typed read. Empty `req.fields` is a version probe. `version == 0`
    /// in the response means the session does not exist.
    async fn read(&self, id: String, req: ReadRequest) -> Result<ReadResponse, SessionError>;

    /// Atomic CAS write. `req.expected_version`: `None` = must-not-exist
    /// (create), `Some(v)` = current version must equal `v`; otherwise
    /// [`SessionError::VersionMismatch`]. `deadline_unix_secs` refreshes the
    /// session's TTL deadline in the same transaction. A `/reset` is a write
    /// too (`Op::Reset`), so it is version-checked like any other.
    async fn write(
        &self,
        id: String,
        req: WriteRequest,
        deadline_unix_secs: Option<u64>,
    ) -> Result<WriteResponse, SessionError>;

    /// Existence probe (version present).
    async fn exists(&self, id: String) -> Result<bool, SessionError>;
}

/// L2 compiled-artifact (cwasm) cache — a blind opaque-blob KV keyed by the
/// identity-hiding `blob_name` the api derives (`hex(HKDF(filename_key,
/// cache_id))`), which the CVM re-derives under the calling peer's own scope
/// before it touches a blob. It never sees the composition, only pseudo-random
/// hex.
///
/// Sealed bytes ride the wire, each blob streamed beside its call as a
/// [`CacheBlob`], so no call carries one and no blob is held whole on either
/// end. A miss is `Ok(None)` (not an error) so the orchestrator recompiles.
#[remoc::rtc::remote]
pub trait CacheService {
    /// Keep the blob streaming beside the call under `key`, in place of any
    /// before it. It is in place only once all of it has arrived: a stream that
    /// fails leaves what was there.
    async fn store(&self, key: String, blob: CacheBlob) -> Result<(), CacheError>;

    /// The blob under `key`, streaming beside the reply, or `None`.
    async fn load(&self, key: String) -> Result<Option<CacheBlob>, CacheError>;

    /// Drop the blob under `key`, if there is one.
    async fn remove(&self, key: String) -> Result<(), CacheError>;
}

/// The base-channel handshake value: on connect the storage-CVM sends the
/// orchestrator BOTH service clients over the one remoc connection, so a single
/// RA-TLS dial reaches both stores. remoc RTC clients are `RemoteSend`
/// (transported as chmux port references), so a struct of two derives cleanly —
/// the same mechanism that lets the execute boundary pass a callback client as a
/// method argument.
#[derive(Serialize, Deserialize)]
pub struct StorageClients {
    pub session: SessionStoreServiceClient<Ciborium>,
    pub cache: CacheServiceClient<Ciborium>,
}

/// The remoc connection config both storage peers build from, and what a role
/// sets of it — the one every fleet leg is brought up with (see `fleet_stream`).
pub use fleet_stream::{LegSettings, connection_cfg};
