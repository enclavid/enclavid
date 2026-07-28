//! `storage-rpc` — the storage-tier RPC contract: remote trait calls (remoc
//! `rtc`) between the orchestrator (api) and the trusted **storage-CVM**, over an
//! RA-TLS tunnel. Two services live behind one connection because they share the
//! same *trust* tier (both blind ciphertext KV, api the sole client) even though
//! their load profiles diverge:
//!
//!   * [`SessionStoreService`] — per-session state / media / disclosures, backed
//!     by redb (write-heavy, CAS, TTL). Replaces the hatch `/sessions/*` +
//!     Redis path.
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

use remoc::codec::Ciborium;
use serde::{Deserialize, Serialize};

use hatch_protocol::{DeleteResponse, ReadRequest, ReadResponse, WriteRequest, WriteResponse};

/// A session-store RPC failure. `VersionMismatch` is the CAS precondition (the
/// session's stored version did not match `expected_version`, or a must-not-exist
/// create found an existing session) — the api client maps it back to
/// `BridgeError::VersionMismatch` (the same 412 the hatch path produced).
/// `Internal` is an opaque redb / transport failure. This is the SESSION error:
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
    /// session's TTL deadline in the same transaction.
    async fn write(
        &self,
        id: String,
        req: WriteRequest,
        deadline_unix_secs: Option<u64>,
    ) -> Result<WriteResponse, SessionError>;

    /// Drop the session STATE field + purge all media (the `/reset` path).
    /// Leaves metadata/version so the session still `exists` and can be
    /// re-claimed with a fresh applicant key. Returns the state-field delete
    /// count.
    async fn delete(&self, id: String) -> Result<DeleteResponse, SessionError>;

    /// Existence probe (version present).
    async fn exists(&self, id: String) -> Result<bool, SessionError>;
}

/// L2 compiled-artifact (cwasm) cache — a blind opaque-blob KV keyed by the
/// identity-hiding `blob_name` the api derives (`hex(HKDF(filename_key,
/// cache_id))`). The CVM never sees the composition, only pseudo-random hex.
/// Sealed bytes ride the wire; a miss is `Ok(None)` (not an error) so the
/// orchestrator recompiles.
#[remoc::rtc::remote]
pub trait CacheService {
    async fn store(&self, key: String, bytes: Vec<u8>) -> Result<(), CacheError>;
    async fn load(&self, key: String) -> Result<Option<Vec<u8>>, CacheError>;
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

/// The remoc connection config both storage peers build from — same limits as
/// `engine-rpc::connection_cfg` (media blobs + cwasm bundles up to 64 MiB ride
/// this channel; immediate flush for latency; pinned peer-driven port limits for
/// adversarial-peer hardening). `remoc::Cfg` is a re-export of `chmux::Cfg`, so
/// the fields are flat and (being `#[non_exhaustive]`) must be mutated after
/// `default()`.
#[allow(clippy::field_reassign_with_default)]
pub fn connection_cfg() -> remoc::Cfg {
    let mut cfg = remoc::Cfg::default();
    cfg.max_data_size = 64 * 1024 * 1024;
    cfg.flush_delay = std::time::Duration::ZERO;
    cfg.max_ports = 256;
    cfg.max_received_ports = 64;
    cfg
}
