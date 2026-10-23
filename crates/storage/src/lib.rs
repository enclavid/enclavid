//! `enclavid-storage` — the trusted storage-CVM's core. Serves the two
//! `storage-rpc` services against local backends:
//!
//!   * [`RemoteSessionStoreAt`] → one SQLite file per session ([`session`]),
//!     write-heavy per-session state / media / disclosures with ACID CAS + a
//!     marker-based TTL sweeper.
//!   * [`RemoteCacheAt`] → `object_store` ([`cache`]), the write-once/read-mostly
//!     L2 cwasm cache.
//!
//! Both share this one CVM (same *trust* tier — blind ciphertext KV, one
//! orchestrator in practice) but stay distinct stores (their *load* profiles diverge), so a future
//! split into two CVMs is a deploy step, not a rewrite. The store cores are plain
//! structs so they unit-test without remoc; [`StorageSvc`] holds them and
//! [`Caller`] — one per connection, carrying the peer's launch digest — serves
//! both contracts at this role's end of the leg, [`boundary::AnyCaller`].

pub mod boundary;
pub mod cache;
mod scope;
pub mod session;

#[cfg(test)]
mod integration_tests;

use std::sync::Arc;

use enclavid_boundary::{Exposed, Untrusted};
use fleet_stream::{Incoming, StreamLen, bin};
use safe_logger::debug;
use storage_rpc::{
    BlobName, CACHE_STREAM_DEADLINE, CACHE_STREAM_IDLE, CacheBlob, CacheError, Dropped, Kept,
    ReadRequest, ReadResponse, RecordName, RemoteCacheAt, RemoteSessionStoreAt, SessionError,
    WriteRequest, WriteResponse,
};

pub use cache::CacheBlobs;
pub use session::{DEFAULT_BUSY_TIMEOUT, SessionStore};

use boundary::AnyCaller;
use scope::Scope;

/// Current wall-clock unix seconds. In the attested build the guest's clock is
/// kept by `timesync`, and this role ends once the kernel stops vouching for it.
/// What it is compared with is less safe: a session's deadline and a blob's file
/// time lie on the volume the host provisions, and the host can rewrite them.
/// That makes a record go sooner, or a session stay longer on a disk the host
/// could keep a copy of anyway.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The storage node's two backends: the per-session SQLite store + one
/// object_store (L2 cache). Cloneable-cheap collaborators, shared by every
/// connection behind an `Arc`.
///
/// It serves nobody by itself: the RPC services are implemented by [`Caller`],
/// which is where a wire name becomes a record name. The backends underneath
/// address a record or a blob only by a name the crate-private `scope` module
/// derived, so what reaches the volume is never a name a caller sent.
pub struct StorageSvc {
    sessions: Arc<SessionStore>,
    cache: CacheBlobs,
}

impl StorageSvc {
    pub fn new(sessions: Arc<SessionStore>, cache: CacheBlobs) -> Self {
        Self { sessions, cache }
    }
}

/// One caller's view of the node: the shared backends, plus WHICH peer is
/// asking. Built per connection, because that is where the answer comes from.
///
/// It exists because this node accepts any attested guest and the backends are
/// one map — see [`scope`] for why a foreign caller cannot land in api's half of
/// it, and for why partitioning costs nothing here.
pub struct Caller {
    svc: Arc<StorageSvc>,
    scope: Scope,
}

impl Caller {
    /// `measurement` is the peer's launch digest, read from its verified
    /// certificate — see `enclavid_ra_tls::peer_measurement`, which refuses to
    /// answer before the handshake completes. This constructor takes the string
    /// on trust; what makes it a digest rather than anything else is that
    /// `storage-cvm` builds a `Caller` at exactly one place, from the connection
    /// it just accepted.
    pub fn new(svc: Arc<StorageSvc>, measurement: String) -> Caller {
        Caller {
            svc,
            scope: Scope::new(measurement),
        }
    }
}

/// Session-store calls are blocking (SQLite opens a file + fsyncs on commit); run
/// them on the blocking pool so they never stall the async runtime. Only the
/// SESSION store is blocking; the cache is async (`object_store`) and calls
/// straight through.
async fn blocking<T, F>(f: F) -> Result<T, SessionError>
where
    F: FnOnce() -> Result<T, SessionError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| SessionError::Internal(format!("session store task join: {e}")))?
}

/// A session-store failure as it leaves: the lost version race as it is, any
/// other in one fixed text, what the store failed on kept for the debug log.
fn session_failed(e: SessionError) -> SessionError {
    match e {
        SessionError::VersionMismatch => SessionError::VersionMismatch,
        SessionError::TooLarge => SessionError::TooLarge,
        SessionError::Internal(detail) => {
            debug!("session store: {detail}");
            SessionError::Internal("the session store failed".into())
        }
    }
}

/// A cache failure as it leaves: one fixed text, what the cache failed on kept
/// for the debug log.
fn cache_failed(e: CacheError) -> CacheError {
    debug!("cache: {e}");
    CacheError("the cache failed".into())
}

impl RemoteSessionStoreAt<AnyCaller> for Caller {
    async fn read(
        &self,
        record: Untrusted<RecordName, (), AnyCaller>,
        req: Untrusted<ReadRequest, (), AnyCaller>,
    ) -> Result<Exposed<ReadResponse, (), AnyCaller>, SessionError> {
        let s = self.svc.sessions.clone();
        let name = self.scope.session(&record.into_inner());
        let req = req.into_inner();
        blocking(move || s.read(&name, req))
            .await
            .map(AnyCaller::expose)
            .map_err(session_failed)
    }

    async fn write(
        &self,
        record: Untrusted<RecordName, (), AnyCaller>,
        req: Untrusted<WriteRequest, (), AnyCaller>,
    ) -> Result<Exposed<WriteResponse, (), AnyCaller>, SessionError> {
        let s = self.svc.sessions.clone();
        let name = self.scope.session(&record.into_inner());
        let req = req.into_inner();
        blocking(move || s.write(&name, req))
            .await
            .map(AnyCaller::expose)
            .map_err(session_failed)
    }
}

impl RemoteCacheAt<AnyCaller> for Caller {
    async fn store(
        &self,
        blob: Untrusted<BlobName, (), AnyCaller>,
        body: Untrusted<CacheBlob, (), AnyCaller>,
    ) -> Result<Exposed<Kept, (), AnyCaller>, CacheError> {
        let name = self.scope.blob(&blob.into_inner());
        let body = body.into_inner();
        let length = body.length.get();
        // A stream that fails, at its deadline among other ways, is not kept:
        // what was written aside goes, and what was there stays. Held to the
        // length it came with, which is what its room in the cache was made for.
        let pieces = Incoming::open(body.body, length, CACHE_STREAM_IDLE)
            .await
            .map_err(|e| cache_failed(CacheError(e.to_string())))?
            .into_pieces(CACHE_STREAM_DEADLINE, None);
        self.svc
            .cache
            .store(&name, length, pieces)
            .await
            .map_err(cache_failed)?;
        Ok(AnyCaller::expose(Kept))
    }

    async fn load(
        &self,
        blob: Untrusted<BlobName, (), AnyCaller>,
    ) -> Result<Exposed<Option<CacheBlob>, (), AnyCaller>, CacheError> {
        let name = self.scope.blob(&blob.into_inner());
        let Some((size, pieces)) = self.svc.cache.load(&name).await.map_err(cache_failed)? else {
            return Ok(AnyCaller::expose(None));
        };
        let length = StreamLen::new(size)
            .ok_or_else(|| cache_failed(CacheError("a blob past what the leg carries".into())))?;
        let (tx, body) = bin::channel();
        // The reply carries the receiving end, so the bytes go after the reply
        // has: a task of their own, which ends with the stream, with a caller
        // that stopped reading, or at the deadline.
        tokio::spawn(async move {
            let _ =
                tokio::time::timeout(CACHE_STREAM_DEADLINE, fleet_stream::send_from(tx, pieces))
                    .await;
        });
        Ok(AnyCaller::expose(Some(CacheBlob { length, body })))
    }

    async fn remove(
        &self,
        blob: Untrusted<BlobName, (), AnyCaller>,
    ) -> Result<Exposed<Dropped, (), AnyCaller>, CacheError> {
        let name = self.scope.blob(&blob.into_inner());
        self.svc.cache.remove(&name).await.map_err(cache_failed)?;
        Ok(AnyCaller::expose(Dropped))
    }
}
