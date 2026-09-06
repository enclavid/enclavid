//! `enclavid-storage` — the trusted storage-CVM's core. Serves the two
//! `storage-rpc` services against local backends:
//!
//!   * [`SessionStoreService`] → one SQLite file per session ([`session`]),
//!     write-heavy per-session state / media / disclosures with ACID CAS + a
//!     marker-based TTL sweeper.
//!   * [`CacheService`] → `object_store` ([`cache`]), the write-once/read-mostly
//!     L2 cwasm cache.
//!
//! Both share this one CVM (same *trust* tier — blind ciphertext KV, api the sole
//! client) but stay distinct stores (their *load* profiles diverge), so a future
//! split into two CVMs is a deploy step, not a rewrite. The store cores are plain
//! structs so they unit-test without remoc; [`StorageSvc`] holds them and
//! [`Caller`] — one per connection, carrying the peer's launch digest — adds the
//! async remoc trait impls on top.

pub mod cache;
mod scope;
pub mod session;

#[cfg(test)]
mod integration_tests;

use std::sync::Arc;

use hatch_protocol::{DeleteResponse, ReadRequest, ReadResponse, WriteRequest, WriteResponse};
use storage_rpc::{CacheError, CacheService, SessionError, SessionStoreService};

pub use cache::CacheBlobs;
pub use session::SessionStore;

use scope::Scope;

/// Current wall-clock unix seconds. The CVM's clock is host-controllable (no
/// trusted time without a vTPM/roughtime upgrade), so a skewed clock only affects
/// TTL *availability* — never confidentiality (data is ciphertext, `tee_seal_key`
/// never enters the CVM). See the sweeper docs.
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
/// It serves nobody by itself. The RPC services are implemented by [`Caller`],
/// which is the only thing in this crate that can name a record — so a call that
/// does not say who is asking is not a call this node knows how to make.
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
    /// certificate — see `enclavid_ra_tls::peer_measurement` for why that is
    /// trustworthy only after the handshake, which is the only place a `Caller`
    /// is built.
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

impl SessionStoreService for Caller {
    async fn read(&self, id: String, req: ReadRequest) -> Result<ReadResponse, SessionError> {
        let s = self.svc.sessions.clone();
        let name = self.scope.session(&id);
        blocking(move || s.read(name.as_str(), req)).await
    }

    async fn write(
        &self,
        id: String,
        req: WriteRequest,
        deadline_unix_secs: Option<u64>,
    ) -> Result<WriteResponse, SessionError> {
        let s = self.svc.sessions.clone();
        let name = self.scope.session(&id);
        blocking(move || s.write(name.as_str(), req, deadline_unix_secs)).await
    }

    async fn delete(&self, id: String) -> Result<DeleteResponse, SessionError> {
        let s = self.svc.sessions.clone();
        let name = self.scope.session(&id);
        blocking(move || s.delete(name.as_str())).await
    }

    async fn exists(&self, id: String) -> Result<bool, SessionError> {
        let s = self.svc.sessions.clone();
        let name = self.scope.session(&id);
        blocking(move || s.exists(name.as_str())).await
    }
}

impl CacheService for Caller {
    async fn store(&self, key: String, bytes: Vec<u8>) -> Result<(), CacheError> {
        let name = self.scope.blob(&key);
        self.svc.cache.store(name.as_str(), bytes).await
    }

    async fn load(&self, key: String) -> Result<Option<Vec<u8>>, CacheError> {
        let name = self.scope.blob(&key);
        self.svc.cache.load(name.as_str()).await
    }
}
