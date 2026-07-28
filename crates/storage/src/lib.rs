//! `enclavid-storage` — the trusted storage-CVM's core. Serves the two
//! `storage-rpc` services against local backends:
//!
//!   * [`SessionStoreService`] → redb ([`session`]), write-heavy per-session
//!     state / media / disclosures with real ACID CAS + a TTL sweeper.
//!   * [`CacheService`] → `object_store` ([`cache`]), the write-once/read-mostly
//!     L2 cwasm cache.
//!
//! Both share this one CVM (same *trust* tier — blind ciphertext KV, api the sole
//! client) but stay distinct stores (their *load* profiles diverge), so a future
//! split into two CVMs is a deploy step, not a rewrite. The store cores are plain
//! functions/structs so they unit-test without remoc; [`StorageSvc`] adds the
//! async remoc trait impls on top.

pub mod cache;
pub mod session;

#[cfg(test)]
mod integration_tests;

use std::sync::Arc;

use redb::Database;

use hatch_protocol::{DeleteResponse, ReadRequest, ReadResponse, WriteRequest, WriteResponse};
use storage_rpc::{CacheError, CacheService, SessionError, SessionStoreService};

pub use cache::CacheBlobs;

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

/// The served storage node: one redb database (sessions) + one object_store
/// (L2 cache). Cloneable-cheap collaborators, held behind `Arc` for the remoc
/// `ServerShared`.
pub struct StorageSvc {
    db: Arc<Database>,
    cache: CacheBlobs,
}

impl StorageSvc {
    pub fn new(db: Arc<Database>, cache: CacheBlobs) -> Self {
        Self { db, cache }
    }

    pub fn db(&self) -> Arc<Database> {
        self.db.clone()
    }
}

/// redb calls are blocking (a write fsyncs the blob); run them on the blocking
/// pool so they never stall the async runtime. Only the SESSION store (redb) is
/// blocking; the cache is async (`object_store`) and calls straight through.
async fn blocking<T, F>(f: F) -> Result<T, SessionError>
where
    F: FnOnce() -> Result<T, SessionError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| SessionError::Internal(format!("session store task join: {e}")))?
}

impl SessionStoreService for StorageSvc {
    async fn read(&self, id: String, req: ReadRequest) -> Result<ReadResponse, SessionError> {
        let db = self.db.clone();
        blocking(move || session::read(&db, &id, req)).await
    }

    async fn write(
        &self,
        id: String,
        req: WriteRequest,
        deadline_unix_secs: Option<u64>,
    ) -> Result<WriteResponse, SessionError> {
        let db = self.db.clone();
        blocking(move || session::write(&db, &id, req, deadline_unix_secs)).await
    }

    async fn delete(&self, id: String) -> Result<DeleteResponse, SessionError> {
        let db = self.db.clone();
        blocking(move || session::delete(&db, &id)).await
    }

    async fn exists(&self, id: String) -> Result<bool, SessionError> {
        let db = self.db.clone();
        blocking(move || session::exists(&db, &id)).await
    }
}

impl CacheService for StorageSvc {
    async fn store(&self, key: String, bytes: Vec<u8>) -> Result<(), CacheError> {
        self.cache.store(&key, bytes).await
    }

    async fn load(&self, key: String) -> Result<Option<Vec<u8>>, CacheError> {
        self.cache.load(&key).await
    }
}
