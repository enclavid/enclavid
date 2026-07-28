//! The STORAGE boundary: hatch-client `SessionBackend` / `CacheBackend` seams
//! implemented over remoc clients to the trusted storage-CVM, dialed under mutual
//! RA-TLS exactly like the compile/execution workers (see [`crate::executor`]).
//!
//! Selected at boot by `ENCLAVID_STORAGE_BACKEND=storage-cvm` (else api keeps the
//! legacy hatch/Redis + host object_store cache). The backends live HERE (not in
//! hatch-client) so hatch-client stays remoc-free; api already links remoc +
//! RA-TLS for the workers. All crypto stays in hatch-client's `SessionStore` /
//! `CacheStore` — these move opaque sealed DTOs only.

use std::sync::Arc;

use remoc::codec::Ciborium;

use hatch_client::{BridgeError, CacheBackend, SessionBackend};
use hatch_protocol::{ReadRequest, Slot, WriteRequest};
use storage_rpc::{
    CacheService, CacheServiceClient, SessionError, SessionStoreService, SessionStoreServiceClient,
    StorageClients,
};

/// Fold any storage-tier RPC error into the hatch-client transport error the
/// stores expect. `SessionError::VersionMismatch` is handled inline on `write`
/// (it must map to the dedicated `BridgeError::VersionMismatch` the CAS callers
/// branch on); everything else — including every `CacheError` — folds here.
fn to_bridge(e: impl std::fmt::Display) -> BridgeError {
    BridgeError::Transport(format!("storage-cvm: {e}"))
}

/// `SessionBackend` over the storage-CVM's `SessionStoreService`.
pub struct SessionCvmBackend {
    client: SessionStoreServiceClient<Ciborium>,
}

#[async_trait::async_trait]
impl SessionBackend for SessionCvmBackend {
    async fn read_raw(&self, id: &str, req: ReadRequest) -> Result<(Vec<Slot>, u64), BridgeError> {
        let r = self.client.read(id.to_string(), req).await.map_err(to_bridge)?;
        Ok((r.slots, r.version))
    }

    async fn write(
        &self,
        id: &str,
        req: WriteRequest,
        deadline_unix_secs: Option<u64>,
    ) -> Result<u64, BridgeError> {
        match self.client.write(id.to_string(), req, deadline_unix_secs).await {
            Ok(r) => Ok(r.new_version),
            Err(SessionError::VersionMismatch) => Err(BridgeError::VersionMismatch),
            Err(e) => Err(to_bridge(e)),
        }
    }

    async fn delete(&self, id: &str) -> Result<u64, BridgeError> {
        Ok(self.client.delete(id.to_string()).await.map_err(to_bridge)?.deleted)
    }

    async fn exists(&self, id: &str) -> Result<bool, BridgeError> {
        self.client.exists(id.to_string()).await.map_err(to_bridge)
    }
}

/// `CacheBackend` over the storage-CVM's `CacheService`.
pub struct CacheCvmBackend {
    client: CacheServiceClient<Ciborium>,
}

#[async_trait::async_trait]
impl CacheBackend for CacheCvmBackend {
    async fn store(&self, blob_name: &str, bytes: Vec<u8>) -> Result<(), BridgeError> {
        self.client.store(blob_name.to_string(), bytes).await.map_err(to_bridge)
    }

    async fn load(&self, blob_name: &str) -> Result<Option<Vec<u8>>, BridgeError> {
        self.client.load(blob_name.to_string()).await.map_err(to_bridge)
    }
}

/// Dial the storage-CVM at `addr`, RA-TLS-handshake + remoc-frame it, and receive
/// BOTH service clients on the base channel. Mirrors `connect_execution_worker`.
pub async fn connect_storage(
    addr: &str,
) -> Result<(SessionCvmBackend, CacheCvmBackend), String> {
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| format!("connect storage-CVM at `{addr}`: {e}"))?;
    // Mutual RA-TLS: we attest the storage-CVM's cert (pinned measurement) and
    // present our own. A completed handshake proves the peer is the pinned
    // storage-CVM — no CA, no post-handshake window.
    let config = enclavid_ra_tls::fleet_client_config()
        .map_err(|e| format!("storage-CVM RA-TLS client config: {e}"))?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tls = connector
        .connect(enclavid_ra_tls::server_name(), tcp)
        .await
        .map_err(|e| format!("storage-CVM RA-TLS handshake: {e}"))?;
    let (read, write) = tokio::io::split(tls);

    let (conn, _tx, mut rx) = remoc::Connect::io::<_, _, StorageClients, StorageClients, Ciborium>(
        storage_rpc::connection_cfg(),
        read,
        write,
    )
    .await
    .map_err(|e| format!("storage-CVM remoc connect: {e}"))?;
    tokio::spawn(conn);

    let clients = rx
        .recv()
        .await
        .map_err(|e| format!("storage-CVM recv clients: {e}"))?
        .ok_or("storage-CVM closed before sending its service clients")?;

    Ok((
        SessionCvmBackend { client: clients.session },
        CacheCvmBackend { client: clients.cache },
    ))
}
