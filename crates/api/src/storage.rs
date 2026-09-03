//! The STORAGE boundary: hatch-client `SessionBackend` / `CacheBackend` seams
//! implemented over remoc clients to the trusted storage-CVM, dialed under mutual
//! RA-TLS exactly like the compile/execution workers (see [`crate::executor`]).
//!
//! Not selected by anything: these are the backends api dials at boot, full
//! stop. There is no runtime switch and no second implementation to switch to —
//! `main::build_storage_backends` constructs them unconditionally. The backends
//! live HERE (not in hatch-client) so hatch-client stays remoc-free; api already
//! links remoc + RA-TLS for the workers. All crypto stays in hatch-client's `SessionStore` /
//! `CacheStore` — these move opaque sealed DTOs only.

use std::sync::Arc;

use remoc::codec::Ciborium;

use fleet_transport::LegFailure;
use hatch_client::{BridgeError, CacheBackend, SessionBackend};
use hatch_protocol::{ReadRequest, Slot, WriteRequest};
use safe_logger::debug;
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
    leg: Arc<crate::fleet::Leg<SessionStoreServiceClient<Ciborium>>>,
}

impl SessionCvmBackend {
    pub fn new(leg: Arc<crate::fleet::Leg<SessionStoreServiceClient<Ciborium>>>) -> Self {
        Self { leg }
    }

    /// The client, or the leg's own failure. A request during an outage fails
    /// rather than waits — the health port is already saying which leg is down,
    /// and how long to wait for it is the host's call.
    fn client(&self) -> Result<SessionStoreServiceClient<Ciborium>, BridgeError> {
        self.leg
            .get()
            .ok_or_else(|| BridgeError::Transport("storage-cvm: the leg is down".into()))
    }
}

#[async_trait::async_trait]
impl SessionBackend for SessionCvmBackend {
    async fn read_raw(&self, id: &str, req: ReadRequest) -> Result<(Vec<Slot>, u64), BridgeError> {
        let r = self
            .client()?
            .read(id.to_string(), req)
            .await
            .map_err(to_bridge)?;
        Ok((r.slots, r.version))
    }

    async fn write(
        &self,
        id: &str,
        req: WriteRequest,
        deadline_unix_secs: Option<u64>,
    ) -> Result<u64, BridgeError> {
        match self
            .client()?
            .write(id.to_string(), req, deadline_unix_secs)
            .await
        {
            Ok(r) => Ok(r.new_version),
            Err(SessionError::VersionMismatch) => Err(BridgeError::VersionMismatch),
            Err(e) => Err(to_bridge(e)),
        }
    }

    async fn delete(&self, id: &str) -> Result<u64, BridgeError> {
        Ok(self
            .client()?
            .delete(id.to_string())
            .await
            .map_err(to_bridge)?
            .deleted)
    }

    async fn exists(&self, id: &str) -> Result<bool, BridgeError> {
        self.client()?
            .exists(id.to_string())
            .await
            .map_err(to_bridge)
    }
}

/// `CacheBackend` over the storage-CVM's `CacheService`.
pub struct CacheCvmBackend {
    leg: Arc<crate::fleet::Leg<CacheServiceClient<Ciborium>>>,
}

impl CacheCvmBackend {
    pub fn new(leg: Arc<crate::fleet::Leg<CacheServiceClient<Ciborium>>>) -> Self {
        Self { leg }
    }

    fn client(&self) -> Result<CacheServiceClient<Ciborium>, BridgeError> {
        self.leg
            .get()
            .ok_or_else(|| BridgeError::Transport("storage-cvm: the leg is down".into()))
    }
}

#[async_trait::async_trait]
impl CacheBackend for CacheCvmBackend {
    async fn store(&self, blob_name: &str, bytes: Vec<u8>) -> Result<(), BridgeError> {
        self.client()?
            .store(blob_name.to_string(), bytes)
            .await
            .map_err(to_bridge)
    }

    async fn load(&self, blob_name: &str) -> Result<Option<Vec<u8>>, BridgeError> {
        self.client()?
            .load(blob_name.to_string())
            .await
            .map_err(to_bridge)
    }
}

/// Dial the storage-CVM at `addr`, RA-TLS-handshake + remoc-frame it, and receive
/// BOTH service clients on the base channel. Mirrors `connect_execution_worker`.
pub async fn connect_storage(
    addr: &str,
    attestor: Arc<dyn enclavid_attestation::Attestor>,
) -> Result<(StorageClients, tokio::task::JoinHandle<()>), LegFailure> {
    let stream = fleet_transport::dial(addr).await.map_err(|e| {
        debug!("connect {addr}: {e}");
        LegFailure::Connect(e.kind())
    })?;
    // Mutual RA-TLS: we attest the storage-CVM's cert (pinned measurement) and
    // present our own. A completed handshake proves the peer is the pinned
    // storage-CVM — no CA, no post-handshake window.
    let config = crate::endorsement::fleet_client_config(attestor).map_err(|e| {
        debug!("ra-tls: {e}");
        LegFailure::Attest
    })?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tls = connector
        .connect(enclavid_ra_tls::server_name(), stream)
        .await
        .map_err(|e| {
            debug!("ra-tls: {e}");
            LegFailure::Attest
        })?;
    let (read, write) = tokio::io::split(tls);

    let (conn, _tx, mut rx) = remoc::Connect::io::<_, _, StorageClients, StorageClients, Ciborium>(
        storage_rpc::connection_cfg(),
        read,
        write,
    )
    .await
    .map_err(|e| {
        debug!("rpc connect: {e}");
        LegFailure::Rpc
    })?;
    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });

    let clients = rx
        .recv()
        .await
        .map_err(|e| {
            debug!("recv clients: {e}");
            LegFailure::Clients
        })?
        .ok_or(LegFailure::Closed)?;

    Ok((clients, driver))
}
