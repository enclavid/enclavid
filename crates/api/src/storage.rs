//! The STORAGE boundary: storage-client `SessionBackend` / `CacheBackend` seams
//! implemented over remoc clients to the trusted storage-CVM, dialed under mutual
//! RA-TLS exactly like the compile/execution workers (see [`crate::executor`]).
//!
//! Not selected by anything: these are the backends api dials at boot, full
//! stop. There is no runtime switch and no second implementation to switch to —
//! `main::build_storage_backends` constructs them unconditionally. The backends
//! live HERE, beside the leg they run over. All crypto stays in storage-client's
//! `SessionStore` / `CacheStore` — these move opaque sealed DTOs only.

use std::sync::Arc;

use futures::{StreamExt, TryStreamExt};
use remoc::codec::Ciborium;
use remoc::rtc::Client as _;

use fleet_stream::{Incoming, StreamLen, bin};
use fleet_transport::LegFailure;
use safe_logger::debug;
use storage_client::{BlobPieces, CacheBackend, SessionBackend, StoreError};
use storage_rpc::{
    CACHE_STREAM_DEADLINE, CACHE_STREAM_IDLE, CacheBlob, CacheService, CacheServiceClient,
    ReadRequest, SessionError, SessionStoreService, SessionStoreServiceClient, Slot,
    StorageClients, WriteRequest,
};

/// Fold any storage-tier RPC error into the transport error the stores
/// expect. `SessionError::VersionMismatch` is handled inline on `write`
/// (it must map to the dedicated `StoreError::VersionMismatch` the CAS callers
/// branch on); everything else — including every `CacheError` — folds here.
fn to_store(e: impl std::fmt::Display) -> StoreError {
    StoreError::Transport(format!("storage-cvm: {e}"))
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
    fn client(&self) -> Result<SessionStoreServiceClient<Ciborium>, StoreError> {
        self.leg
            .get()
            .ok_or_else(|| StoreError::Transport("storage-cvm: the leg is down".into()))
    }
}

#[async_trait::async_trait]
impl SessionBackend for SessionCvmBackend {
    async fn read_raw(&self, id: &str, req: ReadRequest) -> Result<(Vec<Slot>, u64), StoreError> {
        let r = self
            .client()?
            .read(id.to_string(), req)
            .await
            .map_err(to_store)?;
        Ok((r.slots, r.version))
    }

    async fn write(
        &self,
        id: &str,
        req: WriteRequest,
        deadline_unix_secs: Option<u64>,
    ) -> Result<u64, StoreError> {
        match self
            .client()?
            .write(id.to_string(), req, deadline_unix_secs)
            .await
        {
            Ok(r) => Ok(r.new_version),
            Err(SessionError::VersionMismatch) => Err(StoreError::VersionMismatch),
            Err(e) => Err(to_store(e)),
        }
    }

    async fn exists(&self, id: &str) -> Result<bool, StoreError> {
        self.client()?
            .exists(id.to_string())
            .await
            .map_err(to_store)
    }
}

/// `CacheBackend` over the storage-CVM's `CacheService`. Every blob streams
/// beside its call, so no call carries one: a blob of any size crosses without
/// coming near remoc's item limit, and one that fails ends its own stream and
/// nothing else on the connection the session store shares.
pub struct CacheCvmBackend {
    leg: Arc<crate::fleet::Leg<CacheServiceClient<Ciborium>>>,
}

impl CacheCvmBackend {
    pub fn new(leg: Arc<crate::fleet::Leg<CacheServiceClient<Ciborium>>>) -> Self {
        Self { leg }
    }

    fn client(&self) -> Result<CacheServiceClient<Ciborium>, StoreError> {
        self.leg
            .get()
            .ok_or_else(|| StoreError::Transport("storage-cvm: the leg is down".into()))
    }
}

#[async_trait::async_trait]
impl CacheBackend for CacheCvmBackend {
    async fn store(
        &self,
        blob_name: &str,
        length: u64,
        pieces: BlobPieces,
    ) -> Result<(), StoreError> {
        let length = StreamLen::new(length).ok_or_else(|| {
            StoreError::Transport(
                "storage-cvm: a blob past what the leg carries; not stored".into(),
            )
        })?;
        let (tx, body) = bin::channel();
        let client = self.client()?;
        let mut call =
            std::pin::pin!(client.store(blob_name.to_string(), CacheBlob { length, body }));
        // The store answers once the blob has arrived, so the pieces are written
        // while it is awaited. One that fails abandons the blob, and the store
        // answers that; a store that answers first has stopped reading.
        let reply = tokio::select! {
            reply = &mut call => reply,
            _ = fleet_stream::send_from(tx, pieces) => call.await,
        };
        reply.map_err(to_store)
    }

    async fn load(&self, blob_name: &str) -> Result<Option<(u64, BlobPieces)>, StoreError> {
        let Some(blob) = self
            .client()?
            .load(blob_name.to_string())
            .await
            .map_err(to_store)?
        else {
            return Ok(None);
        };
        let length = blob.length.get();
        let pieces = Incoming::open(blob.body, length, CACHE_STREAM_IDLE)
            .await
            .map_err(to_store)?
            .into_pieces(CACHE_STREAM_DEADLINE, None)
            .map_err(to_store);
        Ok(Some((length, pieces.boxed())))
    }

    async fn remove(&self, blob_name: &str) -> Result<(), StoreError> {
        self.client()?
            .remove(blob_name.to_string())
            .await
            .map_err(to_store)
    }
}

/// Dial the storage-CVM at `addr`, RA-TLS-handshake + remoc-frame it, and receive
/// BOTH service clients on the base channel. Mirrors `connect_execution_worker`,
/// down to the handle it returns: it finishes when the leg is over, which is the
/// connection ending or either client's channel closing (`engine_rpc::leg_end`).
/// `leg` is this end of the connection.
pub async fn connect_storage(
    addr: &str,
    attestor: Arc<dyn enclavid_attestation::Attestor>,
    leg: storage_rpc::LegSettings,
) -> Result<(StorageClients, tokio::task::JoinHandle<()>), LegFailure> {
    let stream = fleet_transport::dial(addr).await.map_err(|e| {
        debug!("connect {addr}: {e}");
        LegFailure::Connect(e.kind())
    })?;
    // Mutual RA-TLS: we attest the storage-CVM's cert (pinned measurement) and
    // present our own. A completed handshake proves the peer is the pinned
    // storage-CVM — no CA, no post-handshake window.
    let config = crate::endorsement::fleet_client_config(attestor, crate::health::Peer::Storage)
        .map_err(|e| {
            debug!("ra-tls: {e}");
            LegFailure::Mint
        })?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tls = connector
        .connect(enclavid_ra_tls::server_name(), stream)
        .await
        .map_err(|e| {
            debug!("ra-tls: {e}");
            // A peer that attested to the wrong image is the failure this fleet
            // is most likely to see, and the one `Attest` said least about.
            match enclavid_ra_tls::pin_mismatch(&e)
                .and_then(|p| fleet_transport::Measurement::parse(&p.presented))
            {
                Some(m) => LegFailure::Pin(m),
                None => LegFailure::Attest,
            }
        })?;
    let (read, write) = tokio::io::split(tls);

    let (conn, _tx, mut rx) = remoc::Connect::io::<_, _, StorageClients, StorageClients, Ciborium>(
        storage_rpc::connection_cfg(&leg),
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

    // Two request channels on the one connection, and the leg is over when
    // either closes: they are installed and torn down together.
    let (session_closed, cache_closed) = (clients.session.closed(), clients.cache.closed());
    let ended = engine_rpc::leg_end(driver, async move {
        tokio::select! {
            () = session_closed => {}
            () = cache_closed => {}
        }
    });

    Ok((clients, ended))
}
