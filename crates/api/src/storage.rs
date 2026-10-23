//! The STORAGE leg: api's one durable store, the storage-CVM, dialed under
//! mutual RA-TLS and pinned like every other leg (see [`crate::endorsement`]).
//! storage-client's stores call through it — every seal and open is theirs — at
//! api's end of it, `storage_client::boundary::Storage`, declared there beside
//! the seals, and find it down as they find any leg down.

use std::sync::Arc;

use fleet_transport::LegFailure;
use safe_logger::debug;
use storage_client::boundary::Storage;
use storage_rpc::StorageLeg;

impl storage_client::Link for crate::fleet::Leg<Arc<StorageLeg<Storage>>> {
    fn leg(&self) -> Option<Arc<StorageLeg<Storage>>> {
        self.get()
    }
}

/// Dial the storage-CVM at `addr` and RA-TLS-handshake it. Mirrors
/// `connect_execution_worker`, down to the handle it returns: it finishes when
/// the leg is over, which is the connection ending or either of its two
/// clients' channels closing. `leg` is this end of the connection.
pub async fn connect_storage(
    addr: &str,
    attestor: Arc<dyn enclavid_attestation::Attestor>,
    leg: storage_rpc::LegSettings,
) -> Result<(Arc<StorageLeg<Storage>>, tokio::task::JoinHandle<()>), LegFailure> {
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

    // Everything above this line is WHO — the dial, the pin, what a refusal
    // means. Everything below is WHAT MAY CROSS, and that is storage-rpc's: it
    // brings the leg up and keeps the generated clients, which api has no name
    // for. How api judges what crosses is its end's declaration, `Storage`.
    let (leg, ended) = storage_rpc::connect_storage::<Storage, _, _>(read, write, &leg)
        .await
        .map_err(|e| {
            debug!("storage leg: {e}");
            match e {
                storage_rpc::LegError::Rpc => LegFailure::Rpc,
                storage_rpc::LegError::Clients | storage_rpc::LegError::Serve => {
                    LegFailure::Clients
                }
                storage_rpc::LegError::Closed => LegFailure::Closed,
            }
        })?;
    Ok((Arc::new(leg), ended))
}
