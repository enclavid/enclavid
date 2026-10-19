//! The HATCH leg: api's way out, to the hatch-CVM, dialed under mutual RA-TLS
//! and pinned like every other leg (see [`crate::endorsement`]). The typed
//! clients in `hatch-client` call through it — authorization, pulls, the key
//! broker's legs — and find it down as they find any leg down.

use std::sync::Arc;

use remoc::codec::Ciborium;
use remoc::rtc::Client as _;

use fleet_transport::LegFailure;
use hatch_rpc::HatchClient;
use safe_logger::debug;

impl hatch_client::Link for crate::fleet::Leg<HatchClient> {
    fn client(&self) -> Option<HatchClient> {
        self.get()
    }
}

/// Dial the hatch-CVM at `addr`, RA-TLS-handshake + remoc-frame it, and receive
/// its client on the base channel. Mirrors `connect_storage`, down to the handle
/// it returns: it finishes when the leg is over, which is the connection ending
/// or the client's channel closing (`engine_rpc::leg_end`). `leg` is this end of
/// the connection.
pub async fn connect_hatch(
    addr: &str,
    attestor: Arc<dyn enclavid_attestation::Attestor>,
    leg: hatch_rpc::LegSettings,
) -> Result<(HatchClient, tokio::task::JoinHandle<()>), LegFailure> {
    let stream = fleet_transport::dial(addr).await.map_err(|e| {
        debug!("connect {addr}: {e}");
        LegFailure::Connect(e.kind())
    })?;
    let config = crate::endorsement::fleet_client_config(attestor, crate::health::Peer::Hatch)
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
            match enclavid_ra_tls::pin_mismatch(&e)
                .and_then(|p| fleet_transport::Measurement::parse(&p.presented))
            {
                Some(m) => LegFailure::Pin(m),
                None => LegFailure::Attest,
            }
        })?;
    let (read, write) = tokio::io::split(tls);

    let (conn, _tx, mut rx) = remoc::Connect::io::<_, _, HatchClient, HatchClient, Ciborium>(
        hatch_rpc::connection_cfg(&leg),
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

    let client = rx
        .recv()
        .await
        .map_err(|e| {
            debug!("recv client: {e}");
            LegFailure::Clients
        })?
        .ok_or(LegFailure::Closed)?;
    let closed = client.closed();
    let ended = engine_rpc::leg_end(driver, closed);
    Ok((client, ended))
}
