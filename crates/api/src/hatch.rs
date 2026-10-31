//! The HATCH leg: api's way out, to the hatch-CVM, dialed under mutual RA-TLS
//! and pinned like every other leg (see [`crate::endorsement`]). The typed
//! clients in `hatch-client` call through it — authorization, pulls, the key
//! broker's legs — at api's end of it, [`Hatch`], and find it down as they find
//! any leg down.

use std::sync::Arc;

use fleet_transport::LegFailure;
use hatch_rpc::HatchLeg;
use safe_logger::debug;

use crate::boundary::Hatch;

impl hatch_client::Link<Hatch> for crate::fleet::Leg<Arc<HatchLeg<Hatch>>> {
    fn leg(&self) -> Option<Arc<HatchLeg<Hatch>>> {
        self.get()
    }
}

/// Dial the hatch-CVM at `addr` and RA-TLS-handshake it. Mirrors
/// `connect_execution_worker`, down to the handle it returns: it finishes when
/// the leg is over, which is the connection ending or the client's channel
/// closing. `leg` is this end of the connection.
pub async fn connect_hatch(
    addr: &str,
    attestor: Arc<dyn enclavid_attestation::Attestor>,
    leg: hatch_rpc::LegSettings,
) -> Result<(Arc<HatchLeg<Hatch>>, tokio::task::JoinHandle<()>), LegFailure> {
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
        .connect(enclavid_ra_tls::fresh_server_name(), stream)
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

    // Everything above this line is WHO — the dial, the pin, what a refusal
    // means. Everything below is WHAT MAY CROSS, and that is hatch-rpc's: it
    // brings the leg up and keeps the generated client, which api has no name
    // for. How api judges what crosses is its end's declaration, `Hatch`.
    let (leg, ended) = hatch_rpc::connect_hatch::<Hatch, _, _>(read, write, &leg)
        .await
        .map_err(|e| {
            debug!("hatch leg: {e}");
            match e {
                hatch_rpc::LegError::Rpc => LegFailure::Rpc,
                hatch_rpc::LegError::Clients | hatch_rpc::LegError::Serve => LegFailure::Clients,
                hatch_rpc::LegError::Closed => LegFailure::Closed,
            }
        })?;
    Ok((Arc::new(leg), ended))
}
