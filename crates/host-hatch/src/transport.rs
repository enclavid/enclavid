//! Inbound listener — single location with the `vsock` feature gate.
//!
//! Default build: TCP listener. `vsock` build: vsock listener bound to
//! `VMADDR_CID_ANY` — the guest CVM dials it — taking calls only from the
//! guests `HATCH_FROM` names. Mirrors the TEE-side
//! `crates/api/src/transport.rs` adapter so both ends share the shape.

use axum::Router;

/// Binds the inbound listener at `addr` and runs the HTTP server.
///
/// - default (TCP): `host:port` — e.g. `0.0.0.0:8000`
/// - `vsock` feature: bare u32 port — e.g. `8000` (bound to `VMADDR_CID_ANY`)
#[cfg(not(feature = "vsock"))]
pub async fn serve(app: Router, addr: &str) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP listener");
    println!("hatch listening on tcp://{addr}");
    axum::serve(listener, app).await.expect("server error");
    Ok(())
}

#[cfg(feature = "vsock")]
pub async fn serve(app: Router, addr: &str) -> anyhow::Result<()> {
    use anyhow::Context;
    use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};

    let port: u32 = addr.parse().expect("vsock address must be a u32 port");
    let from = guests(&crate::required_env("HATCH_FROM")?).context(
        "HATCH_FROM: the context IDs of the guests the hatch takes calls from, comma-separated",
    )?;
    let vsock_addr = VsockAddr::new(VMADDR_CID_ANY, port);
    let listener = VsockListener::bind(vsock_addr).expect("failed to bind vsock listener");
    println!("hatch listening on vsock://*:{port}, from {from:?}");
    axum::serve(VsockServeListener { listener, from }, app)
        .await
        .expect("server error");
    Ok(())
}

/// The guests a setting names, by context ID, comma-separated. Below 3 are the
/// hypervisor, the local loopback and the host, and `u32::MAX` is the ANY
/// sentinel: none of them is a guest, so naming one is a mistake.
#[cfg_attr(not(feature = "vsock"), allow(dead_code))]
fn guests(setting: &str) -> anyhow::Result<Vec<u32>> {
    setting
        .split(',')
        .map(|cid| match cid.parse::<u32>() {
            Ok(cid) if (3..u32::MAX).contains(&cid) => Ok(cid),
            _ => anyhow::bail!("`{cid}` is not a guest's context ID (3 to 4294967294)"),
        })
        .collect()
}

/// Adapter implementing `axum::serve::Listener` on top of
/// `tokio_vsock::VsockListener`, taking calls from `from` alone.
#[cfg(feature = "vsock")]
struct VsockServeListener {
    listener: tokio_vsock::VsockListener,
    from: Vec<u32>,
}

#[cfg(feature = "vsock")]
impl axum::serve::Listener for VsockServeListener {
    type Io = tokio_vsock::VsockStream;
    type Addr = tokio_vsock::VsockAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.listener.accept().await {
                Ok((stream, caller)) if self.from.contains(&caller.cid()) => {
                    return (stream, caller);
                }
                // Dropping it closes it, as the guest will see.
                Ok((_, caller)) => {
                    tracing::warn!(
                        guest = caller.cid(),
                        "refused a call from a guest HATCH_FROM does not name"
                    );
                }
                Err(e) => handle_accept_error(e).await,
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

/// What axum does for the listener types it ships an impl for, applied to the
/// one it does not.
///
/// A copy rather than a shared function, and the reason is which side of the
/// machine this runs on: the guests keep the same policy in `fleet-transport`,
/// but depending on that crate from here would pull their logger in with its
/// outward tier switched on — an edge a host binary has no use for and should
/// not grow. Upstream is the thing to stay in step with here, not the TEE.
#[cfg(feature = "vsock")]
async fn handle_accept_error(e: std::io::Error) {
    use std::io::ErrorKind;

    // The peer went away between its connect and this accept. The queued entry
    // went with it, so the next accept finds the queue shorter and parks
    // normally: try again at once, and say nothing — the far end is a guest
    // whose connection died, which it sees for itself.
    if matches!(
        e.kind(),
        ErrorKind::ConnectionRefused | ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset
    ) {
        return;
    }
    // Descriptors or memory: the accept could not be performed at all and the
    // connection is STILL queued, so the listener stays readable and the next
    // attempt fails identically and immediately. Without this delay that is a
    // spin, and the guests on the other side of it see only a hatch that has
    // stopped answering.
    tracing::error!(err = %e, "vsock accept failed; retrying");
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
}

#[cfg(test)]
mod tests {
    use super::guests;

    #[test]
    fn the_callers_are_guests_named_by_context_id() {
        assert_eq!(guests("3").unwrap(), [3]);
        assert_eq!(guests("3,13").unwrap(), [3, 13]);
        // The hypervisor, the loopback, the host, the ANY sentinel, and
        // nothing at all.
        for bad in ["0", "1", "2", "4294967295", "", "3,", "3, 13", "api"] {
            assert!(guests(bad).is_err(), "`{bad}` should not parse");
        }
    }
}
