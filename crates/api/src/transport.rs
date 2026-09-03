//! Inbound listener — single location with the `vsock` feature gate.
//!
//! Default build: TCP listener via `tokio::net::TcpListener`.
//! `vsock` build: vsock listener via `tokio-vsock`.
//!
//! Caller (main) just invokes `serve(app, addr).await` — no feature-specific
//! code elsewhere.

use axum::Router;
use safe_logger::{info, reason, safe};

/// Binds the inbound listener at `addr` and runs the HTTP server.
///
/// `addr` format is per-transport:
/// - default (TCP): `host:port` — e.g. `0.0.0.0:3000`
/// - `vsock` feature: bare u32 port — e.g. `3000` (bound to `VMADDR_CID_ANY`)
///
/// `bound` fires once the listener exists and before the first accept. It is
/// what lets `main` set the health port's `healthy` field on the same terms a
/// leaf sets its own — after the bind, not after the spawn. Dropped without a
/// send only if this function panics, which is the bind failing, which ends the
/// process.
#[cfg(not(feature = "vsock"))]
pub async fn serve(app: Router, addr: &str, bound: tokio::sync::oneshot::Sender<()>) {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP listener");
    info!(
        "api: listening on tcp://{}",
        safe(
            &addr,
            reason!("a listen address from this process's environment")
        ),
        reason!("a constant, emitted once at boot before any session exists")
    );
    let _ = bound.send(());
    axum::serve(listener, app).await.expect("server error");
}

#[cfg(feature = "vsock")]
pub async fn serve(app: Router, addr: &str, bound: tokio::sync::oneshot::Sender<()>) {
    use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};

    let port: u32 = addr.parse().expect("vsock address must be a u32 port");
    let vsock_addr = VsockAddr::new(VMADDR_CID_ANY, port);
    let listener = VsockListener::bind(vsock_addr).expect("failed to bind vsock listener");
    info!(
        "api: listening on vsock://*:{}",
        safe(&port, reason!("on the measured command line")),
        reason!("a constant, emitted once at boot before any session exists")
    );
    let _ = bound.send(());
    axum::serve(VsockServeListener(listener), app)
        .await
        .expect("server error");
}

/// Adapter implementing `axum::serve::Listener` on top of
/// `tokio_vsock::VsockListener`. Private to this module.
#[cfg(feature = "vsock")]
struct VsockServeListener(tokio_vsock::VsockListener);

#[cfg(feature = "vsock")]
impl axum::serve::Listener for VsockServeListener {
    type Io = tokio_vsock::VsockStream;
    type Addr = tokio_vsock::VsockAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        // The loop exists because `axum::serve::Listener::accept` returns no
        // `Result` — its own doc says an impl "must take care of logging and
        // retrying". So the retry policy is this adapter's to supply, and it is
        // the same one the roles' own accept loops run.
        //
        // It comes from `fleet_transport` rather than being written again here.
        // What cannot be shared is the loop: `accept_forever` never returns and
        // consumes each connection through a callback, where this has to hand
        // ONE back per call. The decision is shareable, and the decision is the
        // part that was being duplicated.
        loop {
            match self.0.accept().await {
                Ok(pair) => return pair,
                Err(e) => fleet_transport::after_accept_error(&e).await,
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.0.local_addr()
    }
}
