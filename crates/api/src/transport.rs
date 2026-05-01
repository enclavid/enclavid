//! Inbound listener — single location with the `vsock` feature gate.
//!
//! Default build: TCP listener via `tokio::net::TcpListener`.
//! `vsock` build: vsock listener via `tokio-vsock`.
//!
//! Caller (main) just invokes `serve(app, addr).await` — no feature-specific
//! code elsewhere.

use axum::Router;

/// Binds the inbound listener at `addr` and runs the HTTP server.
///
/// `addr` format is per-transport:
/// - default (TCP): `host:port` — e.g. `0.0.0.0:3000`
/// - `vsock` feature: bare u32 port — e.g. `3000` (bound to `VMADDR_CID_ANY`)
#[cfg(not(feature = "vsock"))]
pub async fn serve(app: Router, addr: &str) {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP listener");
    println!("listening on tcp://{addr}");
    axum::serve(listener, app).await.expect("server error");
}

#[cfg(feature = "vsock")]
pub async fn serve(app: Router, addr: &str) {
    use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

    let port: u32 = addr
        .parse()
        .expect("vsock address must be a u32 port");
    let vsock_addr = VsockAddr::new(VMADDR_CID_ANY, port);
    let listener = VsockListener::bind(&vsock_addr).expect("failed to bind vsock listener");
    println!("listening on vsock://*:{port}");
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
        loop {
            match self.0.accept().await {
                Ok(pair) => return pair,
                Err(e) => {
                    eprintln!("vsock accept error: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.0.local_addr()
    }
}
