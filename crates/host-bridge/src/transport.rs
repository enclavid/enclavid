//! Transport selection for store gRPC client.
//!
//! Single location with the `vsock` feature gate. External callers see only
//! the `connect_store(addr) -> GrpcChannel` surface — they never learn which
//! transport is active.

#[cfg(all(feature = "vsock", not(target_os = "linux")))]
compile_error!(
    "feature `vsock` requires Linux — tokio-vsock uses AF_VSOCK which exists \
     only in the Linux kernel. Build without `--features vsock` for \
     non-Linux dev environments, or run the build inside a Linux container."
);

use tonic::transport::Channel;

use crate::error::BridgeError;

pub use tonic::transport::Channel as GrpcChannel;

/// Connects to the store gRPC server.
///
/// `addr` format is per-transport; opaque to callers:
/// - default (TCP): `http://host:port` — e.g. `http://10.0.0.10:50051`
/// - `vsock` feature: `vsock://CID:PORT` — e.g. `vsock://2:50051`
#[cfg(not(feature = "vsock"))]
pub async fn connect_store(addr: &str) -> Result<GrpcChannel, BridgeError> {
    let channel = Channel::from_shared(addr.to_string())
        .map_err(|e| BridgeError::Transport(e.to_string()))?
        .connect()
        .await?;
    Ok(channel)
}

#[cfg(feature = "vsock")]
pub async fn connect_store(addr: &str) -> Result<GrpcChannel, BridgeError> {
    use hyper_util::rt::TokioIo;
    use tokio_vsock::{VsockAddr, VsockStream};
    use tonic::transport::Endpoint;
    use tower::service_fn;

    let (cid, port) = parse_vsock(addr)?;

    let channel = Endpoint::try_from("http://[::]:50051")
        .map_err(|e| BridgeError::Transport(e.to_string()))?
        .connect_with_connector(service_fn(move |_| async move {
            let stream = VsockStream::connect(&VsockAddr::new(cid, port))
                .await
                .map_err(std::io::Error::other)?;
            Ok::<_, std::io::Error>(TokioIo::new(stream))
        }))
        .await
        .map_err(|e| BridgeError::Transport(e.to_string()))?;
    Ok(channel)
}

#[cfg(feature = "vsock")]
fn parse_vsock(addr: &str) -> Result<(u32, u32), BridgeError> {
    let rest = addr
        .strip_prefix("vsock://")
        .ok_or_else(|| BridgeError::Transport(format!("expected vsock://CID:PORT, got {addr}")))?;
    let (cid, port) = rest
        .split_once(':')
        .ok_or_else(|| BridgeError::Transport(format!("expected vsock://CID:PORT, got {addr}")))?;
    let cid: u32 = cid
        .parse()
        .map_err(|_| BridgeError::Transport(format!("invalid vsock CID: {cid}")))?;
    let port: u32 = port
        .parse()
        .map_err(|_| BridgeError::Transport(format!("invalid vsock port: {port}")))?;
    Ok((cid, port))
}

