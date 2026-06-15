//! HTTP-over-vsock transport for the broker client.
//!
//! One shared request path (`hyper::client::conn::http1` handshake per
//! request) with only the stream connect cfg-split: TCP for dev / CI,
//! vsock for the attested production build. Per-request connect (no
//! pool) keeps the cfg surface to a single line — the rest of the
//! request/response machinery is exercised by the default (TCP) build.
//!
//! External callers see only `connect_store(addr) -> BrokerChannel` and
//! the `BrokerChannel` post/head/delete methods — they never learn which
//! transport is active.

#[cfg(all(feature = "vsock", not(target_os = "linux")))]
compile_error!(
    "feature `vsock` requires Linux — tokio-vsock uses AF_VSOCK which exists \
     only in the Linux kernel. Build without `--features vsock` for \
     non-Linux dev environments, or run the build inside a Linux container."
);

use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::header::{CONTENT_TYPE, HOST};
use hyper_util::rt::TokioIo;

use crate::error::BridgeError;

/// Dummy authority for the `Host` header. The transport is
/// point-to-point over an already-established connection, so the
/// authority is cosmetic — the connect target is fixed by the channel.
const AUTHORITY: &str = "broker.local";

/// A connection target for the broker. Cheap to clone; holds only the
/// connect parameters (each request opens a fresh connection).
#[derive(Clone)]
pub struct BrokerChannel {
    #[cfg(not(feature = "vsock"))]
    addr: String,
    #[cfg(feature = "vsock")]
    cid: u32,
    #[cfg(feature = "vsock")]
    port: u32,
}

/// A broker HTTP response: status code + body bytes. Non-2xx is NOT an
/// error here — callers branch on `status` (412 → VersionMismatch,
/// 404 → NotFound, 401/403 → auth verdict, …).
pub struct HttpResp {
    pub status: u16,
    pub body: Vec<u8>,
}

impl BrokerChannel {
    /// POST a CBOR body to `path`.
    pub async fn post(&self, path: &str, body: Vec<u8>) -> Result<HttpResp, BridgeError> {
        self.request("POST", path, body).await
    }

    /// DELETE `path` (no body).
    pub async fn delete(&self, path: &str) -> Result<HttpResp, BridgeError> {
        self.request("DELETE", path, Vec::new()).await
    }

    /// HEAD `path` — returns just the status code.
    pub async fn head(&self, path: &str) -> Result<u16, BridgeError> {
        Ok(self.request("HEAD", path, Vec::new()).await?.status)
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Vec<u8>,
    ) -> Result<HttpResp, BridgeError> {
        let io = self.connect().await?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| BridgeError::Transport(format!("handshake: {e}")))?;
        // Drive the connection in the background; it ends when the
        // request completes and the sender is dropped.
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = Request::builder()
            .method(method)
            .uri(path)
            .header(HOST, AUTHORITY)
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(Full::new(bytes::Bytes::from(body)))
            .map_err(|e| BridgeError::Transport(format!("build request: {e}")))?;

        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| BridgeError::Transport(format!("send: {e}")))?;
        let status = resp.status().as_u16();
        let collected = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| BridgeError::Transport(format!("body: {e}")))?;
        Ok(HttpResp {
            status,
            body: collected.to_bytes().to_vec(),
        })
    }

    #[cfg(not(feature = "vsock"))]
    async fn connect(&self) -> Result<TokioIo<tokio::net::TcpStream>, BridgeError> {
        let stream = tokio::net::TcpStream::connect(&self.addr)
            .await
            .map_err(|e| BridgeError::Transport(format!("connect {}: {e}", self.addr)))?;
        Ok(TokioIo::new(stream))
    }

    #[cfg(feature = "vsock")]
    async fn connect(&self) -> Result<TokioIo<tokio_vsock::VsockStream>, BridgeError> {
        use tokio_vsock::{VsockAddr, VsockStream};
        let stream = VsockStream::connect(&VsockAddr::new(self.cid, self.port))
            .await
            .map_err(|e| {
                BridgeError::Transport(format!("vsock connect {}:{}: {e}", self.cid, self.port))
            })?;
        Ok(TokioIo::new(stream))
    }
}

/// Build a channel to the broker.
///
/// `addr` format is per-transport; opaque to callers:
/// - default (TCP): `http://host:port` — e.g. `http://10.0.0.10:8000`
/// - `vsock` feature: `vsock://CID:PORT` — e.g. `vsock://2:8000`
///
/// No connection is opened here — each request connects fresh. Async +
/// `Result` kept for signature stability and to validate the address.
#[cfg(not(feature = "vsock"))]
pub async fn connect_store(addr: &str) -> Result<BrokerChannel, BridgeError> {
    let addr = addr.strip_prefix("http://").unwrap_or(addr).to_string();
    if addr.is_empty() {
        return Err(BridgeError::Transport("empty broker address".to_string()));
    }
    Ok(BrokerChannel { addr })
}

#[cfg(feature = "vsock")]
pub async fn connect_store(addr: &str) -> Result<BrokerChannel, BridgeError> {
    let (cid, port) = parse_vsock(addr)?;
    Ok(BrokerChannel { cid, port })
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
