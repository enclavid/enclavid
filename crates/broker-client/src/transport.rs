//! HTTP transport for the broker client — a pooled `hyper-util`
//! `legacy::Client` with a cfg-split connector.
//!
//! - default (TCP, dev/CI): the built-in `HttpConnector`.
//! - `vsock` feature (attested build): a small custom connector that
//!   dials a fixed `(cid, port)` over `AF_VSOCK`.
//!
//! Same `Client` type and the same request path both ways — only the
//! connector differs. Connection reuse comes free from the pool. The
//! `BrokerClient` handle is what external callers (`api` state wiring)
//! hold; `BrokerClient::new` builds it.

#[cfg(all(feature = "vsock", not(target_os = "linux")))]
compile_error!(
    "feature `vsock` requires Linux — tokio-vsock uses AF_VSOCK which exists \
     only in the Linux kernel. Build without `--features vsock` for \
     non-Linux dev environments, or run the build inside a Linux container."
);

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::CONTENT_TYPE;
use hyper::{Request, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::error::BridgeError;

#[cfg(not(feature = "vsock"))]
type Connector = hyper_util::client::legacy::connect::HttpConnector;
#[cfg(feature = "vsock")]
type Connector = vsock::VsockConnector;

type HttpClient = Client<Connector, Full<Bytes>>;

/// A pooled connection to the broker. Cheap to clone (the `Client`
/// shares its connection pool across clones).
#[derive(Clone)]
pub struct BrokerClient {
    client: HttpClient,
    /// Absolute-URI prefix. For TCP this is `http://host:port` and the
    /// `HttpConnector` dials it; for vsock it's a fixed dummy authority
    /// (the connector ignores it and dials the configured cid/port),
    /// which also keys the connection pool.
    base: String,
}

/// A broker HTTP response: status code + body bytes. Non-2xx is NOT an
/// error here — callers branch on `status` (412 → VersionMismatch,
/// 404 → NotFound, 401/403 → auth verdict, …).
pub(crate) struct HttpResp {
    pub(crate) status: StatusCode,
    pub(crate) body: Vec<u8>,
}

impl BrokerClient {
    /// Build a pooled client for the broker.
    ///
    /// `addr` format is per-transport; opaque to callers:
    /// - default (TCP): `http://host:port` — e.g. `http://10.0.0.10:8000`
    /// - `vsock` feature: `vsock://CID:PORT` — e.g. `vsock://2:8000`
    ///
    /// No connection is opened here — the pool connects lazily on first
    /// request. Async + `Result` kept for signature stability and to
    /// validate the address.
    #[cfg(not(feature = "vsock"))]
    pub async fn new(addr: &str) -> Result<Self, BridgeError> {
        if addr.is_empty() {
            return Err(BridgeError::Transport("empty broker address".to_string()));
        }
        // The HttpConnector dials the request URI's authority, so
        // requests must carry an absolute `http://host:port` URI.
        let base = if addr.starts_with("http://") {
            addr.to_string()
        } else {
            format!("http://{addr}")
        };
        let client = Client::builder(TokioExecutor::new()).build(Connector::new());
        Ok(Self { client, base })
    }

    /// Build a pooled client for the broker over `AF_VSOCK`. `addr` is
    /// `vsock://CID:PORT`. Lazy: no connection until the first request.
    #[cfg(feature = "vsock")]
    pub async fn new(addr: &str) -> Result<Self, BridgeError> {
        let (cid, port) = parse_vsock(addr)?;
        let client =
            Client::builder(TokioExecutor::new()).build(vsock::VsockConnector { cid, port });
        // Dummy authority — the connector ignores it and dials cid/port;
        // it also keys the connection pool (all requests share one origin).
        Ok(Self {
            client,
            base: "http://vsock.invalid".to_string(),
        })
    }

    // The wire verbs are `pub(crate)`, NOT `pub`: a `BrokerClient` is an
    // opaque handle external crates (`api`) may hold and pass into a
    // typed client constructor, but they must NOT be able to push raw
    // bytes onto the wire directly — that would bypass the
    // `boundary::outbound` egress gate (the `Exposed<T, ()>` → bytes
    // release). The only callers are this crate's typed clients
    // (`SessionStore` / `AuthClient` / `RegistryClient`), each of which
    // crosses the boundary before reaching here.

    /// POST raw bytes to `path`.
    ///
    /// The transport is a dumb byte mover — it is intentionally unaware
    /// of the boundary `Exposed` wrapper and the CBOR codec. The egress
    /// gate (a fully-vouched `Exposed<T, ()>`, released to bytes via
    /// `into_inner` + encode) lives one level up in the typed clients,
    /// which are the only things that should feed this method.
    pub(crate) async fn post(&self, path: &str, body: Vec<u8>) -> Result<HttpResp, BridgeError> {
        self.request("POST", path, body).await
    }

    /// DELETE `path` (no body).
    pub(crate) async fn delete(&self, path: &str) -> Result<HttpResp, BridgeError> {
        self.request("DELETE", path, Vec::new()).await
    }

    /// HEAD `path` — returns just the status code.
    pub(crate) async fn head(&self, path: &str) -> Result<StatusCode, BridgeError> {
        Ok(self.request("HEAD", path, Vec::new()).await?.status)
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Vec<u8>,
    ) -> Result<HttpResp, BridgeError> {
        let uri = format!("{}{}", self.base, path);
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| BridgeError::Transport(format!("build request: {e}")))?;

        let resp = self
            .client
            .request(req)
            .await
            .map_err(|e| BridgeError::Transport(format!("request: {e}")))?;
        let status = resp.status();
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

/// Custom vsock connector for hyper-util's pooled `Client`.
///
/// hyper-util's `Connect` is auto-implemented for any
/// `tower_service::Service<Uri>` whose response IO implements
/// `Connection + hyper::rt::Read + Write`. `TokioIo<VsockStream>` covers
/// Read/Write but not `Connection`, so `VsockIo` newtypes it to add the
/// `Connection` impl. The connector ignores the request URI and always
/// dials the configured `(cid, port)`.
#[cfg(feature = "vsock")]
mod vsock {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use hyper::Uri;
    use hyper::rt::{Read, ReadBufCursor, Write};
    use hyper_util::client::legacy::connect::{Connected, Connection};
    use hyper_util::rt::TokioIo;
    use tokio_vsock::{VsockAddr, VsockStream};
    use tower_service::Service;

    #[derive(Clone)]
    pub struct VsockConnector {
        pub cid: u32,
        pub port: u32,
    }

    impl Service<Uri> for VsockConnector {
        type Response = VsockIo;
        type Error = std::io::Error;
        type Future = Pin<Box<dyn Future<Output = Result<VsockIo, std::io::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _uri: Uri) -> Self::Future {
            let addr = VsockAddr::new(self.cid, self.port);
            Box::pin(async move {
                let stream = VsockStream::connect(&addr).await?;
                Ok(VsockIo(TokioIo::new(stream)))
            })
        }
    }

    /// `TokioIo<VsockStream>` plus the `Connection` impl hyper-util's
    /// connector contract requires.
    pub struct VsockIo(TokioIo<VsockStream>);

    impl Connection for VsockIo {
        fn connected(&self) -> Connected {
            Connected::new()
        }
    }

    impl Read for VsockIo {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: ReadBufCursor<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl Write for VsockIo {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }
}
