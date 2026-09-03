//! HTTP transport for the hatch client — a pooled `hyper-util`
//! `legacy::Client` with a cfg-split connector.
//!
//! - default (TCP, dev/CI): the built-in `HttpConnector`.
//! - `vsock` feature (attested build): a small custom connector that
//!   dials a fixed `(cid, port)` over `AF_VSOCK`.
//!
//! Same `Client` type and the same request path both ways — only the
//! connector differs. Connection reuse comes free from the pool. The
//! `HatchClient` handle is what external callers (`api` state wiring)
//! hold; `HatchClient::new` builds it.

#[cfg(all(feature = "vsock", not(target_os = "linux")))]
compile_error!(
    "feature `vsock` requires Linux — tokio-vsock uses AF_VSOCK which exists \
     only in the Linux kernel. Build without `--features vsock` for \
     non-Linux dev environments, or run the build inside a Linux container."
);

use std::time::Duration;

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

/// A pooled connection to the hatch. Cheap to clone (the `Client`
/// shares its connection pool across clones).
#[derive(Clone)]
pub struct HatchClient {
    client: HttpClient,
    /// Absolute-URI prefix. For TCP this is `http://host:port` and the
    /// `HttpConnector` dials it; for vsock it's a fixed dummy authority
    /// (the connector ignores it and dials the configured cid/port),
    /// which also keys the connection pool.
    base: String,
}

/// A hatch HTTP response: status code + body bytes. Non-2xx is NOT an
/// error here — callers branch on `status` (412 → VersionMismatch,
/// 404 → NotFound, 401/403 → auth verdict, …).
pub(crate) struct HttpResp {
    pub(crate) status: StatusCode,
    pub(crate) body: Vec<u8>,
}

impl HatchClient {
    /// Build a pooled client for the hatch.
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
            return Err(BridgeError::Transport("empty hatch address".to_string()));
        }
        // The HttpConnector dials the request URI's authority, so
        // requests must carry an absolute `http://host:port` URI.
        let base = if addr.starts_with("http://") {
            addr.to_string()
        } else {
            format!("http://{addr}")
        };
        let client = Client::builder(TokioExecutor::new())
            // Don't keep idle connections pooled. The TEE↔host control
            // link sits idle for seconds between calls — e.g. policy
            // compile+run between an OCI pull and the state write. The
            // hatch's keep-alive can close a pooled connection during
            // that gap; reusing it then fails with a `SendRequest`
            // transport error (request never sent). A fresh connection
            // per call removes the race — cheap on a local TCP / vsock link.
            .pool_max_idle_per_host(0)
            .build(Connector::new());
        Ok(Self { client, base })
    }

    /// Build a pooled client for the hatch over `AF_VSOCK`. `addr` is
    /// `vsock://CID:PORT`. Lazy: no connection until the first request.
    #[cfg(feature = "vsock")]
    pub async fn new(addr: &str) -> Result<Self, BridgeError> {
        let (cid, port) = parse_vsock(addr)?;
        // No idle pooling — same rationale as the TCP path: avoid reusing
        // a connection the hatch closed during a slow gap between calls.
        let client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(0)
            .build(vsock::VsockConnector { cid, port });
        // Dummy authority — the connector ignores it and dials cid/port;
        // it also keys the connection pool (all requests share one origin).
        Ok(Self {
            client,
            base: "http://vsock.invalid".to_string(),
        })
    }

    // `post` is `pub(crate)`, NOT `pub`: a `HatchClient` is an opaque
    // handle external crates (`api`) may hold and pass into a typed
    // client constructor, but they must NOT be able to push raw bytes
    // onto the wire directly — that would bypass the `boundary::outbound`
    // egress gate (the `Exposed<T, ()>` → bytes release). The only
    // callers are this crate's typed EGRESS clients (`AuthClient` /
    // `RegistryClient` / `KbsClient`), each of which crosses the boundary
    // before reaching here. (Durable sealed state — sessions + L2 cache —
    // no longer rides the hatch; it went to the storage-CVM seam.)

    /// POST raw bytes to `path`, giving up after `deadline`.
    ///
    /// The transport is a dumb byte mover — it is intentionally unaware
    /// of the boundary `Exposed` wrapper and the CBOR codec. The egress
    /// gate (a fully-vouched `Exposed<T, ()>`, released to bytes via
    /// `into_inner` + encode) lives one level up in the typed clients,
    /// which are the only things that should feed this method.
    ///
    /// `deadline` is an argument rather than a constant in here for two
    /// reasons. The four callers have honestly different budgets — each is
    /// backed by different work on the far side, some of it leaving the
    /// machine — and a required argument cannot be forgotten the way a
    /// default can. Each caller states its own next to the call, where a
    /// reader can judge it against the work it is buying. Where the hatch
    /// bounds that work itself, the deadline here is set to clear that bound
    /// rather than to compete with it.
    pub(crate) async fn post(
        &self,
        path: &str,
        body: Vec<u8>,
        deadline: Duration,
    ) -> Result<HttpResp, BridgeError> {
        self.request("POST", path, body, deadline).await
    }

    /// Ask the hatch whether it is there. Carries nothing, returns nothing but
    /// the fact of an answer.
    ///
    /// `pub`, unlike [`Self::post`], and the rule above does not apply because
    /// there is nothing here for the egress gate to guard: the path is a
    /// literal, the body is empty, the answer is discarded. Nothing crosses the
    /// boundary in either direction, so there is no vouch to make about it.
    ///
    /// What a success proves is narrow and worth stating: this guest's vsock
    /// path to the hatch works and the hatch's own server answered. It says
    /// nothing about the issuer, the registry, the key broker or AMD — those
    /// are other people's uptime, and the endpoint deliberately does not touch
    /// them.
    pub async fn probe(&self, deadline: Duration) -> Result<(), BridgeError> {
        let resp = self.request("GET", "/health", Vec::new(), deadline).await?;
        if resp.status.is_success() {
            Ok(())
        } else {
            Err(BridgeError::Transport(format!(
                "hatch health: status {}",
                resp.status
            )))
        }
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Vec<u8>,
        deadline: Duration,
    ) -> Result<HttpResp, BridgeError> {
        let uri = format!("{}{}", self.base, path);
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| BridgeError::Transport(format!("build request: {e}")))?;

        // One clock over the WHOLE exchange — connect, status line and body.
        //
        // Wrapping only the response future would leave the hole open: this hop
        // has no TLS, no keepalive and no multiplexer under it, so a host that
        // answers with headers and then stops sending stalls the `collect`
        // below for ever, and nothing beneath this line would ever notice. The
        // fleet legs are bounded by chmux's own idle detection; this one has
        // nothing but this.
        //
        // That matters most where it is least visible: `/oci/pull` and
        // `/kbs/relay` are reached from `cold_compile`, which runs INSIDE an
        // applicant round, so an unbounded wait here parks a round that is
        // holding that round's captures.
        let exchange = async move {
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
        };

        // The path is a literal chosen by the caller, so naming it here adds a
        // stage without adding content.
        match tokio::time::timeout(deadline, exchange).await {
            Ok(result) => result,
            Err(_elapsed) => Err(BridgeError::Transport(format!(
                "{path}: the hatch did not answer within the deadline"
            ))),
        }
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
                let stream = VsockStream::connect(addr).await?;
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

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }
}
