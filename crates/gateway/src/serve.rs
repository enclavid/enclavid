//! One public connection, from handshake to close, and every request on it.
//!
//! Driven per connection through hyper rather than through `axum::serve`, and
//! the reason is structural rather than preference. `axum::serve::Listener`'s
//! `accept` returns no `Result`, so a TLS listener written against it has to
//! finish the handshake INSIDE `accept` and therefore serially: one peer that
//! stalls mid-handshake holds up every other peer's accept. A refused handshake
//! would also land in axum's `after_accept_error`, which classifies a rustls
//! error as a listener problem and throttles accepts to one per second.
//!
//! The shape below is the one the fleet already runs three times for remoc —
//! accept, spawn, handshake on the spawned task.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{Either, Full};
use hyper::body::Incoming;
use hyper::client::conn::http2::SendRequest;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use safe_logger::debug;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

use crate::upstream::{Legs, NoRoute, Upstreams};

/// How long a peer has to finish the handshake before its task is dropped.
///
/// Without it, a peer that opens a connection and sends nothing holds a task
/// and a descriptor for as long as it likes, and the host — which carried the
/// connection in — is the party best placed to open a great many of them.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long an HTTP/1.1 caller has to finish sending a request's headers.
///
/// The same reasoning as [`HANDSHAKE_TIMEOUT`], one step later. hyper has this
/// timeout built in, but it only runs when the connection is given a timer —
/// without one it is silently off, and a caller dribbling header bytes holds its
/// connection for ever.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// How often an established connection is checked for having gone quiet, and
/// how many such checks in a row end it.
///
/// Neither HTTP/1.1 nor HTTP/2 closes an idle connection on its own, and the
/// protocol sniff that runs before either of them has no timeout at all — so a
/// peer that finishes TLS and then says nothing would hold its descriptor, its
/// task and its connections to api until the process ended. A browser between
/// page loads is quiet for far less than this; one that is closed for longer
/// reconnects without noticing.
#[cfg(not(test))]
const QUIET_CHECK: Duration = Duration::from_secs(30);
/// The tests run the same mechanism on a short clock. What they pin is that a
/// connection asking for nothing is closed and one being served is not, never
/// how long either is given.
#[cfg(test)]
const QUIET_CHECK: Duration = Duration::from_millis(50);
const QUIET_CHECKS_BEFORE_CLOSE: u32 = 2;

/// The authority put on every forwarded request.
///
/// A constant, because the connection to api is chosen before the request is
/// sent and the URI plays no part in it — so this decides nothing about where
/// the request goes. What it does decide is the authority api sees, and making
/// that a constant of this build means no caller can choose it. `.invalid` is
/// reserved by RFC 2606 and can never resolve, which is the point: it is a
/// placeholder that could not become a destination by accident.
const UPSTREAM_AUTHORITY: &str = "upstream.invalid";

/// Either the upstream's body, streamed through untouched, or one of this
/// role's own fixed answers — and, while it is being delivered, the count that
/// says this connection is busy.
type Answer = Either<Incoming, Full<Bytes>>;

/// A body that keeps its request counted until the last of it is delivered.
///
/// Without this the count would fall when the answer's HEADERS were handed
/// back, and a caller still receiving a large asset would look as quiet as one
/// asking for nothing at all.
pub struct Counted<B> {
    inner: B,
    _counted: InFlight,
}

impl<B: hyper::body::Body + Unpin> hyper::body::Body for Counted<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// Serve one accepted stream: terminate TLS on it, then proxy what arrives.
pub async fn connection(
    acceptor: TlsAcceptor,
    upstreams: watch::Receiver<Arc<Upstreams>>,
    stream: fleet_transport::Stream,
    peer: String,
) {
    let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            debug!("handshake with {peer} failed: {e}");
            return;
        }
        Err(_) => {
            debug!("handshake with {peer} did not finish within the timeout");
            return;
        }
    };

    // Read once, here, from the finished handshake. Which audience this
    // connection belongs to is settled by the name TLS agreed on, before a byte
    // of HTTP is parsed, and it cannot change per request on the same
    // connection — so a request cannot cross to the other surface by claiming
    // anything about itself.
    let server_name = tls.get_ref().1.server_name().map(str::to_owned);

    // `auto` sniffs the HTTP/2 preface and falls back to HTTP/1.1, so the
    // protocol follows what the peer actually sends rather than what ALPN
    // advertised. The two agree for any correct client; making the wire the
    // authority means a disagreement is served rather than mis-framed.
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT);
    builder.http2().timer(TokioTimer::new());

    // This connection's own connections to api — see `crate::upstream` for why
    // they are never shared with another caller.
    let legs = Arc::new(Legs::default());

    // What the quiet check below reads: how many requests this connection has
    // begun, and how many of them have not finished.
    let begun = Arc::new(AtomicUsize::new(0));
    let in_flight = Arc::new(AtomicUsize::new(0));

    let counters = (begun.clone(), in_flight.clone());
    let service = hyper::service::service_fn(move |req| {
        let (begun, in_flight) = &counters;
        // The table as of THIS request, not as of the connection. An h2
        // connection can outlive many pushes, and a snapshot taken at accept
        // would keep sending its requests to an upstream the host has since
        // withdrawn. The clone is an `Arc`, so the borrow ends here.
        let upstreams = upstreams.borrow().clone();
        let legs = legs.clone();
        let server_name = server_name.clone();
        begun.fetch_add(1, Ordering::Relaxed);
        let counted = InFlight::begin(in_flight.clone());
        async move {
            let answer = proxy(&upstreams, &legs, server_name.as_deref(), req).await;
            Ok::<_, Infallible>(answer.map(|inner| Counted {
                inner,
                _counted: counted,
            }))
        }
    });

    let connection = builder.serve_connection(TokioIo::new(tls), service);
    tokio::pin!(connection);
    let mut quiet = 0;
    let mut served = 0;
    loop {
        tokio::select! {
            ended = &mut connection => {
                if let Err(e) = ended {
                    debug!("connection from {peer} ended: {e}");
                }
                return;
            }
            _ = tokio::time::sleep(QUIET_CHECK) => {
                let begun = begun.load(Ordering::Relaxed);
                // Nothing running and nothing new since the last check. A
                // response still streaming counts as busy, however slowly the
                // caller reads it: what is bounded here is a connection that
                // asks for nothing, not one that is being served.
                if in_flight.load(Ordering::Relaxed) == 0 && begun == served {
                    quiet += 1;
                    if quiet >= QUIET_CHECKS_BEFORE_CLOSE {
                        debug!("connection from {peer} closed for saying nothing");
                        return;
                    }
                } else {
                    quiet = 0;
                    served = begun;
                }
            }
        }
    }
}

/// Counts one request for as long as it is being answered, however it ends.
pub struct InFlight(Arc<AtomicUsize>);

impl InFlight {
    fn begin(count: Arc<AtomicUsize>) -> InFlight {
        count.fetch_add(1, Ordering::Relaxed);
        InFlight(count)
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Which api build the caller requires.
///
/// A header rather than anything in the path, and the difference is not
/// cosmetic. This value is FOR this hop — it selects an upstream and then stops
/// — so it is stripped before forwarding. A path would travel, and would also
/// mean reading paths, which this role does not do.
const MEASUREMENT: &str = "x-enclavid-api-measurement";

/// Carry one request to api and its answer back.
///
/// The path is never examined. On the applicant surface it carries the session
/// id — the one value that turns the host's separate observations, a source
/// address and a consumer's authorisation call and a timing, into one linked
/// profile. Nothing here needs it, so nothing here reads it.
async fn proxy(
    upstreams: &Upstreams,
    legs: &Legs,
    server_name: Option<&str>,
    mut req: Request<Incoming>,
) -> Response<Answer> {
    // Named once or not at all. `remove` would take every value and return the
    // first, so two values would route by whichever happened to come first —
    // a choice made for the caller, which this header exists to prevent.
    if req.headers().get_all(MEASUREMENT).iter().nth(1).is_some() {
        return fixed(
            StatusCode::BAD_REQUEST,
            "name exactly one api measurement\n",
        );
    }
    // Taken, not copied: it named a choice this hop makes, and api has no use
    // for it.
    let wanted = req
        .headers_mut()
        .remove(MEASUREMENT)
        .and_then(|v| v.to_str().ok().map(str::to_owned));

    let target = match upstreams.route(server_name, wanted.as_deref()) {
        Ok(target) => target,
        // 421 rather than 404: the request is well-formed and this role simply
        // is not the server for the name it was sent to.
        Err(NoRoute::UnknownName) => {
            return fixed(
                StatusCode::MISDIRECTED_REQUEST,
                "this name is not served here\n",
            );
        }
        // 400, because the request is missing something only the caller can
        // supply. Naming a build is not a formality here — it is the whole of
        // what this role checks on the caller's behalf.
        Err(NoRoute::Unspecified) => {
            return fixed(
                StatusCode::BAD_REQUEST,
                "name the api measurement you require\n",
            );
        }
        // 502, and deliberately the same answer as an upstream that would not
        // talk: which builds are reachable is the host's business and changes
        // under it, so distinguishing "no such build here" from "it would not
        // answer" would report the fleet's shape to whoever asked.
        Err(NoRoute::NoSuchBuild) => return unavailable(),
    };

    let leg = match legs.get(target, upstreams.tls()).await {
        Ok(leg) => leg,
        Err(e) => {
            debug!("could not open a connection to api: {e}");
            return unavailable();
        }
    };

    forward(leg, req).await
}

/// Send it, hand the answer back.
///
/// Neither body is buffered. `Incoming` streams in both directions, which is
/// what keeps a 16 MiB capture from becoming 16 MiB of this role's memory, and
/// keeps this role from being able to read what it carries even if it wanted to.
///
/// No hop-by-hop header is stripped here, because the leg to api is HTTP/2 and
/// hyper's HTTP/2 codec handles the framing ones in both directions: it removes
/// `Connection`, the headers its value names, `Keep-Alive`, `Proxy-Connection`,
/// `Transfer-Encoding`, `Upgrade` and any `TE` but `trailers` from each request
/// before sending, and it refuses a response that carries them. Whatever an
/// HTTP/1.1 caller put there cannot frame anything on the leg to api, and
/// nothing api sends can reach the caller as framing. Other headers a caller
/// lists in `Connection` may still travel — which gives the caller nothing, since
/// it could have sent those headers to api directly.
async fn forward(mut leg: SendRequest<Incoming>, req: Request<Incoming>) -> Response<Answer> {
    let (mut parts, body) = req.into_parts();
    // The authority api sees is a constant of this build. Left in place, the
    // caller's `Host` would travel beside it and hand api a value the caller
    // chose, for a routing decision api never asked to make.
    parts.headers.remove(hyper::header::HOST);
    parts.uri = match upstream_uri(&parts.uri) {
        Ok(uri) => uri,
        Err(e) => {
            debug!("could not rebuild the request uri: {e}");
            return fixed(StatusCode::BAD_REQUEST, "malformed request target\n");
        }
    };

    let sent = async {
        leg.ready().await?;
        leg.send_request(Request::from_parts(parts, body)).await
    };
    match sent.await {
        Ok(response) => response.map(Either::Left),
        Err(e) => {
            debug!("upstream request failed: {e}");
            unavailable()
        }
    }
}

/// The answer for anything that went wrong behind this role.
///
/// 502 says the failure is behind this role rather than in the request. It
/// carries nothing about which upstream, which name or which path: the party
/// most able to provoke one of these is the host, and an error that varies with
/// what it provoked is a channel.
fn unavailable() -> Response<Answer> {
    fixed(StatusCode::BAD_GATEWAY, "upstream unavailable\n")
}

/// Re-target a request at the upstream, keeping only its path and query.
fn upstream_uri(original: &Uri) -> Result<Uri, hyper::http::Error> {
    let path_and_query = original
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_owned();
    Uri::builder()
        .scheme("http")
        .authority(UPSTREAM_AUTHORITY)
        .path_and_query(path_and_query)
        .build()
}

/// One of this role's own answers, as opposed to something an upstream said.
fn fixed(status: StatusCode, message: &'static str) -> Response<Answer> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Either::Right(Full::new(Bytes::from_static(
            message.as_bytes(),
        ))))
        .expect("a constant response builds")
}

/// End to end over loopback: real TLS, real HTTP/2 on both sides, an api
/// stand-in behind. TCP arm only, because the listeners here are TCP.
#[cfg(all(test, not(feature = "vsock")))]
mod tests {
    use super::*;

    use http_body_util::{BodyExt, Empty};
    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::crypto::CryptoProvider;
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use tokio_rustls::rustls::{self, DigitallySignedStruct, SignatureScheme};

    const M: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BODY: usize = 1 << 20;

    /// An api stand-in: HTTP/2 by prior knowledge, answering every request with
    /// `BODY` bytes.
    async fn api() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(|_req| async {
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(vec![b'x'; BODY]))))
                    });
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        addr
    }

    /// This role on a loopback listener, with `api` as the one build declared.
    async fn gateway(api: &str) -> String {
        let listener = fleet_transport::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(
            crate::tls::server_config(&["verify.example.com", "api.example.com"]).unwrap(),
        ));
        let table = Upstreams::empty("verify.example.com".into(), "api.example.com".into())
            .replaced(vec![crate::config::Upstream {
                measurement: M.into(),
                applicant: api.into(),
                client: api.into(),
            }]);
        let (_, current) = watch::channel(Arc::new(table));
        tokio::spawn(async move {
            fleet_transport::accept_forever(listener, move |stream, peer| {
                let acceptor = acceptor.clone();
                let current = current.clone();
                async move {
                    tokio::spawn(connection(acceptor, current, stream, peer));
                }
            })
            .await
        });
        addr
    }

    /// Accepts any certificate: what is under test is how this role carries
    /// requests, not its identity.
    #[derive(Debug)]
    struct AnyCertificate(Arc<CryptoProvider>);

    impl ServerCertVerifier for AnyCertificate {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    /// One public HTTP/2 connection, receiving with the given window.
    async fn caller(gateway: &str, window: u32) -> SendRequest<Empty<Bytes>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];

        let tcp = tokio::net::TcpStream::connect(gateway).await.unwrap();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("verify.example.com").unwrap(), tcp)
            .await
            .unwrap();
        let (sender, driver) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .initial_stream_window_size(window)
            .initial_connection_window_size(window)
            .handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(driver);
        sender
    }

    fn request() -> hyper::http::request::Builder {
        Request::get("https://verify.example.com/")
    }

    /// A caller that stops reading must not stall anyone else.
    ///
    /// The attacker opens eight streams and reads none of their bodies, each
    /// leaving up to `BODY` bytes of api's answer unread behind this role. On a
    /// connection to api shared between callers that unread data fills the
    /// shared connection window, whatever its size, and every other response on
    /// it stops. Owned per public connection, it fills only the attacker's own.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_caller_that_stops_reading_does_not_stall_another() {
        let gateway = gateway(&api().await).await;

        let mut attacker = caller(&gateway, 65_535).await;
        let mut unread = Vec::new();
        for _ in 0..8 {
            attacker.ready().await.unwrap();
            let response = attacker
                .send_request(request().header(MEASUREMENT, M).body(Empty::new()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            unread.push(response);
        }

        let mut victim = caller(&gateway, 4 << 20).await;
        let body = tokio::time::timeout(Duration::from_secs(10), async {
            victim.ready().await.unwrap();
            let response = victim
                .send_request(request().header(MEASUREMENT, M).body(Empty::new()).unwrap())
                .await
                .unwrap();
            response.into_body().collect().await.unwrap().to_bytes()
        })
        .await
        .expect("the victim's answer must not wait on a caller that stopped reading");
        assert_eq!(body.len(), BODY);
        drop(unread);
    }

    /// A connection that finishes TLS and then says nothing is closed, rather
    /// than holding its descriptor until the process ends. The test above is the
    /// other half of the same rule: a connection whose answers are still being
    /// delivered — the attacker's eight unread bodies — is never quiet, however
    /// slowly it reads.
    #[tokio::test]
    async fn a_connection_that_asks_nothing_is_closed() {
        let gateway = gateway(&api().await).await;
        let caller = caller(&gateway, 4 << 20).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while !caller.is_closed() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("a connection that asks for nothing must not be kept");
    }

    /// Two measurements are refused rather than resolved to whichever came first.
    #[tokio::test]
    async fn a_measurement_named_twice_is_refused() {
        let gateway = gateway(&api().await).await;
        let mut caller = caller(&gateway, 4 << 20).await;
        caller.ready().await.unwrap();
        let response = caller
            .send_request(
                request()
                    .header(MEASUREMENT, M)
                    .header(MEASUREMENT, M)
                    .body(Empty::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
