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
use hyper::header::HeaderValue;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use safe_logger::debug;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

use crate::affinity;
use crate::attest;
use crate::upstream::{Legs, NoRoute, Surface, Target, Upstreams};

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
    proof: attest::Proof,
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
        let proof = proof.clone();
        begun.fetch_add(1, Ordering::Relaxed);
        let counted = InFlight::begin(in_flight.clone());
        async move {
            let answer = proxy(&upstreams, &legs, &proof, server_name.as_deref(), req).await;
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
    proof: &attest::Proof,
    server_name: Option<&str>,
    mut req: Request<Incoming>,
) -> Response<Answer> {
    // This role's own path, answered before anything is routed and without
    // reaching api at all. It is the one path this build knows: what a request
    // for anything else means is the host's configuration, never this file's.
    if req.uri().path() == attest::PATH {
        return attestation(proof, req.method());
    }

    let surface = match upstreams.surface(server_name) {
        Ok(surface) => surface,
        // 421 rather than 404: the request is well-formed and this role simply
        // is not the server for the name it was sent to.
        Err(_) => {
            return fixed(
                StatusCode::MISDIRECTED_REQUEST,
                "this name is not served here\n",
            );
        }
    };

    // Which machine, and — on the consumer surface — a token to hand back so
    // the next request of this session comes to the same one.
    let placed = match surface {
        Surface::Applicant => match applicant_node(&mut req) {
            Some(node) => upstreams
                .at_node(surface, &node)
                .map(|target| (target, None)),
            // The link this role writes always carries a machine. One without
            // is not a session's link, and there is nothing to guess from.
            None => {
                return fixed(StatusCode::BAD_REQUEST, "this link is incomplete\n");
            }
        },
        Surface::Consumer => consumer_node(upstreams, &mut req),
    };

    let (target, minted) = match placed {
        Ok(placed) => placed,
        Err(NoRoute::Unspecified) => {
            // 400, because the request is missing something only the caller can
            // supply. Naming a build is not a formality here — it is the whole
            // of what this role checks on the caller's behalf.
            return fixed(
                StatusCode::BAD_REQUEST,
                "name the api measurement you require\n",
            );
        }
        // 502, and deliberately the same answer as an upstream that would not
        // talk: which machines exist, which builds they run and which can take
        // work is the host's business and changes under it, so telling those
        // apart would report the fleet's shape to whoever asked.
        Err(_) => return unavailable(),
    };
    let node = target.node.to_owned();

    let leg = match legs.get(target, upstreams.tls()).await {
        Ok(leg) => leg,
        Err(e) => {
            debug!("could not open a connection to api: {e}");
            return unavailable();
        }
    };

    let mut answer = forward(leg, req).await;
    if let Some(token) = minted {
        // Said on the way back, on every consumer answer: the machine this
        // request went to, and a token that returns the next one there. Sliding
        // rather than issued once, so a session outliving one token keeps its
        // machine — see `crate::affinity`.
        for (header, value) in [
            (affinity::NODE_HEADER, node),
            (affinity::TOKEN_HEADER, token),
        ] {
            match HeaderValue::from_str(&value) {
                Ok(value) => {
                    answer.headers_mut().insert(header, value);
                }
                Err(e) => debug!("could not write {header}: {e}"),
            }
        }
    }
    answer
}

/// The machine an applicant's link names: the first path segment, removed on
/// the way through so api sees the path it published.
fn applicant_node(req: &mut Request<Incoming>) -> Option<String> {
    let path = req.uri().path();
    let rest = path.strip_prefix('/')?;
    let (node, rest) = rest.split_once('/').unwrap_or((rest, ""));
    if node.is_empty() {
        return None;
    }
    let node = node.to_owned();

    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let stripped = format!("/{rest}{query}");
    match Uri::builder().path_and_query(stripped).build() {
        Ok(uri) => {
            *req.uri_mut() = uri;
            Some(node)
        }
        Err(e) => {
            debug!("could not strip the node from the path: {e}");
            None
        }
    }
}

/// Where a consumer's request goes: back to the machine its token names, or —
/// having none — to one this role picks among those running the build it asked
/// for, with a token to come back by.
fn consumer_node<'a>(
    upstreams: &'a Upstreams,
    req: &mut Request<Incoming>,
) -> Result<(Target<'a>, Option<String>), NoRoute> {
    let keys = upstreams.affinity().ok_or(NoRoute::NoSuchBuild)?;
    let token = req
        .headers_mut()
        .remove(affinity::TOKEN_HEADER)
        .and_then(|value| value.to_str().ok().map(str::to_owned));
    let now = std::time::SystemTime::now();

    // A token that does not check out is treated as absent rather than refused:
    // it is this role's own bookkeeping, and the caller cannot do anything
    // about a key that rotated twice or a clock that moved.
    if let Some(node) = token.as_deref().and_then(|token| keys.node_of(token, now)) {
        let target = upstreams.at_node(Surface::Consumer, &node)?;
        return Ok((target, Some(keys.mint(&node, now))));
    }

    // Named once or not at all. `remove` would take every value and return the
    // first, so two values would route by whichever happened to come first —
    // a choice made for the caller, which this header exists to prevent.
    if req.headers().get_all(MEASUREMENT).iter().nth(1).is_some() {
        return Err(NoRoute::Unspecified);
    }
    // Taken, not copied: it named a choice this hop makes, and api has no use
    // for it.
    let wanted = req
        .headers_mut()
        .remove(MEASUREMENT)
        .and_then(|value| value.to_str().ok().map(str::to_owned))
        .ok_or(NoRoute::Unspecified)?;

    let target = upstreams.assign(Surface::Consumer, &wanted)?;
    let token = keys.mint(target.node, now);
    Ok((target, Some(token)))
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

/// Hand back what this build can prove about itself.
///
/// Read-only and the same for every caller, so `HEAD` answers like `GET` with
/// the body dropped by the protocol, and anything else is refused rather than
/// treated as a request to change something that cannot change.
fn attestation(proof: &attest::Proof, method: &hyper::Method) -> Response<Answer> {
    if method != hyper::Method::GET && method != hyper::Method::HEAD {
        return fixed(
            StatusCode::METHOD_NOT_ALLOWED,
            "this is something to read\n",
        );
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, attest::CONTENT_TYPE)
        // A quote is checked, not cached: a caller that keeps one and compares
        // it to a certificate from a later connection is checking a binding
        // that was true elsewhere.
        .header(hyper::header::CACHE_CONTROL, "no-store")
        .body(Either::Right(Full::new(proof.clone())))
        .expect("a response over constant headers builds")
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
    const NODE: &str = "one";
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
    /// Returns its address and the SPKI its quote is supposed to bind.
    async fn gateway(api: &str) -> (String, Vec<u8>) {
        let listener = fleet_transport::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (config, spki) =
            crate::tls::server_config(&["verify.example.com", "api.example.com"]).unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let proof = attest::proof(spki.clone(), &crate::identity::attestor()).unwrap();
        let table = Upstreams::empty("verify.example.com".into(), "api.example.com".into())
            .replaced(crate::upstream::tests::pushed(vec![
                crate::config::Upstream {
                    node: NODE.into(),
                    measurement: M.into(),
                    applicant: api.into(),
                    client: api.into(),
                    // Nothing listens there: an unreachable health port leaves
                    // the node ready, which is where a fresh push starts it.
                    health: "127.0.0.1:1".into(),
                },
            ]));
        let (_, current) = watch::channel(Arc::new(table));
        tokio::spawn(async move {
            fleet_transport::accept_forever(listener, move |stream, peer| {
                let acceptor = acceptor.clone();
                let current = current.clone();
                let proof = proof.clone();
                async move {
                    tokio::spawn(connection(acceptor, current, proof, stream, peer));
                }
            })
            .await
        });
        (addr, spki)
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

    /// One public HTTP/2 connection to the applicant's name, receiving with the
    /// given window.
    async fn caller(gateway: &str, window: u32) -> SendRequest<Empty<Bytes>> {
        connect(gateway, "verify.example.com", window).await
    }

    /// The same, to the consumer's name.
    async fn consumer(gateway: &str) -> SendRequest<Empty<Bytes>> {
        connect(gateway, "api.example.com", 4 << 20).await
    }

    async fn connect(gateway: &str, name: &'static str, window: u32) -> SendRequest<Empty<Bytes>> {
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
            .connect(ServerName::try_from(name).unwrap(), tcp)
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

    /// What an applicant's link looks like: the machine first, then api's path.
    fn request() -> hyper::http::request::Builder {
        Request::get(format!("https://verify.example.com/{NODE}/"))
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
        let (gateway, _) = gateway(&api().await).await;

        let mut attacker = caller(&gateway, 65_535).await;
        let mut unread = Vec::new();
        for _ in 0..8 {
            attacker.ready().await.unwrap();
            let response = attacker
                .send_request(request().body(Empty::new()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            unread.push(response);
        }

        let mut victim = caller(&gateway, 4 << 20).await;
        let body = tokio::time::timeout(Duration::from_secs(10), async {
            victim.ready().await.unwrap();
            let response = victim
                .send_request(request().body(Empty::new()).unwrap())
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
        let (gateway, _) = gateway(&api().await).await;
        let caller = caller(&gateway, 4 << 20).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while !caller.is_closed() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("a connection that asks for nothing must not be kept");
    }

    /// The quote this role serves binds the key it is serving it over, and is
    /// answered without an api behind it or a measurement named.
    #[tokio::test]
    async fn the_attestation_binds_the_serving_certificate() {
        let (gateway, spki) = gateway(&api().await).await;
        let mut caller = caller(&gateway, 4 << 20).await;
        caller.ready().await.unwrap();
        let response = caller
            .send_request(
                Request::get(format!("https://verify.example.com{}", attest::PATH))
                    .body(Empty::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[hyper::header::CONTENT_TYPE],
            attest::CONTENT_TYPE
        );

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let quote: enclavid_attestation::Quote = ciborium::from_reader(body.as_ref()).unwrap();
        crate::identity::attestor()
            .verify(
                &quote,
                &enclavid_attestation::ReportData::for_ratls(spki.clone()),
            )
            .expect("the quote binds the certificate this role serves it over");

        // And a quote bound to some OTHER key does not pass the same check,
        // which is what makes the assertion above worth making.
        let (_, other) = crate::tls::server_config(&["verify.example.com"]).unwrap();
        assert!(
            crate::identity::attestor()
                .verify(&quote, &enclavid_attestation::ReportData::for_ratls(other))
                .is_err()
        );
    }

    /// A consumer is told where its session was placed, and comes back there
    /// with the token it was given rather than with a machine of its choosing.
    #[tokio::test]
    async fn a_consumer_is_placed_and_comes_back_with_a_token() {
        let (gateway, _) = gateway(&api().await).await;
        let mut consumer = consumer(&gateway).await;

        consumer.ready().await.unwrap();
        let placed = consumer
            .send_request(
                Request::get("https://api.example.com/api/v1/sessions")
                    .header(MEASUREMENT, M)
                    .body(Empty::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(placed.status(), StatusCode::OK);
        assert_eq!(placed.headers()[affinity::NODE_HEADER], NODE);
        let token = placed.headers()[affinity::TOKEN_HEADER].clone();

        // Coming back with it needs no measurement: the token says where.
        consumer.ready().await.unwrap();
        let again = consumer
            .send_request(
                Request::get("https://api.example.com/api/v1/sessions/1")
                    .header(affinity::TOKEN_HEADER, &token)
                    .body(Empty::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(again.status(), StatusCode::OK);
        assert_eq!(again.headers()[affinity::NODE_HEADER], NODE);

        // Without either, there is nothing to place on and nothing to go back
        // to, and the answer says which is missing.
        consumer.ready().await.unwrap();
        let naked = consumer
            .send_request(
                Request::get("https://api.example.com/api/v1/sessions")
                    .body(Empty::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(naked.status(), StatusCode::BAD_REQUEST);
    }

    /// An applicant's link carries the machine, and one without it is not a
    /// link this role wrote.
    #[tokio::test]
    async fn an_applicant_link_without_a_machine_is_refused() {
        let (gateway, _) = gateway(&api().await).await;
        let mut caller = caller(&gateway, 4 << 20).await;
        caller.ready().await.unwrap();
        let response = caller
            .send_request(
                Request::get("https://verify.example.com/")
                    .body(Empty::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // And a machine nobody declares is the same answer as one that would
        // not talk.
        caller.ready().await.unwrap();
        let elsewhere = caller
            .send_request(
                Request::get("https://verify.example.com/somewhere/")
                    .body(Empty::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(elsewhere.status(), StatusCode::BAD_GATEWAY);
    }

    /// Two measurements are refused rather than resolved to whichever came first.
    #[tokio::test]
    async fn a_measurement_named_twice_is_refused() {
        let (gateway, _) = gateway(&api().await).await;
        let mut consumer = consumer(&gateway).await;
        consumer.ready().await.unwrap();
        let response = consumer
            .send_request(
                Request::get("https://api.example.com/api/v1/sessions")
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
