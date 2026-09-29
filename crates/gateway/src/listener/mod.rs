//! The public listener: what it accepts, the certificate it presents, and the
//! name each connection agreed to.
//!
//! ## The connection is this role's; the loop is the transport's
//!
//! This guest has no NIC, so public connections arrive over the fleet transport
//! and nothing else. `fleet_transport::service::serve` takes them, and each is
//! handed here already established: the TLS and the HTTP server run over a
//! stream that never has to know what carried it. Nothing is bridged, spliced
//! or wrapped to make a transport look like one a library recognises.
//!
//! What the listener PRESENTS is in `certificate`: the key is this guest's own and
//! reaches the handshake through a resolver that follows the pushed names, so a
//! table declaring different names replaces the certificate under a listener
//! that stays up.
//!
//! ## Who dialled, before anything else
//!
//! Every connection starts with a PROXY protocol v2 header naming its source,
//! written by the host's first hop ahead of the caller's bytes; one without it
//! is let go before the handshake, except in a `dev-attestation` build, which
//! serves it as an unstated source. The source decides one thing: no source
//! holds more than `connections_per_source` of the places, counted from the
//! header on —
//! which is why the first hop must write it the moment it connects. What is
//! read, what is kept and why neither leaves this role is in `source`.
//!
//! ## Then the hello, and whose connection it is
//!
//! A connection whose hello offers `acme-tls/1` and nothing else is an ACME
//! validator's, and is answered from what the host armed for the name it asks
//! for — or, if nothing is armed, refused as a protocol this role does not
//! speak is. Every other connection is this role's, and the handshake carries
//! on from the hello rustls has already read. See `acme`.
//!
//! ## Why the name is remembered rather than read from the request
//!
//! Routing needs the name the caller AGREED to, not the one it claims. A
//! request carries a `Host` a caller writes; the handshake settled an SNI it
//! cannot change afterwards, and it is the one the certificate answered for.
//! Reading `Host` instead would let a caller reach an address it never
//! negotiated for.
//!
//! Here that is a local variable: the name is read off the finished handshake
//! and handed to every request on that connection. A request that names
//! another host than it is not routed by either name but gets a 421 — see
//! `crate::route`.
//!
//! ## The numbers are the host's
//!
//! Every limit and timeout below is a field of the `listener` part of the
//! tuning the host pushes — see `crate::config`. Each connection runs by the
//! table that was current when it was accepted, so a push changes what the
//! next connection gets and leaves the open ones be.
//!
//! Except `connections`, which is resized under the listener: the place a
//! connection holds is a permit of a semaphore that holds exactly what the
//! current table grants — see [`follow`]. Raising the number adds permits at
//! once. Lowering it takes them back as connections close, and a connection
//! arriving meanwhile waits in line behind that; none that is open is cut.
//!
//! ## Two ceilings, because two things run out
//!
//! `connections` bounds CONNECTIONS, which is what a caller opens.
//! `streams_per_connection` bounds the requests each one may have in flight,
//! which is what opens legs to api. Only the second bounds descriptors in any
//! useful way — one connection offering a hundred streams would otherwise stand
//! for a hundred legs — and stating both is what makes the budget multiply out
//! to a number, which a push has to fit in what the process has. Across a
//! change from one push to the next, `crate::budget` is what holds.
//!
//! What each of those streams may hold in memory is bounded twice more: by
//! [`SENDING`] here, and by the window a leg offers api.
//!
//! ## Nothing holds a place for nothing
//!
//! A connection holds one of the places for as long as it lives, so a
//! connection that does nothing must not live for ever — or a caller opening
//! all of them and saying nothing shuts everyone else out. Every stage where a
//! caller can stall is bounded:
//!
//! - the PROXY header and the TLS handshake after it, together, by
//!   `handshake_timeout` — which is the whole of a validator's connection;
//! - an HTTP/1 request head, by `header_timeout` — which the HTTP library
//!   applies only if it is given a timer, and otherwise drops without a word.
//!   Its clock starts as soon as the library waits for the next request, so on
//!   HTTP/1 it also bounds the gap between two requests, and usually first;
//! - an HTTP/2 peer that has gone, by a ping it must answer within
//!   `ping_interval`;
//! - a request body, by `request_body_pause` between two frames and
//!   `request_body_timeout` whole — it holds a place at its member until api
//!   responds, and api reads it whole first; see `body`;
//! - a connection on which no request has started — for
//!   `first_request_timeout` after its handshake, for `idle_timeout` after one
//!   has — which covers a caller that finished the handshake and sent nothing,
//!   and one that answers pings and asks for nothing. A caller that finished a
//!   handshake has nothing left to wait for, so the first wait can be short;
//! - and every connection, busy or not, by `lifetime`. A caller asking once in
//!   a while never goes idle, and a stream whose response is never read keeps
//!   its leg for as long as the connection lives; this is what bounds both. A
//!   browser opens a new connection when an old one is shut down, so an honest
//!   caller does not notice, and a caller keeping a connection busy to keep its
//!   place goes to the back of the line for the next one.
//!
//! A connection that reaches either of the last two is shut down gracefully,
//! and given `drain_timeout` for whatever it had started before it is dropped —
//! longer, the table checks, than any request may wait for api to start
//! responding, so what it cuts is a caller that stopped reading or never stops
//! writing.

pub mod acme;
mod body;
pub mod certificate;
mod source;

use std::convert::Infallible;
use std::sync::Arc;

use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use safe_logger::debug;
use tokio::sync::{Semaphore, watch};
use tokio_rustls::TlsAcceptor;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::map_request_body::MapRequestBodyLayer;
use tower_http::timeout::RequestBodyTimeoutLayer;

use crate::route::Hop;
use crate::upstream::Upstreams;
use source::Sources;

/// How much of a response may wait here for a caller that is not reading it,
/// per stream.
///
/// Past it, this role stops pulling from api, and api's own window on the leg
/// takes over — so what a caller that never reads can hold in memory is this
/// plus that window, per stream, and never the whole response.
const SENDING: usize = 64 << 10;

/// What a public connection responds with: `crate::route`'s response, boxed
/// once more by the layer that catches a panic, since its response to one is a
/// body of another type.
type Outgoing = tower_http::body::UnsyncBoxBody<bytes::Bytes, tower::BoxError>;

/// Serve public connections, for ever, by the numbers in `table`.
///
/// Await this on the role's own task: a role whose listener stopped would hold
/// a socket nothing drains and respond to nobody, while still looking alive.
///
/// One connection per place: the place is taken when the transport asks
/// whether a connection can be taken — BEFORE it is accepted, so a caller over
/// the limit waits in the listener's backlog rather than inside this process
/// holding a descriptor — and given back when [`one`] returns.
pub async fn serve(
    listener: fleet_transport::Listener,
    hop: Arc<Hop>,
    tls: TlsAcceptor,
    challenges: Arc<acme::Challenges>,
    table: watch::Receiver<Arc<Upstreams>>,
) -> ! {
    let places = Arc::new(Semaphore::new(0));
    let sources = Sources::new();
    let serving = tower::limit::ConcurrencyLimit::with_semaphore(
        tower::service_fn({
            let table = table.clone();
            move |accepted| {
                one(
                    hop.clone(),
                    tls.clone(),
                    challenges.clone(),
                    sources.clone(),
                    table.clone(),
                    accepted,
                )
            }
        }),
        places.clone(),
    );
    tokio::select! {
        never = fleet_transport::service::serve(listener, serving) => never,
        never = follow(places, table) => never,
    }
}

/// Keep the listener's places at what each table grants, for ever.
///
/// The semaphore starts empty and holds exactly the permits the current table
/// grants, free and taken together. A raise adds permits, which go at once to
/// whoever waits. A lowering removes the free ones at once and the rest as
/// connections close — the semaphore is fair, so a connection arriving
/// meanwhile waits behind the removal — and a push that comes before it is done
/// replaces it.
///
/// Connections may still come in past a lowering in two ways. The listener
/// takes a place BEFORE it accepts, so the place for the next connection may
/// already be taken when the push arrives, and that one is let in on it. And a
/// lowering that another change of `connections` interrupts starts over, handing
/// what it had gathered to whoever waits first. Both are bounded, and the
/// descriptors they spend are counted all the same — see `crate::budget`.
async fn follow(places: Arc<Semaphore>, mut table: watch::Receiver<Arc<Upstreams>>) -> ! {
    // What the semaphore stands for now, free and taken.
    let mut granted: usize = 0;
    loop {
        table.mark_unchanged();
        let wanted = connections(&table);

        if wanted > granted {
            places.add_permits(wanted - granted);
            granted = wanted;
        } else if wanted < granted {
            granted -= places.forget_permits(granted - wanted);
            if granted > wanted {
                let owed = u32::try_from(granted - wanted).expect("a count of connections");
                let reclaiming = places.clone().acquire_many_owned(owed);
                tokio::pin!(reclaiming);
                // Pushes that leave `connections` as it is — a new member, a
                // rotated key — do not interrupt the reclaiming: dropped, it
                // would hand what it had gathered to the next caller in line,
                // and pushes coming often enough would keep a lowering from
                // ever taking hold.
                let reclaimed = loop {
                    tokio::select! {
                        returned = &mut reclaiming => break Some(returned),
                        changed = table.changed() => {
                            if changed.is_err() {
                                std::future::pending::<()>().await;
                            }
                            if connections(&table) != wanted {
                                break None;
                            }
                        }
                    }
                };
                let Some(returned) = reclaimed else {
                    continue;
                };
                returned.expect("the semaphore is never closed").forget();
                granted = wanted;
            }
        }

        if table.changed().await.is_err() {
            // The sender lives as long as the process.
            std::future::pending::<()>().await;
        }
    }
}

/// What each request on one connection passes through, outermost first: a
/// panic anywhere inside turned into the response for a failure behind this
/// role — see `crate::route::panicked` — then its body given a deadline, then a
/// bound on its pauses — both by that connection's numbers — then its trailers
/// taken off, all three in `body`; then boxed into what a leg carries, and
/// responded to.
///
/// Built here and boxed rather than inline in [`one`]: a closure type held
/// across an `await` there trips the compiler's `Send` reasoning about the
/// lifetimes inside a boxed error type, and a boxed service holds no closure
/// type for it to reason about.
fn responding(
    hop: Arc<Hop>,
    agreed: Arc<str>,
    asked: Arc<tokio::sync::Notify>,
    tuning: &crate::config::ListenerTuning,
) -> tower::util::BoxCloneService<Request<hyper::body::Incoming>, Response<Outgoing>, Infallible> {
    let whole = tuning.request_body_timeout;
    tower::ServiceBuilder::new()
        .boxed_clone()
        .layer(CatchPanicLayer::custom(crate::route::panicked))
        .map_request(move |req: Request<hyper::body::Incoming>| body::due(req, whole))
        .layer(RequestBodyTimeoutLayer::new(tuning.request_body_pause))
        .layer(MapRequestBodyLayer::new(body::untrailed))
        .layer(MapRequestBodyLayer::new(body::boxed))
        .service_fn(move |req| {
            // Rung as each request starts, which is what keeps a connection
            // that is being used from being taken for idle.
            asked.notify_one();
            let (hop, agreed) = (hop.clone(), agreed.clone());
            async move { Ok(hop.respond(&agreed, req).await) }
        })
}

/// How many connections the current table grants.
fn connections(table: &watch::Receiver<Arc<Upstreams>>) -> usize {
    table
        .borrow()
        .tuning()
        .map_or(0, |tuning| tuning.listener.connections)
}

/// Why a connection was let go before its first request.
enum Unopened {
    Header(source::Malformed),
    Crowded,
    Handshake(std::io::Error),
    /// An ACME validator's, whose handshake did not finish — see `acme`.
    Answered(std::io::Error),
}

impl std::fmt::Display for Unopened {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unopened::Header(e) => write!(f, "{e}"),
            Unopened::Crowded => f.write_str("its source holds its share of places"),
            Unopened::Handshake(e) => write!(f, "no handshake: {e}"),
            Unopened::Answered(e) => write!(f, "an ACME validator's, answered: {e}"),
        }
    }
}

/// One public connection, from the header to the last response on it.
async fn one(
    hop: Arc<Hop>,
    tls: TlsAcceptor,
    challenges: Arc<acme::Challenges>,
    sources: Arc<Sources>,
    table: watch::Receiver<Arc<Upstreams>>,
    accepted: fleet_transport::Accepted,
) -> Result<(), Infallible> {
    let fleet_transport::Accepted { stream, peer } = accepted;
    // The numbers this connection runs by, from the table current as it was
    // taken. The listener opens only once a push has arrived, so there is one.
    let Some(tuning) = table.borrow().tuning().map(|tuning| tuning.listener) else {
        return Ok(());
    };
    // Its descriptor, counted for as long as it is open — see `crate::budget`.
    let Some(_descriptor) = crate::budget::take() else {
        debug!("the connection from {peer} was let go: no descriptor to spare");
        return Ok(());
    };
    // The source's share is taken before the handshake, so a source over it
    // costs no TLS work, and held until this function returns.
    // An ACME validator's connection is a handshake and nothing more, so it
    // is answered whole inside this bound — see `acme` — and comes out of it
    // with nothing left to serve.
    let opened = tokio::time::timeout(tuning.handshake_timeout, async move {
        let (origin, mut stream) = source::read(stream).await.map_err(Unopened::Header)?;
        let admitted = sources
            .admit(origin, tuning.connections_per_source)
            .ok_or(Unopened::Crowded)?;
        let hello = acme::hello(&mut stream)
            .await
            .map_err(Unopened::Handshake)?;
        let answer = acme::validates(&hello)
            .then(|| challenges.answering(hello.client_hello().server_name()))
            .flatten();
        if let Some(answer) = answer {
            acme::answered(hello, stream, answer)
                .await
                .map_err(Unopened::Answered)?;
            return Ok(None);
        }
        let settled = tokio_rustls::StartHandshake::from_parts(hello, stream)
            .into_stream(tls.config().clone())
            .await
            .map_err(Unopened::Handshake)?;
        Ok::<_, Unopened>(Some((admitted, settled)))
    })
    .await;
    let (_admitted, settled) = match opened {
        Ok(Ok(Some(opened))) => opened,
        Ok(Ok(None)) => {
            debug!("the connection from {peer} was an ACME validator's, answered");
            return Ok(());
        }
        Ok(Err(e)) => {
            // Ordinary: a caller that went away mid-handshake, one that arrived
            // before the first push and found no certificate, a source that
            // already holds its share, or a validator that left before its
            // handshake was done.
            debug!("the connection from {peer} was let go: {e}");
            return Ok(());
        }
        Err(_) => {
            debug!("the connection from {peer} did not finish its handshake in time");
            return Ok(());
        }
    };

    // The name the certificate answered for, read off the finished handshake.
    // A connection that asked for none keeps none, and `crate::route` responds
    // to such a request as misdirected — this role serves names, and a caller
    // that named none has not reached one.
    let agreed: Arc<str> = match settled.get_ref().1.server_name() {
        Some(name) => Arc::from(name),
        None => Arc::from(""),
    };

    // Rung by `responding` as each request starts.
    let asked = Arc::new(tokio::sync::Notify::new());
    let responding = hyper_util::service::TowerToHyperService::new(responding(
        hop,
        agreed,
        asked.clone(),
        &tuning,
    ));

    let mut server = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    server
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(tuning.header_timeout);
    server
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(tuning.ping_interval)
        .keep_alive_timeout(tuning.ping_interval)
        .max_concurrent_streams(tuning.streams_per_connection)
        .max_send_buf_size(SENDING);
    let mut conn = std::pin::pin!(server.serve_connection(TokioIo::new(settled), responding));

    let lifetime = tokio::time::sleep(tuning.lifetime);
    tokio::pin!(lifetime);
    let mut quiet = tuning.first_request_timeout;
    let stopping = loop {
        tokio::select! {
            ended = conn.as_mut() => {
                ended_as(ended, &peer);
                return Ok(());
            }
            () = asked.notified() => quiet = tuning.idle_timeout,
            () = tokio::time::sleep(quiet) => break "went idle",
            () = &mut lifetime => break "reached the end of its life",
        }
    };
    debug!("the connection from {peer} {stopping}");
    conn.as_mut().graceful_shutdown();
    // Its requests' bodies are bounded by this connection's own numbers, and
    // the rest of their wait by those of whichever table routed them — which
    // a push may have lengthened since. So it drains for the longer of its own
    // drain and the current one, each checked against its own table's longest
    // wait. A request routed by a table between the two, or mixing the two,
    // may wait longer than either drain. That is accepted: pushes that change
    // the numbers are rare, and a drain that ends first fails a request — it
    // exposes nothing.
    let drain = table
        .borrow()
        .tuning()
        .map_or(tuning.drain_timeout, |current| {
            current.listener.drain_timeout.max(tuning.drain_timeout)
        });
    match tokio::time::timeout(drain, conn.as_mut()).await {
        Ok(ended) => ended_as(ended, &peer),
        Err(_) => debug!("the connection from {peer} did not finish draining"),
    }
    Ok(())
}

/// Every ordinary ending of a connection is an error to the HTTP library — a
/// caller that went away, a reset, a half-close the other side did not expect,
/// or a shutdown interrupting a connection still deciding its protocol.
fn ended_as<E: std::fmt::Display>(ended: Result<(), E>, peer: &str) {
    if let Err(e) = ended {
        debug!("the connection from {peer} ended: {e}");
    }
}

/// What the tests here and in `acme` share.
#[cfg(test)]
pub(crate) mod testing {
    use std::sync::Arc;

    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::crypto::CryptoProvider;
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use tokio_rustls::rustls::{self, DigitallySignedStruct, SignatureScheme};

    /// Accepts any certificate, and any handshake signature by it: what is
    /// under test is how this role carries requests, or answers a validator,
    /// not its identity. Signatures are not checked because checking one parses
    /// the certificate as a client would, and a client refuses the critical
    /// extension a validator's answer carries.
    #[derive(Debug)]
    pub(crate) struct AnyCertificate(pub(crate) Arc<CryptoProvider>);

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
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}

/// End to end over a real socket: this role's own accept loop, the TLS that
/// terminates on a certificate it minted, and an api stand-in behind. TCP arm
/// only, because the leg to the stand-in is TCP here.
#[cfg(all(test, not(feature = "vsock")))]
mod tests {
    use super::*;

    use std::convert::Infallible;
    use std::time::Duration;

    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty, Full};
    use hyper::StatusCode;
    use hyper::client::conn::http2::SendRequest;
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
    use tokio_rustls::rustls::{self};

    use super::testing::AnyCertificate;

    use crate::route::MEASUREMENT;
    use crate::upstream::tests::{A, B, FIRST, SECOND, pushed};
    use tokio::sync::watch;

    use crate::config::testing::{FIRST_REQUEST, IDLE, LIFETIME, PER_SOURCE, STREAMS, TUNING};
    use crate::identity::attest;
    use crate::identity::key::Identity;
    use crate::route::GROUP_HEADER;

    use super::certificate::acceptor;

    const GROUP: &str = "one";
    const BODY: usize = 1 << 20;

    /// An api stand-in: HTTP/2 by prior knowledge, responding with `BODY` bytes
    /// and saying in a header which path it was asked for — which is how a test
    /// sees whether the label was taken out on the way through.
    async fn api() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(
                        |req: Request<hyper::body::Incoming>| async move {
                            let asked = req.uri().path().to_owned();
                            let mut response =
                                Response::new(Full::new(Bytes::from(vec![b'x'; BODY])));
                            response
                                .headers_mut()
                                .insert("x-asked-for", asked.parse().unwrap());
                            if let Some(authority) = req.uri().authority() {
                                response
                                    .headers_mut()
                                    .insert("x-asked-of", authority.as_str().parse().unwrap());
                            }
                            // Said back so a test can prove what stopped here.
                            let stopped = [MEASUREMENT, "host"]
                                .into_iter()
                                .chain(crate::route::FORWARDING);
                            for header in stopped {
                                if req.headers().contains_key(header) {
                                    response
                                        .headers_mut()
                                        .insert("x-arrived-with", header.parse().unwrap());
                                }
                            }
                            // An upload is read whole before the response, as
                            // api reads one — and whether trailers came with it
                            // is said back too.
                            if asked.ends_with("/upload")
                                && let Ok(whole) = req.into_body().collect().await
                            {
                                if whole.trailers().is_some() {
                                    response
                                        .headers_mut()
                                        .insert("x-arrived-with", "trailers".parse().unwrap());
                                }
                                let length = whole.to_bytes().len().to_string();
                                response
                                    .headers_mut()
                                    .insert("x-uploaded", length.parse().unwrap());
                            }
                            Ok::<_, Infallible>(response)
                        },
                    );
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        addr
    }

    /// What one group running `build` at `api` looks like as a push, under both
    /// names.
    fn table(api: &str, build: &str) -> String {
        tuned(api, build, TUNING)
    }

    /// The same, with `tuning` as its `tuning` member.
    fn tuned(api: &str, build: &str, tuning: &str) -> String {
        format!(
            r#"{{
              "groups": {{ "{GROUP}": {{ "measurement": "{build}" }} }},
              "names": {{
                "{FIRST}": {{ "{GROUP}": ["{api}"] }},
                "{SECOND}":  {{ "{GROUP}": ["{api}"] }} }},
              {tuning} }}"#
        )
    }

    /// This role on a socket of its own, with `api` as the one group declared
    /// under both names. Returns where to reach it, the SPKI its quote binds,
    /// and the sender a test pushes a later table through.
    async fn gateway(api: &str) -> (String, Vec<u8>, watch::Sender<Arc<Upstreams>>) {
        let serving = serving(api).await;
        (serving.at, serving.identity.spki().to_vec(), serving.pushes)
    }

    /// [`gateway`], and what it leaves out.
    struct Serving {
        at: String,
        /// The key this role serves on.
        identity: Arc<Identity>,
        pushes: watch::Sender<Arc<Upstreams>>,
        /// Where issued certificates arrive.
        issue: watch::Sender<Vec<crate::identity::tls::Issued>>,
        /// What a validator is answered from.
        challenges: Arc<acme::Challenges>,
        /// The ACME account's key, as the JWK this role serves.
        account: String,
    }

    async fn serving(api: &str) -> Serving {
        let identity = Arc::new(Identity::generated().unwrap());
        let spki = identity.spki().to_vec();
        let evidence = attest::evidence(spki.clone(), &crate::identity::attestor()).unwrap();
        let account = crate::identity::account::Account::generated().unwrap();

        let first = Upstreams::empty(crate::identity::attestor()).replaced(&pushed(&table(api, A)));
        let (pushes, current) = watch::channel(Arc::new(first));

        let (certificate, presented) = watch::channel(None);
        let (issue, issued) = watch::channel(Vec::new());
        tokio::spawn(super::certificate::follow(
            current.clone(),
            issued,
            identity.clone(),
            certificate,
        ));

        let listener = fleet_transport::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap().to_string();
        let hop = Arc::new(Hop::new(
            current.clone(),
            evidence,
            Bytes::copy_from_slice(account.jwk().as_bytes()),
        ));
        let challenges = Arc::new(acme::Challenges::new());
        tokio::spawn(serve(
            listener,
            hop,
            acceptor(presented.clone()),
            challenges.clone(),
            current.clone(),
        ));

        // A certificate has to exist before anything gets a response, and it
        // is minted from the first table on a task of its own — so the wait is
        // on a request that works, not on a flag this test can read.
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if presented.borrow().is_some() {
                    let mut warm = caller(&at, FIRST, 4 << 20).await;
                    let response = ask(
                        &mut warm,
                        Request::get(format!("https://{FIRST}/-{GROUP}.{A}/"))
                            .body(Empty::new())
                            .unwrap(),
                    )
                    .await;
                    if response.status() == StatusCode::OK {
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the first table is acted on and its member responds");

        Serving {
            at,
            identity,
            pushes,
            issue,
            challenges,
            account: account.jwk().to_owned(),
        }
    }

    /// Certificates an issuer signed for this role's key are what a caller
    /// asking for any served name is answered with — by a client that trusts
    /// that issuer and nothing else — whether one covers both names or each
    /// covers its own, which only the certificate for the name asked for can
    /// satisfy.
    #[tokio::test]
    async fn issued_certificates_reach_a_caller_for_every_served_name() {
        let api = api().await;
        let ca = crate::identity::tls::tests::issuer();
        let layouts: [&[&[&str]]; 2] = [&[&[FIRST, SECOND]], &[&[FIRST], &[SECOND]]];
        for layout in layouts {
            // The table's sender is held: dropped, nothing would follow the
            // certificates any more.
            let Serving {
                at,
                identity,
                issue,
                pushes: _pushes,
                ..
            } = serving(&api).await;
            let pems: Vec<String> = layout
                .iter()
                .map(|names| {
                    crate::identity::tls::tests::issued_by(
                        &ca,
                        identity.key(),
                        names,
                        (2020, 1, 1),
                        (2099, 1, 1),
                    )
                })
                .collect();
            let issued = crate::identity::tls::issued(
                &identity,
                &pems,
                &[FIRST.to_owned(), SECOND.to_owned()],
                std::time::SystemTime::now(),
            )
            .unwrap();
            issue.send_replace(issued);

            let mut roots = rustls::RootCertStore::empty();
            roots.add(ca.0.der().clone()).unwrap();
            let trusting_the_issuer = Arc::new(
                rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
            );
            let handshake = |name: &'static str| {
                let config = trusting_the_issuer.clone();
                let at = at.clone();
                async move {
                    let socket = tokio::net::TcpStream::connect(&at).await.unwrap();
                    tokio_rustls::TlsConnector::from(config)
                        .connect(ServerName::try_from(name).unwrap(), socket)
                        .await
                }
            };

            // Presented on a task of its own, so the wait is on handshakes that
            // succeed rather than on a flag.
            tokio::time::timeout(Duration::from_secs(5), async {
                while handshake(FIRST).await.is_err() || handshake(SECOND).await.is_err() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!("both names answered with an issued certificate: {layout:?}")
            });
        }
    }

    /// A handshake with this role offering `protocols`, from a source of its
    /// own: the protocol agreed, if any, and the certificate presented — or
    /// nothing if the handshake was refused.
    async fn offering(
        at: &str,
        protocols: &[&[u8]],
    ) -> Option<(Option<Vec<u8>>, CertificateDer<'static>)> {
        use tokio::io::AsyncWriteExt;

        let mut socket = tokio::net::TcpStream::connect(at).await.unwrap();
        socket
            .write_all(&header_from(fresh_source()))
            .await
            .unwrap();
        let tls = tls_to(socket, FIRST, protocols).await?;
        let (_, session) = tls.get_ref();
        Some((
            session.alpn_protocol().map(<[u8]>::to_vec),
            session.peer_certificates().unwrap()[0].clone().into_owned(),
        ))
    }

    /// A validator's connection — `acme-tls/1` and nothing else — for a name
    /// the host armed is answered here, as RFC 8737 asks. With nothing armed it
    /// is refused, as a protocol this role does not speak is; and one offering
    /// anything beside `acme-tls/1` is served as any other.
    #[tokio::test]
    async fn a_validator_is_answered_for_an_armed_name() {
        const KEY_AUTHORIZATION: &str = "token_-0.thumbprint_-0";
        let api = api().await;
        let Serving {
            at,
            challenges,
            pushes: _pushes,
            ..
        } = serving(&api).await;

        assert!(
            offering(&at, &[b"acme-tls/1"]).await.is_none(),
            "nothing armed yet, so the handshake is refused"
        );

        challenges.arm(FIRST, KEY_AUTHORIZATION).unwrap();
        let (agreed, presented) = offering(&at, &[b"acme-tls/1"]).await.expect("answered");
        assert_eq!(agreed.as_deref(), Some(&b"acme-tls/1"[..]));
        assert!(super::acme::tests::answers_for(
            &presented,
            FIRST,
            KEY_AUTHORIZATION
        ));

        let (agreed, presented) = offering(&at, &[b"acme-tls/1", b"h2"])
            .await
            .expect("served as any other");
        assert_eq!(agreed.as_deref(), Some(&b"h2"[..]));
        assert!(!super::acme::tests::answers_for(
            &presented,
            FIRST,
            KEY_AUTHORIZATION
        ));
    }

    /// A source no other caller in this process has, so that a test's own
    /// connections never meet another's share.
    fn fresh_source() -> std::net::SocketAddr {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::net::SocketAddr::from((std::net::Ipv4Addr::from(0x0a00_0000 | n), 40_000))
    }

    /// The header the host's first hop writes, by an implementation other than
    /// this role's.
    fn header_from(source: std::net::SocketAddr) -> Vec<u8> {
        use ppp::v2::{Builder, Command, Protocol, Version};
        let destination: std::net::SocketAddr = "198.51.100.1:443".parse().unwrap();
        Builder::with_addresses(
            Version::Two | Command::Proxy,
            Protocol::Stream,
            (source, destination),
        )
        .build()
        .unwrap()
    }

    /// One public HTTP/2 connection to a name, from a source of its own,
    /// receiving with the given window.
    async fn caller(at: &str, name: &str, window: u32) -> SendRequest<Empty<Bytes>> {
        opened(at, name, window, fresh_source())
            .await
            .expect("a caller with a source of its own is let in")
    }

    /// The same from a given source, or nothing if the connection is let go
    /// before its handshake finishes.
    async fn opened(
        at: &str,
        name: &str,
        window: u32,
        source: std::net::SocketAddr,
    ) -> Option<SendRequest<Empty<Bytes>>> {
        opened_for(at, name, window, source).await
    }

    /// The same, for requests carrying bodies of type `B`.
    async fn opened_for<B>(
        at: &str,
        name: &str,
        window: u32,
        source: std::net::SocketAddr,
    ) -> Option<SendRequest<B>>
    where
        B: hyper::body::Body + Send + Unpin + 'static,
        B::Data: Send,
        B::Error: Into<tower::BoxError>,
    {
        use tokio::io::AsyncWriteExt;

        let mut socket = tokio::net::TcpStream::connect(at).await.unwrap();
        socket.write_all(&header_from(source)).await.unwrap();
        handshake_for(socket, name, window).await
    }

    async fn handshake(
        socket: tokio::net::TcpStream,
        name: &str,
        window: u32,
    ) -> Option<SendRequest<Empty<Bytes>>> {
        handshake_for(socket, name, window).await
    }

    async fn handshake_for<B>(
        socket: tokio::net::TcpStream,
        name: &str,
        window: u32,
    ) -> Option<SendRequest<B>>
    where
        B: hyper::body::Body + Send + Unpin + 'static,
        B::Data: Send,
        B::Error: Into<tower::BoxError>,
    {
        let tls = tls_to(socket, name, &[b"h2"]).await?;
        let (sender, driver) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .initial_stream_window_size(window)
            .initial_connection_window_size(window)
            .handshake(TokioIo::new(tls))
            .await
            .ok()?;
        tokio::spawn(driver);
        Some(sender)
    }

    /// The TLS a caller opens to `name`, offering `protocols`.
    async fn tls_to(
        socket: tokio::net::TcpStream,
        name: &str,
        protocols: &[&[u8]],
    ) -> Option<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
            .with_no_client_auth();
        config.alpn_protocols = protocols.iter().map(|p| p.to_vec()).collect();
        tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(name.to_owned()).unwrap(), socket)
            .await
            .ok()
    }

    async fn ask(
        caller: &mut SendRequest<Empty<Bytes>>,
        request: Request<Empty<Bytes>>,
    ) -> Response<hyper::body::Incoming> {
        caller.ready().await.unwrap();
        caller.send_request(request).await.unwrap()
    }

    /// The label and its build travel in the path, are taken out on the way
    /// through, and api sees the path it published.
    #[tokio::test]
    async fn a_marked_label_routes_and_is_taken_out() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let mut caller = caller(&at, FIRST, 4 << 20).await;

        // With the header this hop reads, which must stop here on this route as
        // on every other.
        let response = ask(
            &mut caller,
            Request::get(format!(
                "https://{FIRST}/-{GROUP}.{A}/api/v1/sessions/7/status"
            ))
            .header(MEASUREMENT, A)
            .body(Empty::new())
            .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["x-asked-for"],
            "/api/v1/sessions/7/status"
        );
        assert!(
            !response.headers().contains_key("x-arrived-with"),
            "what this hop reads stops at this hop, whichever way it routed"
        );
    }

    /// A link's marker with nothing after it is sent on to the same marker
    /// with a slash, its query kept: the page served there loads what it needs
    /// relatively, against the path up to its last slash.
    #[tokio::test]
    async fn a_bare_marker_is_sent_on_with_a_slash() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let mut caller = caller(&at, FIRST, 4 << 20).await;
        let response = ask(
            &mut caller,
            Request::get(format!("https://{FIRST}/-{GROUP}.{A}?from=link"))
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            response.headers()[hyper::header::LOCATION],
            format!("/-{GROUP}.{A}/?from=link").as_str()
        );
    }

    /// What a page under a marker loads relatively — an asset, a call to api —
    /// is under the marker as well, and reaches api at its own path.
    #[tokio::test]
    async fn what_a_page_loads_under_its_marker_reaches_api_at_its_own_path() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let mut caller = caller(&at, FIRST, 4 << 20).await;
        for path in ["assets/index.js", "api/v1/sessions/7/status"] {
            let response = ask(
                &mut caller,
                Request::get(format!("https://{FIRST}/-{GROUP}.{A}/{path}"))
                    .body(Empty::new())
                    .unwrap(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(
                response.headers()["x-asked-for"],
                format!("/{path}").as_str()
            );
        }
    }

    /// A path with no marker is not a link, and a label nobody carries gets
    /// the same response as an upstream that would not talk.
    #[tokio::test]
    async fn a_path_without_a_label_and_a_label_nobody_has() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let mut caller = caller(&at, FIRST, 4 << 20).await;

        let bare = ask(
            &mut caller,
            Request::get(format!("https://{FIRST}/api/v1/sessions/7/status"))
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(bare.status(), StatusCode::BAD_REQUEST);

        let elsewhere = ask(
            &mut caller,
            Request::get(format!("https://{FIRST}/-somewhere.{A}/"))
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(elsewhere.status(), StatusCode::BAD_GATEWAY);
    }

    /// A label with no build beside it is refused, not routed: routed, it would
    /// follow whatever the host declares under that label.
    #[tokio::test]
    async fn a_label_without_its_build_is_refused() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let mut caller = caller(&at, FIRST, 4 << 20).await;

        for path in [
            format!("/-{GROUP}/api/v1/sessions/7/status"),
            format!("/-{GROUP}./"),
            format!("/-.{A}/"),
        ] {
            let response = ask(
                &mut caller,
                Request::get(format!("https://{FIRST}{path}"))
                    // Even with the build named where a caller that can set a
                    // header would name it: the link has to carry its own.
                    .header(MEASUREMENT, A)
                    .body(Empty::new())
                    .unwrap(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        }
    }

    /// The attack a bare label allowed: the host re-declares the label under
    /// another build, and a link written for the first no longer reaches
    /// anything — it is refused rather than moved.
    #[tokio::test]
    async fn a_link_does_not_follow_its_label_onto_another_build() {
        let api = api().await;
        let (at, _, pushes) = gateway(&api).await;
        let mut caller = caller(&at, FIRST, 4 << 20).await;
        let link = format!("https://{FIRST}/-{GROUP}.{A}/");

        let before = ask(&mut caller, Request::get(&link).body(Empty::new()).unwrap()).await;
        assert_eq!(before.status(), StatusCode::OK);

        // The host says the same label runs something else now.
        let next = Upstreams::empty(crate::identity::attestor()).replaced(&pushed(&table(&api, B)));
        pushes.send_replace(Arc::new(next));

        let after = ask(&mut caller, Request::get(&link).body(Empty::new()).unwrap()).await;
        assert_eq!(
            after.status(),
            StatusCode::BAD_GATEWAY,
            "the link names build A, and the label no longer runs it"
        );

        // The label with the build it runs now is a different link, and routes.
        let rewritten = ask(
            &mut caller,
            Request::get(format!("https://{FIRST}/-{GROUP}.{B}/"))
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(rewritten.status(), StatusCode::OK);
    }

    /// A build named in a header and a different one in the link are refused,
    /// rather than resolved in favour of either.
    #[tokio::test]
    async fn a_named_build_that_contradicts_the_link_is_refused() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let mut caller = caller(&at, FIRST, 4 << 20).await;

        let contradicted = ask(
            &mut caller,
            Request::get(format!("https://{FIRST}/-{GROUP}.{A}/"))
                .header(MEASUREMENT, B)
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(contradicted.status(), StatusCode::BAD_REQUEST);

        let twice = ask(
            &mut caller,
            Request::get(format!("https://{FIRST}/-{GROUP}.{A}/"))
                .header(MEASUREMENT, A)
                .header(MEASUREMENT, A)
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(twice.status(), StatusCode::BAD_REQUEST);
    }

    /// A caller naming a build is placed, told its group in the form a link
    /// carries it, and comes back naming that group — with no build to name.
    #[tokio::test]
    async fn a_caller_is_placed_and_names_its_group_from_then_on() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let mut second = caller(&at, SECOND, 4 << 20).await;

        let placed = ask(
            &mut second,
            Request::get(format!("https://{SECOND}/api/v1/sessions"))
                .header(MEASUREMENT, A)
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(placed.status(), StatusCode::OK);
        let group = placed.headers()[GROUP_HEADER].to_str().unwrap().to_owned();
        assert_eq!(group, format!("{GROUP}.{A}"));
        assert!(
            !placed.headers().contains_key("x-arrived-with"),
            "what this hop reads stops at this hop"
        );

        let again = ask(
            &mut second,
            Request::get(format!("https://{SECOND}/-{group}/api/v1/sessions/1"))
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(again.status(), StatusCode::OK);
        assert_eq!(again.headers()["x-asked-for"], "/api/v1/sessions/1");
        assert!(
            !again.headers().contains_key(GROUP_HEADER),
            "a caller that named its group is told nothing"
        );

        // With neither there is nothing to place on and nothing to return to.
        let naked = ask(
            &mut second,
            Request::get(format!("https://{SECOND}/api/v1/sessions"))
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(naked.status(), StatusCode::BAD_REQUEST);
    }

    /// A name's rules hold creating a session to placement, and every request
    /// about one to naming its group — over a real connection, as pushed.
    #[tokio::test]
    async fn a_name_s_rules_hold_its_requests() {
        let api = api().await;
        let (at, _, pushes) = gateway(&api).await;
        let ruled = table(&api, A).replace(
            &format!(r#""{SECOND}":  {{ "{GROUP}": ["{api}"] }} }},"#),
            &format!(
                r#""{SECOND}":  {{ "{GROUP}": ["{api}"] }} }},
                "routes": {{ "{SECOND}": [
                  {{ "method": "POST", "path": "/api/v1/sessions", "flags": ["reject_named_group"] }},
                  {{ "path": "/api/v1/sessions/{{*rest}}", "flags": ["require_named_group"] }} ] }},"#
            ),
        );
        assert_ne!(ruled, table(&api, A));
        let next = pushes.borrow().replaced(&pushed(&ruled));
        pushes.send_replace(Arc::new(next));
        let mut second = caller(&at, SECOND, 4 << 20).await;
        let status = |method: &str, path: String, build: Option<&str>| {
            let mut request = Request::builder()
                .method(method)
                .uri(format!("https://{SECOND}{path}"));
            if let Some(build) = build {
                request = request.header(MEASUREMENT, build);
            }
            request.body(Empty::new()).unwrap()
        };

        let created = ask(
            &mut second,
            status("POST", "/api/v1/sessions".into(), Some(A)),
        )
        .await;
        assert_eq!(created.status(), StatusCode::OK);
        assert!(created.headers().contains_key(GROUP_HEADER));

        let pinned = ask(
            &mut second,
            status("POST", format!("/-{GROUP}.{A}/api/v1/sessions"), None),
        )
        .await;
        assert_eq!(
            pinned.status(),
            StatusCode::BAD_REQUEST,
            "a creation names no group"
        );

        let unnamed = ask(
            &mut second,
            status("GET", "/api/v1/sessions/1".into(), Some(A)),
        )
        .await;
        assert_eq!(
            unnamed.status(),
            StatusCode::BAD_REQUEST,
            "a session's request names one"
        );

        let named = ask(
            &mut second,
            status("GET", format!("/-{GROUP}.{A}/api/v1/sessions/1"), None),
        )
        .await;
        assert_eq!(named.status(), StatusCode::OK);

        // The rules are the second name's; the first holds its requests to none.
        let mut first = caller(&at, FIRST, 4 << 20).await;
        let elsewhere = ask(
            &mut first,
            Request::get(format!("https://{FIRST}/api/v1/sessions/1"))
                .header(MEASUREMENT, A)
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(elsewhere.status(), StatusCode::OK);
    }

    /// A build closed to new sessions is gone for them — said so, and not to be
    /// cached — while its links still answer, across the push that closed it; a
    /// later push reopens it.
    #[tokio::test]
    async fn a_closed_build_is_gone_for_new_sessions_over_a_connection() {
        let api = api().await;
        let (at, _, pushes) = gateway(&api).await;
        let ruled = |refused: &str| {
            table(&api, A).replace(
                &format!(r#""{SECOND}":  {{ "{GROUP}": ["{api}"] }} }},"#),
                &format!(
                    r#""{SECOND}":  {{ "{GROUP}": ["{api}"] }} }},
                    "routes": {{ "{SECOND}": [
                      {{ "method": "POST", "path": "/api/v1/sessions", "flags": ["reject_named_group"],
                         "refuse_measurements": [{refused}] }},
                      {{ "path": "/api/v1/sessions/{{*rest}}", "flags": ["require_named_group"] }} ] }},"#
                ),
            )
        };
        let push = |body: String| {
            let next = pushes.borrow().replaced(&pushed(&body));
            pushes.send_replace(Arc::new(next));
        };
        let create = || {
            Request::post(format!("https://{SECOND}/api/v1/sessions"))
                .header(MEASUREMENT, A)
                .body(Empty::new())
                .unwrap()
        };

        push(ruled(&format!(r#""{A}""#)));
        let mut second = caller(&at, SECOND, 4 << 20).await;
        let gone = ask(&mut second, create()).await;
        assert_eq!(gone.status(), StatusCode::GONE);
        assert_eq!(
            gone.headers().get(hyper::header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert!(!gone.headers().contains_key(GROUP_HEADER), "placed nowhere");

        let link = ask(
            &mut second,
            Request::get(format!("https://{SECOND}/-{GROUP}.{A}/api/v1/sessions/1"))
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(link.status(), StatusCode::OK, "its sessions finish");

        push(ruled(""));
        let reopened = ask(&mut second, create()).await;
        assert_eq!(reopened.status(), StatusCode::OK);
        assert!(reopened.headers().contains_key(GROUP_HEADER));
    }

    /// A request goes on to api under the name its connection agreed to,
    /// spelled as that name is — not with the case, port or final dot the
    /// caller wrote, and without its `Host`.
    #[tokio::test]
    async fn a_request_goes_on_under_the_name_its_connection_agreed_to() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let mut caller = caller(&at, FIRST, 4 << 20).await;
        let response = ask(
            &mut caller,
            Request::get(format!(
                "https://{}:8443/-{GROUP}.{A}/",
                FIRST.to_ascii_uppercase()
            ))
            .header("host", format!("{FIRST}."))
            .body(Empty::new())
            .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-asked-of"], FIRST);
        assert!(
            !response.headers().contains_key("x-arrived-with"),
            "and without the Host the caller wrote"
        );
    }

    /// A request asked of another name than its connection agreed to — in its
    /// target or its `Host` — is misdirected, whether or not this role serves
    /// that name too: a browser that pooled the connection asks again on one
    /// of the right name.
    #[tokio::test]
    async fn a_request_asked_of_another_name_is_misdirected() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let mut caller = caller(&at, FIRST, 4 << 20).await;
        for (target, host) in [
            (SECOND, None),
            ("elsewhere.example.com", None),
            (FIRST, Some(SECOND)),
        ] {
            let mut request = Request::get(format!("https://{target}/-{GROUP}.{A}/"));
            if let Some(host) = host {
                request = request.header("host", host);
            }
            let response = ask(&mut caller, request.body(Empty::new()).unwrap()).await;
            assert_eq!(
                response.status(),
                StatusCode::MISDIRECTED_REQUEST,
                "{target} {host:?}"
            );
        }
    }

    /// On HTTP/1.1 the name is the `Host` header alone, and it is held to the
    /// connection's name the same way.
    #[tokio::test]
    async fn an_http1_request_is_held_to_its_connection_s_name() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let socket = tokio::net::TcpStream::connect(&at).await.unwrap();
        let tls = tls_to(socket, FIRST, &[b"http/1.1"]).await.unwrap();
        let (mut caller, driver) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(driver);
        let mut asked_as = async |host: &str| {
            caller.ready().await.unwrap();
            let response = caller
                .send_request(
                    Request::get(format!("/-{GROUP}.{A}/"))
                        .header("host", host)
                        .body(Empty::<Bytes>::new())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            // Read to its end, so the connection takes the next request.
            response.into_body().collect().await.unwrap();
            status
        };
        assert_eq!(asked_as(FIRST).await, StatusCode::OK);
        assert_eq!(asked_as(SECOND).await, StatusCode::MISDIRECTED_REQUEST);
    }

    /// A target that is not a path — a host alone, or `*` — is refused rather
    /// than routed: a name's rules read the path, and this one would have gone
    /// on to api as a path they never read.
    #[tokio::test]
    async fn a_target_that_is_not_a_path_is_refused() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let socket = tokio::net::TcpStream::connect(&at).await.unwrap();
        let tls = tls_to(socket, FIRST, &[b"http/1.1"]).await.unwrap();
        let (mut caller, driver) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(driver);
        for target in [FIRST, "*", "/"] {
            caller.ready().await.unwrap();
            let response = caller
                .send_request(
                    Request::get(target)
                        .header("host", FIRST)
                        .header(MEASUREMENT, A)
                        .body(Empty::<Bytes>::new())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            response.into_body().collect().await.unwrap();
            let expected = match target {
                "/" => StatusCode::OK,
                _ => StatusCode::BAD_REQUEST,
            };
            assert_eq!(status, expected, "{target}");
        }
    }

    /// A build nobody runs gets the same response as an upstream that would
    /// not talk, and two measurements are refused rather than resolved to
    /// whichever came first.
    #[tokio::test]
    async fn a_build_nobody_runs_and_a_build_named_twice() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let mut second = caller(&at, SECOND, 4 << 20).await;

        let nobody = ask(
            &mut second,
            Request::get(format!("https://{SECOND}/api/v1/sessions"))
                .header(MEASUREMENT, "c".repeat(96))
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(nobody.status(), StatusCode::BAD_GATEWAY);

        let twice = ask(
            &mut second,
            Request::get(format!("https://{SECOND}/api/v1/sessions"))
                .header(MEASUREMENT, A)
                .header(MEASUREMENT, A)
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(twice.status(), StatusCode::BAD_REQUEST);
    }

    /// A caller's account of where it came from stops here — each header that
    /// names an origin, each value of it — and the rest of the request goes on.
    #[tokio::test]
    async fn a_caller_s_account_of_its_origin_stops_here() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let mut caller = caller(&at, FIRST, 4 << 20).await;
        let mut request = Request::get(format!("https://{FIRST}/-{GROUP}.{A}/"));
        for header in crate::route::FORWARDING {
            request = request
                .header(header, "203.0.113.7")
                .header(header, "198.51.100.9");
        }
        let response = ask(&mut caller, request.body(Empty::new()).unwrap()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            !response.headers().contains_key("x-arrived-with"),
            "arrived with {:?}",
            response.headers().get("x-arrived-with")
        );
    }

    /// An upload's trailers stop here, whatever they carry, and its data goes
    /// on whole.
    #[tokio::test]
    async fn an_upload_s_trailers_stop_here() {
        use http_body_util::channel::Channel;

        let (at, _, _pushes) = gateway(&api().await).await;
        let mut uploader: SendRequest<Channel<Bytes, Infallible>> =
            opened_for(&at, FIRST, 4 << 20, fresh_source())
                .await
                .unwrap();
        let (mut sending, body) = Channel::<Bytes, Infallible>::new(2);
        sending
            .send_data(Bytes::from_static(b"the whole of it"))
            .await
            .unwrap();
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
        trailers.insert(MEASUREMENT, A.parse().unwrap());
        sending.send_trailers(trailers).await.unwrap();
        drop(sending);

        uploader.ready().await.unwrap();
        let response = uploader
            .send_request(
                Request::post(format!("https://{FIRST}/-{GROUP}.{A}/upload"))
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-uploaded"], "15");
        assert!(
            !response.headers().contains_key("x-arrived-with"),
            "arrived with {:?}",
            response.headers().get("x-arrived-with")
        );
    }

    /// A name this role does not answer to is told so — and the name is the one
    /// the HANDSHAKE settled, which is what makes routing by it worth anything.
    #[tokio::test]
    async fn a_name_this_role_does_not_serve_is_misdirected() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let mut stranger = caller(&at, "elsewhere.example.com", 4 << 20).await;
        let response = ask(
            &mut stranger,
            Request::get("https://elsewhere.example.com/")
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
    }

    /// And a caller that agreed to one name cannot reach another by asking for
    /// it in the request. The `Host` is the caller's to write; the name that
    /// routes is the one it negotiated a certificate for.
    #[tokio::test]
    async fn the_host_header_does_not_choose_the_name() {
        let (at, _, _pushes) = gateway(&api().await).await;
        // Negotiated for a name this role does not serve, then claims one it
        // does. If `Host` were what routed, this would be served.
        let mut liar = caller(&at, "elsewhere.example.com", 4 << 20).await;
        let response = ask(
            &mut liar,
            Request::get(format!("https://{FIRST}/-{GROUP}.{A}/"))
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
    }

    /// The quote this role serves binds the key it is serving over, and the
    /// response needs no api behind it and no build named.
    #[tokio::test]
    async fn the_attestation_binds_the_serving_key() {
        let (at, spki, _pushes) = gateway(&api().await).await;
        let mut caller = caller(&at, FIRST, 4 << 20).await;

        let response = ask(
            &mut caller,
            Request::get(format!("https://{FIRST}{}", attest::PATH))
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[hyper::header::CONTENT_TYPE],
            attest::CONTENT_TYPE
        );

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let quote = enclavid_ra_tls::read_evidence(&body).unwrap();
        crate::identity::attestor()
            .verify(
                &quote,
                &enclavid_attestation::ReportData::for_ratls(spki.clone()),
            )
            .expect("the quote binds the key this role serves over");

        // And a quote bound to some OTHER key does not pass the same check,
        // which is what makes the assertion above worth making.
        let other = Identity::generated().unwrap();
        assert!(
            crate::identity::attestor()
                .verify(
                    &quote,
                    &enclavid_attestation::ReportData::for_ratls(other.spki().to_vec())
                )
                .is_err()
        );
    }

    /// The ACME account's key is served beside the quote, on the same
    /// connection, needing no api behind it — and only read, never posted to.
    #[tokio::test]
    async fn the_account_key_is_served_beside_the_quote() {
        let Serving {
            at,
            account,
            pushes: _pushes,
            ..
        } = serving(&api().await).await;
        let mut caller = caller(&at, FIRST, 4 << 20).await;

        let response = ask(
            &mut caller,
            Request::get(format!("https://{FIRST}{}", crate::identity::account::PATH))
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[hyper::header::CONTENT_TYPE],
            crate::identity::account::CONTENT_TYPE
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, account.as_bytes());

        let response = ask(
            &mut caller,
            Request::post(format!("https://{FIRST}{}", crate::identity::account::PATH))
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    /// A caller that stops reading must not stall anyone else.
    ///
    /// It opens streams and reads none of their bodies, each leaving up to
    /// `BODY` bytes of api's response unread behind this role. A leg
    /// carries one request at a time and travels with the body, so what
    /// those hold up is their own legs and nothing else; another caller's
    /// request takes a leg of its own.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_caller_that_stops_reading_does_not_stall_another() {
        let (at, _, _pushes) = gateway(&api().await).await;

        let mut attacker = caller(&at, FIRST, 65_535).await;
        let mut unread = Vec::new();
        for _ in 0..STREAMS {
            let response = ask(
                &mut attacker,
                Request::get(format!("https://{FIRST}/-{GROUP}.{A}/"))
                    .body(Empty::new())
                    .unwrap(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            unread.push(response);
        }

        let mut victim = caller(&at, FIRST, 4 << 20).await;
        let body = tokio::time::timeout(Duration::from_secs(10), async {
            let response = ask(
                &mut victim,
                Request::get(format!("https://{FIRST}/-{GROUP}.{A}/"))
                    .body(Empty::new())
                    .unwrap(),
            )
            .await;
            response.into_body().collect().await.unwrap().to_bytes()
        })
        .await
        .expect("a response must not wait on a caller that stopped reading");
        assert_eq!(body.len(), BODY);
        drop(unread);
    }

    /// A caller that connects and sends nothing — no header, no handshake — is
    /// let go, and the place it held with it.
    #[tokio::test]
    async fn a_caller_that_never_starts_a_handshake_is_let_go() {
        use tokio::io::AsyncReadExt;

        let (at, _, _pushes) = gateway(&api().await).await;
        let mut silent = tokio::net::TcpStream::connect(&at).await.unwrap();
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), silent.read_to_end(&mut rest))
            .await
            .expect("the listener closed a connection that never started a handshake")
            .unwrap();
    }

    /// In a build whose attestation is a stand-in, a connection that starts
    /// with the caller's own ClientHello is served: what was read looking for a
    /// header goes back in front of the handshake, untouched.
    #[tokio::test]
    async fn a_connection_without_a_header_is_served_in_this_build() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let socket = tokio::net::TcpStream::connect(&at).await.unwrap();
        let mut caller = handshake(socket, FIRST, 4 << 20)
            .await
            .expect("the handshake finishes without a header");
        let response = ask(
            &mut caller,
            Request::get(format!("https://{FIRST}/-{GROUP}.{A}/"))
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// One source holds its share of the places and no more, while another is
    /// let in beside it — and a place it gives back can be taken again.
    #[tokio::test]
    async fn one_source_holds_no_more_than_its_share() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let crowd = fresh_source();

        // Each held connection asks once, so it is given IDLE rather than
        // FIRST_REQUEST: what frees a place below must be the drop, not a timer.
        let mut held = Vec::new();
        for _ in 0..PER_SOURCE {
            let mut connection = opened(&at, FIRST, 4 << 20, crowd).await.unwrap();
            let response = ask(
                &mut connection,
                Request::get(format!("https://{FIRST}/-{GROUP}.{A}/"))
                    .body(Empty::new())
                    .unwrap(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            held.push(connection);
        }
        assert!(
            opened(&at, FIRST, 4 << 20, crowd).await.is_none(),
            "one past the share is let go"
        );

        let mut other = opened(&at, FIRST, 4 << 20, fresh_source())
            .await
            .expect("another source is not held to the first one's share");
        let response = ask(
            &mut other,
            Request::get(format!("https://{FIRST}/-{GROUP}.{A}/"))
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        // The place comes back once this role sees the connection close, which
        // is after the caller drops it — so the wait is on a connection that
        // works, not on a guess at how long that takes. Bounded well inside
        // IDLE, so it is the drop that gave the place back.
        drop(held.pop());
        tokio::time::timeout(IDLE / 2, async {
            while opened(&at, FIRST, 4 << 20, crowd).await.is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("a place given back can be taken again");
    }

    /// Wait until the connection behind `caller` has been closed, or `within`.
    async fn closed_within(caller: &SendRequest<Empty<Bytes>>, within: Duration) -> bool {
        tokio::time::timeout(within, async {
            while !caller.is_closed() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .is_ok()
    }

    /// A caller that finishes the handshake and then asks for nothing is let
    /// go too — the case no protocol timeout covers, because an HTTP/2 caller
    /// that answers pings looks perfectly alive. And it is let go well before
    /// the gap allowed between two requests: it has not made a first one.
    #[tokio::test]
    async fn a_caller_that_asks_for_nothing_is_let_go() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let idle = caller(&at, FIRST, 4 << 20).await;
        assert!(
            closed_within(&idle, IDLE / 2).await,
            "closed after FIRST_REQUEST, not after IDLE"
        );
    }

    /// Once a request has been made, the connection is given the whole gap
    /// between requests, not the short wait for a first one.
    #[tokio::test]
    async fn a_caller_that_has_asked_is_given_the_gap_between_requests() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let mut caller = caller(&at, FIRST, 4 << 20).await;
        let response = ask(
            &mut caller,
            Request::get(format!("https://{FIRST}/-{GROUP}.{A}/"))
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        drop(response);

        assert!(
            !closed_within(&caller, FIRST_REQUEST * 3).await,
            "still open well past FIRST_REQUEST"
        );
        // Bounded so it ends before LIFETIME would close the connection anyway.
        assert!(
            closed_within(&caller, IDLE * 3 / 2).await,
            "and let go once IDLE has passed"
        );
    }

    /// A caller that keeps asking never goes idle, and is let go all the same
    /// once its connection has lived LIFETIME — which is what gives its place
    /// back, and ends any stream on it whose response nobody reads.
    #[tokio::test]
    async fn a_busy_connection_is_let_go_at_the_end_of_its_life() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let opened = std::time::Instant::now();
        let mut busy = caller(&at, FIRST, 4 << 20).await;
        let asked_until_closed = tokio::time::timeout(LIFETIME * 3, async {
            loop {
                if busy.ready().await.is_err() {
                    return;
                }
                let request = Request::get(format!("https://{FIRST}/-{GROUP}.{A}/"))
                    .body(Empty::new())
                    .unwrap();
                match busy.send_request(request).await {
                    Ok(response) => drop(response),
                    Err(_) => return,
                }
                tokio::time::sleep(IDLE / 4).await;
            }
        })
        .await;
        assert!(
            asked_until_closed.is_ok(),
            "a connection asking every IDLE/4 is let go after LIFETIME"
        );
        assert!(
            opened.elapsed() >= LIFETIME,
            "and not before: it was busy the whole time"
        );
    }

    /// Push a table granting `connections`, one per source, with timeouts long
    /// enough that no connection a test holds is let go while it runs — so what
    /// frees a place is the limit, never a timer.
    fn grant(pushes: &watch::Sender<Arc<Upstreams>>, api: &str, connections: usize) {
        let tuning = TUNING
            .replace(
                r#""connections": 256, "connections_per_source": 2"#,
                &format!(r#""connections": {connections}, "connections_per_source": 1"#),
            )
            .replace(
                r#""first_request_timeout_ms": 100, "idle_timeout_ms": 1000, "lifetime_ms": 3000"#,
                r#""first_request_timeout_ms": 5000, "idle_timeout_ms": 10000, "lifetime_ms": 30000"#,
            );
        let next = pushes.borrow().replaced(&pushed(&tuned(api, A, &tuning)));
        pushes.send_replace(Arc::new(next));
    }

    /// A connection from a source of its own, once the listener takes it.
    async fn taken(at: &str) -> SendRequest<Empty<Bytes>> {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(caller) = opened(at, FIRST, 4 << 20, fresh_source()).await {
                    return caller;
                }
            }
        })
        .await
        .expect("the listener takes it")
    }

    /// Whether the listener takes a new connection within a moment.
    async fn let_in(at: &str) -> bool {
        tokio::time::timeout(
            Duration::from_millis(300),
            opened(at, FIRST, 4 << 20, fresh_source()),
        )
        .await
        .is_ok_and(|opened| opened.is_some())
    }

    /// Raised, the limit takes more connections at once, while the ones it
    /// already held stay open.
    #[tokio::test]
    async fn a_raised_connection_limit_takes_more_at_once() {
        let api = api().await;
        let (at, _, pushes) = gateway(&api).await;
        grant(&pushes, &api, 2);
        let _held = (taken(&at).await, taken(&at).await);
        assert!(!let_in(&at).await, "the limit holds");

        grant(&pushes, &api, 4);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), taken(&at))
                .await
                .is_ok(),
            "raised, a new connection is taken while the others stay open"
        );
    }

    /// Lowered below what is open, the limit cuts nothing, and a new connection
    /// waits — even after one of the open ones closes, since that place is
    /// taken back.
    #[tokio::test]
    async fn a_lowered_connection_limit_cuts_nothing_and_holds_new_ones_back() {
        let api = api().await;
        let (at, _, pushes) = gateway(&api).await;
        grant(&pushes, &api, 256);
        let asked = |caller: &mut SendRequest<Empty<Bytes>>| {
            let request = Request::get(format!("https://{FIRST}/-{GROUP}.{A}/"))
                .body(Empty::new())
                .unwrap();
            let mut caller = caller.clone();
            async move { ask(&mut caller, request).await.status() }
        };

        let mut first = taken(&at).await;
        let mut second = taken(&at).await;
        grant(&pushes, &api, 1);

        assert_eq!(
            asked(&mut first).await,
            StatusCode::OK,
            "nothing open is cut"
        );
        assert_eq!(
            asked(&mut second).await,
            StatusCode::OK,
            "nothing open is cut"
        );
        // The listener may already hold the place for its next connection,
        // taken before the push: that one comes in, and no other.
        let _early = let_in(&at).await;
        assert!(!let_in(&at).await, "over the new limit, a new one waits");

        drop(first);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !let_in(&at).await,
            "the place the first gave back is taken back"
        );
        drop(second);
    }

    /// The layer that catches a panic, given `crate::route::panicked` as the
    /// stack in `responding` gives it, responds as to a failure behind this
    /// role: an empty 502. That the stack puts the layer outermost is not
    /// checked here — no request can make the real hop panic.
    #[tokio::test]
    async fn a_panic_gets_the_response_of_a_failure_behind_this_role() {
        use tower::{Service, ServiceExt};

        let mut responding = tower::ServiceBuilder::new()
            .layer(CatchPanicLayer::custom(crate::route::panicked))
            .service_fn(
                |_: Request<()>| -> std::future::Ready<Result<Response<Empty<Bytes>>, Infallible>> {
                    panic!("what a caller sent")
                },
            );
        let response = responding
            .ready()
            .await
            .unwrap()
            .call(Request::new(()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty(), "and says nothing of what the panic said");
    }

    /// An upload that stops arriving is cut off after the pause, and its
    /// caller gets a response — so it holds its member's place no longer
    /// than that, though api would have waited for the rest of it for ever.
    #[tokio::test]
    async fn a_stalled_upload_is_cut_off_after_the_pause() {
        use http_body_util::channel::Channel;

        let (at, _, _pushes) = gateway(&api().await).await;
        let mut uploader: SendRequest<Channel<Bytes, Infallible>> =
            opened_for(&at, FIRST, 4 << 20, fresh_source())
                .await
                .unwrap();
        let (mut sending, body) = Channel::<Bytes, Infallible>::new(1);
        sending
            .send_data(Bytes::from_static(b"the start of it"))
            .await
            .unwrap();

        let responded = tokio::time::timeout(crate::config::testing::BODY / 2, async {
            uploader.ready().await.unwrap();
            uploader
                .send_request(
                    Request::post(format!("https://{FIRST}/-{GROUP}.{A}/upload"))
                        .body(body)
                        .unwrap(),
                )
                .await
                .unwrap()
        })
        .await
        .expect("cut off after the pause, not left for the whole body's deadline");
        assert_eq!(responded.status(), StatusCode::BAD_GATEWAY);
        drop(sending);
    }
}
