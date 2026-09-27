//! The port the host pushes configuration to.
//!
//! The host dials this guest's own CID, as it does for the health port, and
//! sends the whole table with `PUT /config`. Nothing on the host has to be
//! running for this role to keep serving; the host speaks when the fleet changes.
//!
//! ## And certificates an issuer signed
//!
//! The host reads a request for a certificate with `GET /csr` — over the names
//! it pushed, or over any it asks for, pushed or about to be — has an issuer
//! sign it, and carries the chain in its next push, among the table's
//! `certificates`. This role never talks to an issuer: the challenge, the
//! account and whatever the issuer wants happen on the host, and what crosses
//! this port is public — a request any holder of the names could ask for, and
//! certificates that are useless without the key they name, which never leaves
//! this guest. See `crate::identity::tls::issued` for what is checked before
//! they are presented, and `crate::listener::certificate` for how they are.
//!
//! In the push rather than beside it, because a push is the whole of what the
//! host says: the push after a restart restores the certificates with the rest,
//! and one without any presents none. Together they cover every name the push
//! declares, or the push is refused, so no name is served on this role's own
//! certificate while issued ones are in use. How the names are split among
//! them is the host's: one for all, one each, or as its issuer handed them
//! out. A name is added by asking for a request over it —
//! `GET /csr?names=c.example` — having it issued, and pushing the name and its
//! certificate together. An issuer validating over TLS-ALPN-01 reaches the
//! host's ACME client through this role, for names pushed or not yet — see
//! `crate::listener::acme`.
//!
//! ## It is not the health port
//!
//! The health port never reads a byte, and that is its guarantee. This port
//! exists to read, so the two cannot share a listener without the health port
//! losing what makes it safe to leave open.
//!
//! ## What reading host input here puts at risk
//!
//! hyper's HTTP/1 parser, the JSON parser, the router a rule's path is read
//! into — see `crate::route::Rules` — and, for a certificate, a PEM and an
//! X.509 parser and the name check a TLS client runs; nothing past them. A push
//! says where this role may go and nothing about what it will accept — see
//! `crate::config` — so a push can make routes fail but cannot make an
//! applicant's connection reach anything but a member proving the build its
//! group names. A certificate for another key is refused, so a push can take
//! the public surface down at worst, which the host could anyway.
//!
//! A push does say one thing more: where an ACME validator's connection is
//! carried, and so who answers it for the names — who can have a certificate
//! issued for them. That is the host's to say, as the rest is. Whoever reaches
//! this port is taken to be the host, which holds the names' address and could
//! have a certificate issued without this role; which of the host's own
//! processes may reach it is the host's to settle, not this role's.
//!
//! ## One push at a time
//!
//! A push reads the published table, builds the next one from it — telling each
//! set of members it carries across what changed — and publishes. Two at once
//! would read the same table, interleave their changes to the same sets, and
//! the later to publish would erase the other. So pushes are applied strictly
//! one after another, and [`AT_ONCE`] is what makes them so: the port is a
//! service behind a concurrency limit of one, and the next connection is not
//! accepted while a push is being applied.
//!
//! Applying has no await in it — from reading the table to publishing the next
//! — so nothing can suspend it halfway, and the timeout on a connection cannot
//! cut it off with some sets told and the table unpublished.
//!
//! A panic inside a push ends that connection's task, not the role. The loop
//! taking pushes goes on, and the next push is applied to whatever table was
//! last published.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Body;
use hyper::server::conn::http1;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use safe_logger::{debug, info, reason, safe};
use tokio::sync::watch;

use crate::identity::key::Identity;
use crate::identity::tls::{self, Issued};
use crate::upstream::Upstreams;

/// Where a table is pushed.
const PATH: &str = "/config";

/// Where the request for a certificate over the served names is read.
const REQUEST: &str = "/csr";

/// The largest push accepted. Far beyond any table a fleet declares, and small
/// enough that the host cannot use a push to take this role's memory.
const MAX_PUSH_BYTES: usize = 1 << 20;

/// How long one connection may take, from accept to response.
const PUSH_TIMEOUT: Duration = Duration::from_secs(10);

/// How many configuration connections are served at once.
///
/// ONE, and it must stay one — see the module docs. It is not a tuning knob:
/// any other value lets two pushes interleave.
const AT_ONCE: usize = 1;

/// What a push acts on.
#[derive(Clone)]
pub struct Port {
    /// Where each accepted table is published.
    current: watch::Sender<Arc<Upstreams>>,
    /// How many descriptors the process holds at most — what it got at boot. A
    /// push whose tuning could need more is refused, because a ceiling the
    /// descriptor table cannot back is not a ceiling.
    descriptors: u64,
    /// The key a certificate request is signed with, and an issued certificate
    /// must be for.
    identity: Arc<Identity>,
    /// Where the accepted issued certificates are published: none, or enough
    /// to cover every name.
    issued: watch::Sender<Vec<Issued>>,
}

impl Port {
    pub fn new(
        current: watch::Sender<Arc<Upstreams>>,
        descriptors: u64,
        identity: Arc<Identity>,
        issued: watch::Sender<Vec<Issued>>,
    ) -> Port {
        Port {
            current,
            descriptors,
            identity,
            issued,
        }
    }
}

/// Take pushes for ever, publishing each accepted table and certificate.
///
/// Await it on the role's own task, not in a spawn: a role that stopped taking
/// configuration would keep serving a table the host can no longer change, and
/// that should end the process rather than go on quietly.
pub async fn serve(listener: fleet_transport::Listener, port: Port) -> ! {
    let port = tower::ServiceBuilder::new()
        .concurrency_limit(AT_ONCE)
        .service_fn(move |accepted| connection(port.clone(), accepted));
    fleet_transport::service::serve(listener, port).await
}

/// One configuration connection, from its first byte to its response.
///
/// [`PUSH_TIMEOUT`] bounds it here, inside, rather than as a layer around the
/// service: only here is the peer known, and the two ways a connection ends —
/// it failed, or it never finished — are told apart side by side.
async fn connection(port: Port, accepted: fleet_transport::Accepted) -> Result<(), Infallible> {
    let peer = accepted.peer;
    let responding = hyper::service::service_fn(move |req| {
        let port = port.clone();
        async move { Ok::<_, Infallible>(push(&port, req).await) }
    });
    let conn = http1::Builder::new()
        // One request per connection. Ordering does not need it — HTTP/1 serves
        // one request at a time on a connection anyway. The permit does: it is
        // held for as long as the connection lives, so a pusher that kept its
        // connection open after the response would hold the only one until
        // PUSH_TIMEOUT, and the next push would wait out the difference.
        .keep_alive(false)
        // A pusher that shuts its sending side once the request is out — as a
        // tool pushing a file does — is waiting for the response, not leaving.
        // Without this, the end of its input reads as a connection lost in the
        // middle of a request, and the push is dropped without being applied.
        .half_close(true)
        .serve_connection(TokioIo::new(accepted.stream), responding);
    match tokio::time::timeout(PUSH_TIMEOUT, conn).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => debug!("config connection from {peer} ended: {e}"),
        Err(_) => debug!("config connection from {peer} did not finish within the timeout"),
    }
    Ok(())
}

/// Respond to one request, and act on it if it is a valid one.
async fn push<B>(port: &Port, req: Request<B>) -> Response<Full<Bytes>>
where
    B: Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    match (req.method(), req.uri().path()) {
        (&Method::PUT, PATH) => match body(req).await {
            Ok(body) => configure(port, &body),
            Err((status, said)) => respond(status, Some(said.into())),
        },
        (&Method::GET, REQUEST) => request(port, req.uri().query()),
        (_, PATH) => not_allowed("PUT"),
        (_, REQUEST) => not_allowed("GET"),
        _ => respond(
            StatusCode::NOT_FOUND,
            Some(format!("the paths here are {PATH} and {REQUEST}\n").into()),
        ),
    }
}

/// The method a path takes, said to one that used another.
fn not_allowed(method: &'static str) -> Response<Full<Bytes>> {
    let mut refused = respond(
        StatusCode::METHOD_NOT_ALLOWED,
        Some(format!("this path takes {method}\n").into()),
    );
    refused.headers_mut().insert(
        hyper::header::ALLOW,
        hyper::header::HeaderValue::from_static(method),
    );
    refused
}

/// A request's body, whole and no longer than [`MAX_PUSH_BYTES`], or the status
/// and text the sender is told instead.
async fn body<B>(req: Request<B>) -> Result<Bytes, (StatusCode, String)>
where
    B: Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    match Limited::new(req.into_body(), MAX_PUSH_BYTES)
        .collect()
        .await
    {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("a push is at most {MAX_PUSH_BYTES} bytes\n"),
        )),
        Err(_) => Err((
            StatusCode::BAD_REQUEST,
            "the body did not arrive whole\n".into(),
        )),
    }
}

/// The most names one request may ask for: as many as a public issuer puts in
/// one certificate.
const MOST_REQUESTED_NAMES: usize = 100;

/// The request for a certificate, in DER: over the names the query asks for,
/// or over the names this role serves now if it asks for none.
///
/// Names it does not serve yet may be asked for, and that is the point: a
/// certificate covering a name before the push that adds it is what lets the
/// name be served, from the push on, with nothing but that certificate. It is
/// no more than it looks. An issuer certifies the key for a name only once the
/// host proves it holds that name, and the key the request is for never leaves
/// this guest — this role signs a request it builds itself, over names it
/// checked to be names, and nothing else.
fn request(port: &Port, query: Option<&str>) -> Response<Full<Bytes>> {
    let names = match asked_for(query) {
        Ok(Some(names)) => names,
        Ok(None) => port.current.borrow().served().to_vec(),
        Err(said) => return respond(StatusCode::BAD_REQUEST, Some(format!("{said}\n").into())),
    };
    if names.is_empty() {
        return respond(
            StatusCode::CONFLICT,
            Some(
                format!("no names yet — push a configuration first, or ask for them: {REQUEST}?names=a.example,b.example\n")
                    .into(),
            ),
        );
    }
    match tls::request(&port.identity, &names) {
        Ok(der) => Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/pkcs10")
            .body(Full::new(Bytes::from(der)))
            .expect("a constant response builds"),
        // A name that is not one — the sender's to fix.
        Err(reason) => respond(StatusCode::BAD_REQUEST, Some(format!("{reason}\n").into())),
    }
}

/// The names a request asks for, from `names=a,b,…` in its query, or `None`
/// when it asks for none. Each is checked to be a name when the request is
/// built.
fn asked_for(query: Option<&str>) -> Result<Option<Vec<String>>, String> {
    let Some(query) = query else {
        return Ok(None);
    };
    let mut names: Option<Vec<String>> = None;
    for pair in query.split('&') {
        match pair.split_once('=') {
            Some(("names", list)) if names.is_none() => {
                names = Some(list.split(',').map(str::to_owned).collect());
            }
            Some(("names", _)) => return Err("names is given twice".into()),
            _ => {
                return Err(format!(
                    "the one parameter here is names, as in {REQUEST}?names=a.example,b.example"
                ));
            }
        }
    }
    if let Some(names) = &names
        && names.len() > MOST_REQUESTED_NAMES
    {
        return Err(format!(
            "at most {MOST_REQUESTED_NAMES} names to one request"
        ));
    }
    Ok(names)
}

/// Apply a table, and the issued certificates it carries, if all are valid.
///
/// The certificates are checked here rather than with the rest of the table,
/// because they are checked against this role's key, which a table cannot know
/// — see [`tls::issued`] for what is checked, and why the sender need not be
/// trusted. They are checked against the names of the same push, and one that
/// is refused refuses the push whole, as any other part does.
///
/// This role keeps them for as long as it runs and no longer: nothing is
/// written anywhere. The key they are for is the same at every boot, so the
/// push the host makes after a restart carries the same certificates, and a
/// renewal is the next push carrying the next ones.
fn configure(port: &Port, body: &[u8]) -> Response<Full<Bytes>> {
    let current = &port.current;
    let descriptors = port.descriptors;
    // The reason is the sender's to read and is not logged: it can quote the
    // push, and the push is the host's, which already has it.
    let declared = match crate::config::ValidatedConfig::parse(body) {
        Ok(declared) => declared,
        Err(reason) => return respond(StatusCode::BAD_REQUEST, Some(format!("{reason}\n").into())),
    };
    // Checked here rather than with the rest: it is about this process, not
    // the table, and the table's checks read nothing but the push. It bounds
    // this tuning alone; `crate::budget` holds across a change from the last.
    let needed = declared.tuning().descriptors();
    if needed > descriptors {
        return respond(
            StatusCode::BAD_REQUEST,
            Some(
                format!(
                    "tuning: could need {needed} file descriptors, and this process could get \
                     no more than {descriptors} — lower listener.connections, \
                     listener.streams_per_connection or upstream.parked_legs\n"
                )
                .into(),
            ),
        );
    }

    // The reason goes to the sender, whose certificates they are, and is not
    // logged.
    let pushed: Vec<String> = declared.names().keys().cloned().collect();
    let issued = match tls::issued(
        &port.identity,
        declared.certificates(),
        &pushed,
        std::time::SystemTime::now(),
    ) {
        Ok(issued) => issued,
        Err(reason) => {
            return respond(
                StatusCode::BAD_REQUEST,
                Some(format!("certificates{reason}\n").into()),
            );
        }
    };

    // The apply step, with no await in it — see the module docs. The borrow is
    // released before publishing, because holding it across `send_replace`
    // would wait on itself.
    let previous = current.borrow().clone();
    let next = Arc::new(previous.replaced(&declared));
    let groups = next.len();
    let carried = issued.len();
    // The certificates before the table. What the listener presents is made
    // from both, again whenever either moves, and in this order a push that
    // carries certificates is never answered with this role's own in between.
    port.issued.send_replace(issued);
    current.send_replace(next);
    if carried > 0 {
        info!(
            "gateway: {} issued certificate(s) presented in place of this role's own",
            safe(
                &carried,
                reason!("how many certificates the host's own push carried")
            ),
            reason!("constant text; says the host pushed some, which it did")
        );
    }

    info!(
        "gateway: configuration accepted, {} group(s) declared",
        safe(
            &groups,
            reason!("how many groups the host's own push declared")
        ),
        reason!("constant text; says when the host changed this role's table, which it did")
    );
    respond(StatusCode::NO_CONTENT, None)
}

/// What the sender is told: text it can read, or nothing at all.
///
/// Nothing is a push that applied — what the table now holds is what it sent —
/// and that response has no body, so it carries no content type either: one
/// would describe nothing.
fn respond<T: Buf>(status: StatusCode, body: Option<Full<T>>) -> Response<Full<T>> {
    let builder = Response::builder().status(status);
    match body {
        Some(text) => builder
            .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(text),
        None => builder.body(Full::default()),
    }
    .expect("a constant response builds")
}

/// TCP arm only: the fixtures declare TCP member addresses, which the vsock arm
/// rightly refuses, and the port tests stand a listener up on a TCP socket.
#[cfg(all(test, not(feature = "vsock")))]
mod tests {
    use super::*;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::config::testing::TUNING;
    use crate::upstream::tests::{A, FIRST, SECOND};

    /// Descriptors enough for any tuning, for the tests about something else.
    const ENOUGH: u64 = u64::MAX;

    /// A port over an empty table, holding `descriptors`, and the two things it
    /// publishes: the table and the issued certificates.
    fn fixture(
        descriptors: u64,
    ) -> (
        Port,
        watch::Receiver<Arc<Upstreams>>,
        watch::Receiver<Vec<Issued>>,
    ) {
        let (current, table) =
            watch::channel(Arc::new(Upstreams::empty(crate::identity::attestor())));
        let (issued, accepted) = watch::channel(Vec::new());
        let identity = Arc::new(Identity::generated().unwrap());
        (
            Port::new(current, descriptors, identity, issued),
            table,
            accepted,
        )
    }

    fn valid() -> String {
        format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{A}" }} }},
              "names": {{
                "{FIRST}": {{ "one": ["127.0.0.1:1"] }},
                "{SECOND}":  {{ "one": ["127.0.0.1:2"] }} }},
              {TUNING} }}"#
        )
    }

    fn request(method: Method, path: &str, body: impl Into<Bytes>) -> Request<Full<Bytes>> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Full::new(body.into()))
            .unwrap()
    }

    /// The request head a pusher sends before the body.
    fn head(body: &str) -> String {
        format!(
            "PUT {PATH} HTTP/1.1\r\nhost: config\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            body.len()
        )
    }

    /// This role's port on a socket of its own, and where to reach it.
    async fn listening(port: Port) -> String {
        let listener = fleet_transport::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, port));
        addr
    }

    /// Everything the port says back, up to its closing the connection — well
    /// inside PUSH_TIMEOUT, or the test fails rather than waiting it out.
    async fn response_to(stream: &mut tokio::net::TcpStream) -> String {
        let mut got = String::new();
        tokio::time::timeout(Duration::from_secs(3), stream.read_to_string(&mut got))
            .await
            .expect("the port responded and closed well inside the timeout")
            .unwrap();
        got
    }

    #[tokio::test]
    async fn a_valid_push_replaces_the_table() {
        let (port, rx, _) = fixture(ENOUGH);
        let resp = push(&port, request(Method::PUT, PATH, valid())).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(rx.borrow().len(), 1);
        assert!(rx.borrow().at_group(FIRST, "one").is_ok());
    }

    /// A push whose tuning could need more descriptors than this process has is
    /// refused, and says which numbers to lower.
    #[tokio::test]
    async fn a_push_this_process_could_not_back_is_refused() {
        let needed = crate::config::testing::tuning().descriptors();

        let (short, rx, _) = fixture(needed - 1);
        let resp = push(&short, request(Method::PUT, PATH, valid())).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let said = resp.into_body().collect().await.unwrap().to_bytes();
        let said = String::from_utf8_lossy(&said);
        assert!(said.contains("listener.connections"), "{said}");
        assert_eq!(rx.borrow().len(), 0, "and nothing was applied");

        let (exact, _, _) = fixture(needed);
        let resp = push(&exact, request(Method::PUT, PATH, valid())).await;
        assert_eq!(
            resp.status(),
            StatusCode::NO_CONTENT,
            "exactly enough is enough"
        );
    }

    /// A refused push leaves the table exactly as it was.
    #[tokio::test]
    async fn a_refused_push_changes_nothing() {
        let (port, rx, _) = fixture(ENOUGH);
        assert_eq!(
            push(&port, request(Method::PUT, PATH, valid()))
                .await
                .status(),
            StatusCode::NO_CONTENT
        );

        let resp = push(
            &port,
            request(Method::PUT, PATH, r#"{"upstreams":[],"x":1}"#),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(rx.borrow().len(), 1);
    }

    /// Each path takes its one method, and says which to one using another.
    #[tokio::test]
    async fn each_path_takes_its_own_method() {
        let (port, rx, _) = fixture(ENOUGH);
        for (method, path, allowed) in [
            (Method::POST, PATH, "PUT"),
            (Method::GET, PATH, "PUT"),
            (Method::PUT, REQUEST, "GET"),
        ] {
            let refused = push(&port, request(method.clone(), path, valid())).await;
            assert_eq!(
                refused.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} {path}"
            );
            assert_eq!(refused.headers()[hyper::header::ALLOW], allowed);
        }
        assert_eq!(
            push(&port, request(Method::PUT, "/elsewhere", valid()))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(rx.borrow().len(), 0);
    }

    /// A certificate a test issuer signs for `key` over `names`, valid for as
    /// long as these tests will run.
    fn signed_for(key: &rcgen::KeyPair, names: &[&str]) -> String {
        crate::identity::tls::tests::issued_by(
            &crate::identity::tls::tests::issuer(),
            key,
            names,
            (2020, 1, 1),
            (2099, 1, 1),
        )
    }

    /// The request is read once there are names, and is for this role's key.
    #[tokio::test]
    async fn the_request_is_for_this_key_once_there_are_names() {
        use x509_parser::prelude::FromDer;

        let (port, _rx, _) = fixture(ENOUGH);
        assert_eq!(
            push(&port, request(Method::GET, REQUEST, ""))
                .await
                .status(),
            StatusCode::CONFLICT,
            "no names before a push"
        );
        assert_eq!(
            push(&port, request(Method::PUT, PATH, valid()))
                .await
                .status(),
            StatusCode::NO_CONTENT
        );

        let resp = push(&port, request(Method::GET, REQUEST, "")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()[hyper::header::CONTENT_TYPE],
            "application/pkcs10"
        );
        let der = resp.into_body().collect().await.unwrap().to_bytes();
        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&der).unwrap();
        assert_eq!(
            csr.certification_request_info.subject_pki.raw,
            port.identity.spki()
        );
    }

    /// A request may ask for names no push has declared yet, and is over
    /// exactly those; a query that is not one list of names is refused.
    #[tokio::test]
    async fn a_request_may_ask_for_the_names_a_push_will_declare() {
        let (port, _rx, _) = fixture(ENOUGH);
        let resp = push(
            &port,
            request(
                Method::GET,
                &format!("{REQUEST}?names={FIRST},{SECOND}"),
                "",
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "before any push");
        let der = resp.into_body().collect().await.unwrap().to_bytes();
        let mut asked = [FIRST, SECOND];
        asked.sort();
        assert_eq!(crate::identity::tls::tests::requested_names(&der), asked);

        let too_many = vec![FIRST; MOST_REQUESTED_NAMES + 1].join(",");
        for (query, said) in [
            (
                format!("names={FIRST}&names={SECOND}"),
                "names is given twice",
            ),
            (
                format!("names={FIRST}&which=all"),
                "the one parameter here is names",
            ),
            ("names".to_owned(), "the one parameter here is names"),
            ("names=bad..example".to_owned(), "is not a DNS name"),
            ("names=".to_owned(), "is not a DNS name"),
            (format!("names={too_many}"), "at most"),
        ] {
            let resp = push(
                &port,
                request(Method::GET, &format!("{REQUEST}?{query}"), ""),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{query}");
            let got = resp.into_body().collect().await.unwrap().to_bytes();
            assert!(
                String::from_utf8_lossy(&got).contains(said),
                "{query}: {got:?}"
            );
        }
    }

    /// [`valid`], carrying `pems` as its issued certificates.
    fn carrying(pems: &[String]) -> String {
        valid().replacen(
            '{',
            &format!(
                "{{ \"certificates\": {},",
                serde_json::to_string(pems).unwrap()
            ),
            1,
        )
    }

    /// What the port says to a push it refused.
    async fn refusal(resp: Response<Full<Bytes>>) -> String {
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let said = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8_lossy(&said).into_owned()
    }

    /// A push carrying certificates for this role's key that cover its names
    /// between them — one for both, or one each — presents them; one carrying
    /// a certificate for another key is refused whole, the table as well, and
    /// says which; and one carrying none presents none.
    #[tokio::test]
    async fn a_push_s_certificates_are_taken_with_it_or_refuse_it() {
        let (port, rx, mut accepted) = fixture(ENOUGH);
        let key = port.identity.key();

        for (layout, pems) in [
            ("one for both", vec![signed_for(key, &[FIRST, SECOND])]),
            (
                "one each",
                vec![signed_for(key, &[FIRST]), signed_for(key, &[SECOND])],
            ),
        ] {
            assert_eq!(
                push(&port, request(Method::PUT, PATH, carrying(&pems)))
                    .await
                    .status(),
                StatusCode::NO_CONTENT,
                "{layout}"
            );
            assert_eq!(accepted.borrow_and_update().len(), pems.len(), "{layout}");
        }
        assert_eq!(rx.borrow().len(), 1);

        let other = rcgen::KeyPair::generate().unwrap();
        let said = refusal(
            push(
                &port,
                request(
                    Method::PUT,
                    PATH,
                    carrying(&[signed_for(key, &[FIRST]), signed_for(&other, &[SECOND])])
                        .replace("\"one\"", "\"uno\""),
                ),
            )
            .await,
        )
        .await;
        assert!(
            said.contains("certificates[1]: the certificate is for another key"),
            "{said}"
        );
        assert!(
            !accepted.has_changed().unwrap(),
            "the certificates presented are still the ones taken"
        );
        assert!(
            rx.borrow().at_group(FIRST, "uno").is_err(),
            "and the table the push carried was not applied"
        );

        // A name none of them covers would be served on this role's own, which
        // no caller trusting the issuer accepts.
        let said = refusal(
            push(
                &port,
                request(Method::PUT, PATH, carrying(&[signed_for(key, &[FIRST])])),
            )
            .await,
        )
        .await;
        assert!(
            said.contains(&format!("certificates: none of them covers {SECOND}")),
            "{said}"
        );
        assert!(!accepted.has_changed().unwrap());

        assert_eq!(
            push(&port, request(Method::PUT, PATH, valid()))
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
        assert!(
            accepted.borrow_and_update().is_empty(),
            "a push without any presents none"
        );
    }

    #[tokio::test]
    async fn an_oversized_push_is_refused_before_it_is_parsed() {
        let (port, rx, _) = fixture(ENOUGH);
        let resp = push(
            &port,
            request(Method::PUT, PATH, vec![b' '; MAX_PUSH_BYTES + 1]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(rx.borrow().len(), 0);
    }

    /// The listener end to end: a real connection, a real HTTP/1 push, and the
    /// table seen to change.
    #[tokio::test]
    async fn the_port_takes_a_push_over_a_connection() {
        let (port, mut rx, _) = fixture(ENOUGH);
        let addr = listening(port).await;

        let body = valid();
        let mut stream = tokio::net::TcpStream::connect(&addr).await.unwrap();
        stream
            .write_all(format!("{}{body}", head(&body)).as_bytes())
            .await
            .unwrap();
        let got = response_to(&mut stream).await;
        assert!(got.starts_with("HTTP/1.1 204"), "{got}");

        rx.changed().await.unwrap();
        assert_eq!(rx.borrow().len(), 1);
    }

    /// A pusher that closes its sending side once the request is out still gets
    /// a response, and its push is still applied.
    #[tokio::test]
    async fn a_pusher_that_stops_sending_still_gets_a_response() {
        let (port, mut rx, _) = fixture(ENOUGH);
        let addr = listening(port).await;

        let body = valid();
        let mut stream = tokio::net::TcpStream::connect(&addr).await.unwrap();
        stream
            .write_all(format!("{}{body}", head(&body)).as_bytes())
            .await
            .unwrap();
        stream.shutdown().await.unwrap();

        let got = response_to(&mut stream).await;
        assert!(got.starts_with("HTTP/1.1 204"), "{got}");
        rx.changed().await.unwrap();
        assert_eq!(rx.borrow().len(), 1);
    }

    /// Pushes are one at a time: while one is still arriving, the next is not
    /// taken — let alone applied — and once the first is done, it is.
    #[tokio::test]
    async fn a_second_push_waits_for_the_first() {
        let (port, rx, _) = fixture(ENOUGH);
        let addr = listening(port).await;
        let body = valid();

        // The first holds the port: its head and only part of its body.
        let mut first = tokio::net::TcpStream::connect(&addr).await.unwrap();
        first
            .write_all(format!("{}{}", head(&body), &body[..10]).as_bytes())
            .await
            .unwrap();

        // The second is whole, and waits.
        let mut second = tokio::net::TcpStream::connect(&addr).await.unwrap();
        second
            .write_all(format!("{}{body}", head(&body)).as_bytes())
            .await
            .unwrap();
        let mut byte = [0u8; 1];
        let waited = tokio::time::timeout(Duration::from_millis(300), second.read(&mut byte)).await;
        assert!(
            waited.is_err(),
            "the second gets no response while the first holds the port"
        );
        assert_eq!(rx.borrow().len(), 0, "and neither has been applied");

        // The first finishes; then the second is taken and responded to.
        first.write_all(&body.as_bytes()[10..]).await.unwrap();
        assert!(response_to(&mut first).await.starts_with("HTTP/1.1 204"));
        assert!(response_to(&mut second).await.starts_with("HTTP/1.1 204"));
    }

    /// A pusher asking to keep its connection is told the connection closes,
    /// and does not keep the port: the next push gets its response at once, not
    /// after PUSH_TIMEOUT.
    #[tokio::test]
    async fn a_pusher_that_would_keep_its_connection_does_not_keep_the_port() {
        let (port, _rx, _) = fixture(ENOUGH);
        let addr = listening(port).await;
        let body = valid();

        let mut first = tokio::net::TcpStream::connect(&addr).await.unwrap();
        let keep = head(&body).replace("\r\n\r\n", "\r\nconnection: keep-alive\r\n\r\n");
        first
            .write_all(format!("{keep}{body}").as_bytes())
            .await
            .unwrap();
        let got = response_to(&mut first).await.to_ascii_lowercase();
        assert!(got.contains("connection: close"), "{got}");

        let mut second = tokio::net::TcpStream::connect(&addr).await.unwrap();
        second
            .write_all(format!("{}{body}", head(&body)).as_bytes())
            .await
            .unwrap();
        assert!(response_to(&mut second).await.starts_with("HTTP/1.1 204"));
    }
}
