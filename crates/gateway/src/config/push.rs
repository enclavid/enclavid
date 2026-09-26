//! The port the host pushes configuration to.
//!
//! The host dials this guest's own CID, as it does for the health port, and
//! sends the whole table with `PUT /config`. Nothing on the host has to be
//! running for this role to keep serving; the host speaks when the fleet changes.
//!
//! ## It is not the health port
//!
//! The health port never reads a byte, and that is its guarantee. This port
//! exists to read, so the two cannot share a listener without the health port
//! losing what makes it safe to leave open.
//!
//! ## What reading host input here puts at risk
//!
//! hyper's HTTP/1 parser and the JSON parser, and nothing past them. A push says
//! where this role may go and nothing about what it will accept — see
//! `crate::config` — so a push from anyone who reaches this port, the host or
//! otherwise, can make routes fail but cannot make a caller talk to a build it
//! did not name.
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

use crate::upstream::Upstreams;

/// The one path this port answers.
const PATH: &str = "/config";

/// The largest push accepted. Far beyond any table a fleet declares, and small
/// enough that the host cannot use a push to take this role's memory.
const MAX_PUSH_BYTES: usize = 1 << 20;

/// How long one connection may take, from accept to answer.
const PUSH_TIMEOUT: Duration = Duration::from_secs(10);

/// How many configuration connections are served at once.
///
/// ONE, and it must stay one — see the module docs. It is not a tuning knob:
/// any other value lets two pushes interleave.
const AT_ONCE: usize = 1;

/// Take pushes for ever, publishing each accepted table to `current`.
///
/// `descriptors` is how many the process holds at most — what it got at boot.
/// A push whose tuning could need more is refused, because a ceiling the
/// descriptor table cannot back is not a ceiling.
///
/// Await it on the role's own task, not in a spawn: a role that stopped taking
/// configuration would keep serving a table the host can no longer change, and
/// that should end the process rather than go on quietly.
pub async fn serve(
    listener: fleet_transport::Listener,
    current: watch::Sender<Arc<Upstreams>>,
    descriptors: u64,
) -> ! {
    let port = tower::ServiceBuilder::new()
        .concurrency_limit(AT_ONCE)
        .service_fn(move |accepted| connection(current.clone(), descriptors, accepted));
    fleet_transport::service::serve(listener, port).await
}

/// One configuration connection, from its first byte to its answer.
///
/// [`PUSH_TIMEOUT`] bounds it here, inside, rather than as a layer around the
/// service: only here is the peer known, and the two ways a connection ends —
/// it failed, or it never finished — are told apart side by side.
async fn connection(
    current: watch::Sender<Arc<Upstreams>>,
    descriptors: u64,
    accepted: fleet_transport::Accepted,
) -> Result<(), Infallible> {
    let peer = accepted.peer;
    let answering = hyper::service::service_fn(move |req| {
        let current = current.clone();
        async move { Ok::<_, Infallible>(push(&current, descriptors, req).await) }
    });
    let conn = http1::Builder::new()
        // One request per connection. Ordering does not need it — HTTP/1 serves
        // one request at a time on a connection anyway. The permit does: it is
        // held for as long as the connection lives, so a pusher that kept its
        // connection open after the answer would hold the only one until
        // PUSH_TIMEOUT, and the next push would wait out the difference.
        .keep_alive(false)
        // A pusher that shuts its sending side once the request is out — as a
        // tool pushing a file does — is waiting for the answer, not leaving.
        // Without this, the end of its input reads as a connection lost in the
        // middle of a request, and the push is dropped without being applied.
        .half_close(true)
        .serve_connection(TokioIo::new(accepted.stream), answering);
    match tokio::time::timeout(PUSH_TIMEOUT, conn).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => debug!("config connection from {peer} ended: {e}"),
        Err(_) => debug!("config connection from {peer} did not finish within the timeout"),
    }
    Ok(())
}

/// Answer one request, and apply it if it is a valid push.
async fn push<B>(
    current: &watch::Sender<Arc<Upstreams>>,
    descriptors: u64,
    req: Request<B>,
) -> Response<Full<Bytes>>
where
    B: Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    if req.uri().path() != PATH {
        return answer(
            StatusCode::NOT_FOUND,
            Some(format!("the only path here is {PATH}\n").into()),
        );
    }
    if req.method() != Method::PUT {
        let mut refused = answer(
            StatusCode::METHOD_NOT_ALLOWED,
            Some("push with PUT\n".into()),
        );
        refused.headers_mut().insert(
            hyper::header::ALLOW,
            hyper::header::HeaderValue::from_static("PUT"),
        );
        return refused;
    }

    let body = match Limited::new(req.into_body(), MAX_PUSH_BYTES)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => {
            return answer(
                StatusCode::PAYLOAD_TOO_LARGE,
                Some(format!("a push is at most {MAX_PUSH_BYTES} bytes\n").into()),
            );
        }
        Err(_) => {
            return answer(
                StatusCode::BAD_REQUEST,
                Some("the body did not arrive whole\n".into()),
            );
        }
    };

    // The reason is the sender's to read and is not logged: it can quote the
    // push, and the push is the host's, which already has it.
    let declared = match crate::config::ValidatedConfig::parse(&body) {
        Ok(declared) => declared,
        Err(reason) => return answer(StatusCode::BAD_REQUEST, Some(format!("{reason}\n").into())),
    };
    // Checked here rather than with the rest: it is about this process, not
    // the table, and the table's checks read nothing but the push. It bounds
    // this tuning alone; `crate::budget` holds across a change from the last.
    let needed = declared.tuning().descriptors();
    if needed > descriptors {
        return answer(
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

    // The apply step, with no await in it — see the module docs. The borrow is
    // released before publishing, because holding it across `send_replace`
    // would wait on itself.
    let previous = current.borrow().clone();
    let next = Arc::new(previous.replaced(&declared));
    let groups = next.len();
    current.send_replace(next);

    info!(
        "gateway: configuration accepted, {} group(s) declared",
        safe(
            &groups,
            reason!("how many groups the host's own push declared")
        ),
        reason!("constant text; says when the host changed this role's table, which it did")
    );
    answer(StatusCode::NO_CONTENT, None)
}

/// What the sender is told: text it can read, or nothing at all.
///
/// Nothing is a push that applied — what the table now holds is what it sent —
/// and that answer has no body, so it carries no content type either: one would
/// describe nothing.
fn answer<T: Buf>(status: StatusCode, body: Option<Full<T>>) -> Response<Full<T>> {
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

    fn table() -> (
        watch::Sender<Arc<Upstreams>>,
        watch::Receiver<Arc<Upstreams>>,
    ) {
        watch::channel(Arc::new(Upstreams::empty(crate::identity::attestor())))
    }

    fn valid() -> String {
        format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{A}" }} }},
              "names": {{
                "{FIRST}": {{ "one": ["127.0.0.1:1"] }},
                "{SECOND}":  {{ "one": ["127.0.0.1:2"] }} }},
              "affinity": {{ "key": "{}", "ttl_seconds": 600 }}, {TUNING} }}"#,
            "1".repeat(64)
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
    async fn port(tx: watch::Sender<Arc<Upstreams>>) -> String {
        let listener = fleet_transport::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, tx, ENOUGH));
        addr
    }

    /// Everything the port says back, up to its closing the connection — well
    /// inside PUSH_TIMEOUT, or the test fails rather than waiting it out.
    async fn answer_to(stream: &mut tokio::net::TcpStream) -> String {
        let mut got = String::new();
        tokio::time::timeout(Duration::from_secs(3), stream.read_to_string(&mut got))
            .await
            .expect("the port answered and closed well inside the timeout")
            .unwrap();
        got
    }

    #[tokio::test]
    async fn a_valid_push_replaces_the_table() {
        let (tx, rx) = table();
        let resp = push(&tx, ENOUGH, request(Method::PUT, PATH, valid())).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(rx.borrow().len(), 1);
        assert!(rx.borrow().at_group(FIRST, "one").is_ok());
    }

    /// A push whose tuning could need more descriptors than this process has is
    /// refused, and says which numbers to lower.
    #[tokio::test]
    async fn a_push_this_process_could_not_back_is_refused() {
        let (tx, rx) = table();
        let needed = crate::config::testing::tuning().descriptors();

        let resp = push(&tx, needed - 1, request(Method::PUT, PATH, valid())).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let said = resp.into_body().collect().await.unwrap().to_bytes();
        let said = String::from_utf8_lossy(&said);
        assert!(said.contains("listener.connections"), "{said}");
        assert_eq!(rx.borrow().len(), 0, "and nothing was applied");

        let resp = push(&tx, needed, request(Method::PUT, PATH, valid())).await;
        assert_eq!(
            resp.status(),
            StatusCode::NO_CONTENT,
            "exactly enough is enough"
        );
    }

    /// A refused push leaves the table exactly as it was.
    #[tokio::test]
    async fn a_refused_push_changes_nothing() {
        let (tx, rx) = table();
        assert_eq!(
            push(&tx, ENOUGH, request(Method::PUT, PATH, valid()))
                .await
                .status(),
            StatusCode::NO_CONTENT
        );

        let resp = push(
            &tx,
            ENOUGH,
            request(Method::PUT, PATH, r#"{"upstreams":[],"x":1}"#),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(rx.borrow().len(), 1);
    }

    #[tokio::test]
    async fn only_put_on_the_one_path_is_a_push() {
        let (tx, rx) = table();
        let refused = push(&tx, ENOUGH, request(Method::POST, PATH, valid())).await;
        assert_eq!(refused.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(refused.headers()[hyper::header::ALLOW], "PUT");
        assert_eq!(
            push(&tx, ENOUGH, request(Method::PUT, "/elsewhere", valid()))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(rx.borrow().len(), 0);
    }

    #[tokio::test]
    async fn an_oversized_push_is_refused_before_it_is_parsed() {
        let (tx, rx) = table();
        let resp = push(
            &tx,
            ENOUGH,
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
        let (tx, mut rx) = table();
        let addr = port(tx).await;

        let body = valid();
        let mut stream = tokio::net::TcpStream::connect(&addr).await.unwrap();
        stream
            .write_all(format!("{}{body}", head(&body)).as_bytes())
            .await
            .unwrap();
        let got = answer_to(&mut stream).await;
        assert!(got.starts_with("HTTP/1.1 204"), "{got}");

        rx.changed().await.unwrap();
        assert_eq!(rx.borrow().len(), 1);
    }

    /// A pusher that closes its sending side once the request is out is still
    /// answered, and its push still applied.
    #[tokio::test]
    async fn a_pusher_that_stops_sending_is_still_answered() {
        let (tx, mut rx) = table();
        let addr = port(tx).await;

        let body = valid();
        let mut stream = tokio::net::TcpStream::connect(&addr).await.unwrap();
        stream
            .write_all(format!("{}{body}", head(&body)).as_bytes())
            .await
            .unwrap();
        stream.shutdown().await.unwrap();

        let got = answer_to(&mut stream).await;
        assert!(got.starts_with("HTTP/1.1 204"), "{got}");
        rx.changed().await.unwrap();
        assert_eq!(rx.borrow().len(), 1);
    }

    /// Pushes are one at a time: while one is still arriving, the next is not
    /// taken — let alone applied — and once the first is done, it is.
    #[tokio::test]
    async fn a_second_push_waits_for_the_first() {
        let (tx, rx) = table();
        let addr = port(tx).await;
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
            "the second is not answered while the first holds the port"
        );
        assert_eq!(rx.borrow().len(), 0, "and neither has been applied");

        // The first finishes; then the second is taken and answered.
        first.write_all(&body.as_bytes()[10..]).await.unwrap();
        assert!(answer_to(&mut first).await.starts_with("HTTP/1.1 204"));
        assert!(answer_to(&mut second).await.starts_with("HTTP/1.1 204"));
    }

    /// A pusher asking to keep its connection is told the connection closes,
    /// and does not keep the port: the next push is answered at once, not after
    /// PUSH_TIMEOUT.
    #[tokio::test]
    async fn a_pusher_that_would_keep_its_connection_does_not_keep_the_port() {
        let (tx, _rx) = table();
        let addr = port(tx).await;
        let body = valid();

        let mut first = tokio::net::TcpStream::connect(&addr).await.unwrap();
        let keep = head(&body).replace("\r\n\r\n", "\r\nconnection: keep-alive\r\n\r\n");
        first
            .write_all(format!("{keep}{body}").as_bytes())
            .await
            .unwrap();
        let got = answer_to(&mut first).await.to_ascii_lowercase();
        assert!(got.contains("connection: close"), "{got}");

        let mut second = tokio::net::TcpStream::connect(&addr).await.unwrap();
        second
            .write_all(format!("{}{body}", head(&body)).as_bytes())
            .await
            .unwrap();
        assert!(answer_to(&mut second).await.starts_with("HTTP/1.1 204"));
    }
}
