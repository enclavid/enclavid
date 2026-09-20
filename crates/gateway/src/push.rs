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
//! The JSON parser, and nothing past it. A push says where this role may go and
//! nothing about what it will accept — see `crate::config` — so a push from
//! anyone who reaches this port, the host or otherwise, can make routes fail but
//! cannot make a consumer talk to a build it did not name.
//!
//! ## One push at a time
//!
//! Each connection is served to the end before the next is accepted. Pushes are
//! then applied in the order they arrived and one cannot interleave with
//! another, which a spawned handler would allow. [`PUSH_TIMEOUT`] bounds how
//! long one connection can hold the port.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
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

/// Take pushes for ever, publishing each accepted table to `current`.
///
/// Returns only by panicking. Await it on the role's own task, not in a spawn:
/// a role that stopped taking configuration would keep serving a table the host
/// can no longer change, and that should end the process rather than go on
/// quietly.
pub async fn serve(
    listener: fleet_transport::Listener,
    current: watch::Sender<Arc<Upstreams>>,
) -> ! {
    let current = Arc::new(current);
    fleet_transport::accept_forever(listener, move |stream, peer| {
        let current = current.clone();
        async move {
            let service = hyper::service::service_fn(move |req| {
                let current = current.clone();
                async move { Ok::<_, Infallible>(push(&current, req).await) }
            });
            let conn = http1::Builder::new()
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service);
            match tokio::time::timeout(PUSH_TIMEOUT, conn).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => debug!("config connection from {peer} ended: {e}"),
                Err(_) => debug!("config connection from {peer} did not finish within the timeout"),
            }
        }
    })
    .await
}

/// Answer one request, and apply it if it is a valid push.
async fn push<B>(current: &watch::Sender<Arc<Upstreams>>, req: Request<B>) -> Response<Full<Bytes>>
where
    B: Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    if req.uri().path() != PATH {
        return answer(
            StatusCode::NOT_FOUND,
            format!("the only path here is {PATH}\n"),
        );
    }
    if req.method() != Method::PUT {
        return answer(StatusCode::METHOD_NOT_ALLOWED, "push with PUT\n".to_owned());
    }

    let body = match Limited::new(req.into_body(), MAX_PUSH_BYTES)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => {
            return answer(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("a push is at most {MAX_PUSH_BYTES} bytes\n"),
            );
        }
        Err(_) => {
            return answer(
                StatusCode::BAD_REQUEST,
                "the body did not arrive whole\n".to_owned(),
            );
        }
    };

    // The reason is the sender's to read and is not logged: it can quote the
    // push, and the push is the host's, which already has it.
    let declared = match crate::config::ValidatedConfig::parse(&body) {
        Ok(declared) => declared,
        Err(reason) => return answer(StatusCode::BAD_REQUEST, format!("{reason}\n")),
    };

    // Built before it is published, with the borrow released first: holding it
    // across `send_replace` would wait on itself.
    let next = Arc::new(current.borrow().replaced(declared));
    let builds = next.len();
    current.send_replace(next);

    info!(
        "gateway: configuration accepted, {} api build(s) declared",
        safe(
            &builds,
            reason!("how many entries the host's own push declared")
        ),
        reason!("constant text; says when the host changed this role's table, which it did")
    );
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Full::new(Bytes::new()))
        .expect("a constant response builds")
}

fn answer(status: StatusCode, message: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(message)))
        .expect("a constant response builds")
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::upstream::tests::{A, APPLICANT, CONSUMER};

    fn table() -> (
        watch::Sender<Arc<Upstreams>>,
        watch::Receiver<Arc<Upstreams>>,
    ) {
        watch::channel(Arc::new(Upstreams::empty()))
    }

    fn valid() -> String {
        format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{A}" }} }},
              "names": {{
                "{APPLICANT}": {{ "one": ["127.0.0.1:1"] }},
                "{CONSUMER}":  {{ "one": ["127.0.0.1:2"] }} }},
              "affinity": {{ "key": "{}", "ttl_seconds": 600 }} }}"#,
            "0".repeat(64)
        )
    }

    fn request(method: Method, path: &str, body: impl Into<Bytes>) -> Request<Full<Bytes>> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Full::new(body.into()))
            .unwrap()
    }

    #[tokio::test]
    async fn a_valid_push_replaces_the_table() {
        let (tx, rx) = table();
        let resp = push(&tx, request(Method::PUT, PATH, valid())).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(rx.borrow().len(), 1);
        assert!(rx.borrow().at_group(APPLICANT, "one").is_ok());
    }

    /// A refused push leaves the table exactly as it was.
    #[tokio::test]
    async fn a_refused_push_changes_nothing() {
        let (tx, rx) = table();
        assert_eq!(
            push(&tx, request(Method::PUT, PATH, valid()))
                .await
                .status(),
            StatusCode::NO_CONTENT
        );

        let resp = push(&tx, request(Method::PUT, PATH, r#"{"upstreams":[],"x":1}"#)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(rx.borrow().len(), 1);
    }

    #[tokio::test]
    async fn only_put_on_the_one_path_is_a_push() {
        let (tx, rx) = table();
        assert_eq!(
            push(&tx, request(Method::POST, PATH, valid()))
                .await
                .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            push(&tx, request(Method::PUT, "/elsewhere", valid()))
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
            request(Method::PUT, PATH, vec![b' '; MAX_PUSH_BYTES + 1]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(rx.borrow().len(), 0);
    }

    /// The listener end to end: a real connection, a real HTTP/1 push, and the
    /// table seen to change. TCP arm only, for the reason `fleet_transport`'s
    /// health test gives.
    #[cfg(not(feature = "vsock"))]
    #[tokio::test]
    async fn the_port_takes_a_push_over_a_connection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (tx, mut rx) = table();
        let listener = fleet_transport::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, tx));

        let body = valid();
        let mut stream = tokio::net::TcpStream::connect(&addr).await.unwrap();
        stream
            .write_all(
                format!(
                    "PUT {PATH} HTTP/1.1\r\nhost: config\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut got = String::new();
        stream.read_to_string(&mut got).await.unwrap();
        assert!(got.starts_with("HTTP/1.1 204"), "{got}");

        rx.changed().await.unwrap();
        assert_eq!(rx.borrow().len(), 1);
    }
}
