//! One webhook, sent to the endpoint its consumer named: one `POST`, and whether
//! the endpoint took it back.
//!
//! The hatch is a stateless sender here, as for a broker's leg: api builds the
//! request — its body and the signature over it — and whether to try again is
//! api's. Bounded as a broker leg is: a deadline on the whole, and a redirect is
//! not followed — it would send the body, signature and all, to wherever it
//! pointed. The answer's body is not read.

use std::time::Duration;

use reqwest::Method;
use reqwest::header::CONTENT_TYPE;

use hatch_rpc::{WebhookAnswer, WebhookError, WebhookRequest};
use safe_logger::debug;

use crate::egress::{self, BuildError, Hosts};

/// How long a webhook's connection may take to open, unless the host says
/// otherwise (`webhook-connect-secs`).
pub const DEFAULT_WEBHOOK_CONNECT: Duration = Duration::from_secs(5);
/// How long one webhook may take whole, unless the host says otherwise
/// (`webhook-send-secs`): under api's own wait for an attempt.
pub const DEFAULT_WEBHOOK_SEND: Duration = Duration::from_secs(15);

/// The webhooks' one client, made at startup: its connections open within
/// `connect`, each webhook ends within `send`, and it sends to `hosts` alone.
pub fn client(
    hosts: Hosts,
    connect: Duration,
    send: Duration,
) -> Result<egress::Client, BuildError> {
    egress::Client::new(hosts, connect, send)
}

/// Send `req` once, and whether the endpoint took it.
pub async fn send(
    client: &egress::Client,
    req: WebhookRequest,
) -> Result<WebhookAnswer, WebhookError> {
    let Some(builder) = client.request(Method::POST, &req.url).await else {
        return Err(WebhookError("not a URL this hatch sends to".into()));
    };
    let mut builder = builder
        .header(CONTENT_TYPE, "application/json")
        .body(req.body);
    for (name, value) in &req.headers {
        builder = builder.header(name, value);
    }
    let answer = builder.send().await.map_err(|e| {
        debug!("webhook to {}: {e}", req.url);
        WebhookError("the endpoint did not answer".into())
    })?;
    Ok(WebhookAnswer {
        accepted: answer.status().is_success(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::body::Bytes;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;

    use super::*;

    /// What an endpoint was sent: its headers and its body.
    type Seen = Arc<Mutex<Option<(HeaderMap, Bytes)>>>;

    /// An endpoint on loopback answering `/hook` with `status`, and
    /// `/elsewhere` with a redirect to it; and what it was sent there.
    async fn endpoint(status: StatusCode) -> (String, Seen) {
        let seen: Seen = Arc::default();
        let kept = seen.clone();
        let app = Router::new()
            .route(
                "/hook",
                post(move |headers: HeaderMap, body: Bytes| async move {
                    *kept.lock().unwrap() = Some((headers, body));
                    status
                }),
            )
            .route(
                "/elsewhere",
                post(|| async { (StatusCode::TEMPORARY_REDIRECT, [("location", "/hook")]) }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await });
        (origin, seen)
    }

    fn webhook(url: String) -> WebhookRequest {
        WebhookRequest {
            url,
            headers: vec![("webhook-id".into(), "msg_1".into())],
            body: b"{\"type\":\"session.ended\"}".to_vec(),
        }
    }

    /// A client as this build defaults it, held to public addresses where
    /// `public_only`.
    fn defaulted(public_only: bool) -> egress::Client {
        let hosts = Hosts::new(public_only).unwrap();
        client(hosts, DEFAULT_WEBHOOK_CONNECT, DEFAULT_WEBHOOK_SEND).unwrap()
    }

    /// A client not held to public addresses: the test's endpoints are on
    /// loopback.
    fn open() -> egress::Client {
        defaulted(false)
    }

    /// The body goes as it was built, with its headers and its type; a `2xx`
    /// comes back as taken, any other status as not.
    #[tokio::test]
    async fn a_webhook_goes_as_built_and_a_2xx_takes_it() {
        let (origin, seen) = endpoint(StatusCode::NO_CONTENT).await;
        let answer = send(&open(), webhook(format!("{origin}/hook")))
            .await
            .unwrap();
        assert!(answer.accepted);
        let (headers, body) = seen.lock().unwrap().take().unwrap();
        assert_eq!(headers["webhook-id"], "msg_1");
        assert_eq!(headers["content-type"], "application/json");
        assert_eq!(&body[..], b"{\"type\":\"session.ended\"}");

        let (origin, _) = endpoint(StatusCode::INTERNAL_SERVER_ERROR).await;
        let answer = send(&open(), webhook(format!("{origin}/hook")))
            .await
            .unwrap();
        assert!(!answer.accepted);
    }

    /// A redirect is the endpoint's answer, not a place the body goes.
    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let (origin, seen) = endpoint(StatusCode::NO_CONTENT).await;
        let answer = send(&open(), webhook(format!("{origin}/elsewhere")))
            .await
            .unwrap();
        assert!(!answer.accepted);
        assert!(seen.lock().unwrap().is_none());
    }

    /// Held to public addresses, the client sends no webhook to an endpoint on
    /// loopback, by its address or by its name.
    #[tokio::test]
    async fn a_held_client_sends_nothing_to_loopback() {
        let (origin, seen) = endpoint(StatusCode::NO_CONTENT).await;
        let held = defaulted(true);
        let by_name = origin.replace("127.0.0.1", "localhost");
        for url in [format!("{origin}/hook"), format!("{by_name}/hook")] {
            assert!(send(&held, webhook(url.clone())).await.is_err(), "{url}");
        }
        assert!(seen.lock().unwrap().is_none());
    }

    /// Only an http(s) URL is sent to, and one that does not answer is an error.
    #[tokio::test]
    async fn a_url_that_is_not_an_endpoint_gets_no_webhook() {
        let client = open();
        assert!(
            send(&client, webhook("ftp://example".into()))
                .await
                .is_err()
        );
        // A port nothing listens on: the connection is refused.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed = format!("http://{}/hook", listener.local_addr().unwrap());
        drop(listener);
        assert!(send(&client, webhook(closed)).await.is_err());
    }
}
