//! Shared HTTP boilerplate for `session` commands. Centralises:
//!   * the reqwest client for one API (rustls-only — same TLS stack we use
//!     elsewhere), over plain http to this machine alone,
//!   * `Authorization: Bearer <token>` from `auth::api_token_for`, to the
//!     API the token is for alone,
//!   * `X-Session-Token: <cached>` for read endpoints,
//!   * `x-enclavid-measurement: <build>` when `create` names a build,
//!   * error body capture (we always print the server's JSON error
//!     instead of letting reqwest swallow it).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Context, Result, bail};
use reqwest::{Client, Method, Response, header};

use crate::{auth, plain_http};

/// The api build a creating request requires, for a gateway to place
/// the session on a group running it. api itself ignores it.
pub const MEASUREMENT_HEADER: &str = "x-enclavid-measurement";

/// The group a gateway placed a created session on, in the form a
/// path marker carries it: `<label>.<build>`.
pub const GROUP_HEADER: &str = "x-enclavid-group";

/// Where `localhost` is reached, whatever the resolver says of the name.
const LOCALHOST: [SocketAddr; 2] = [
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
];

/// The client for requests to the API at `api`. Over plain http that is
/// this machine alone, reached through no proxy and with `localhost` pinned
/// to [`LOCALHOST`], so the bearer, the session token and the session's id
/// cross no network in the clear.
pub fn http_client(api: &str) -> Result<Client> {
    let url = url::Url::parse(api).with_context(|| format!("reading the API's URL {api}"))?;
    let builder = Client::builder();
    let builder = match (url.scheme(), url.host()) {
        ("https", _) => builder,
        ("http", Some(host)) if plain_http::is_this_machine(&host) => {
            builder.no_proxy().resolve_to_addrs("localhost", &LOCALHOST)
        }
        _ => bail!(
            "{api}: an API is reached over https, or over plain http on this machine \
             alone (localhost, 127.0.0.1, [::1])"
        ),
    };
    builder.build().context("building http client")
}

pub async fn send(
    client: &Client,
    method: Method,
    url: &str,
    session_token: Option<&str>,
    measurement: Option<&str>,
    body: Option<serde_json::Value>,
) -> Result<Response> {
    let mut req = client.request(method.clone(), url);
    if let Some(token) = auth::api_token_for(url) {
        req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(t) = session_token {
        req = req.header("x-session-token", t);
    }
    if let Some(m) = measurement {
        req = req.header(MEASUREMENT_HEADER, m);
    }
    if let Some(b) = body {
        req = req.json(&b);
    }
    let response = req
        .send()
        .await
        .with_context(|| format!("{method} {url}"))?;
    Ok(response)
}

/// Convert a non-2xx response into an anyhow error that includes the
/// status code and the server's response body verbatim — easier
/// debugging than a bare `reqwest::Error: status code 422`. A refusal
/// for want of a bearer says where one goes.
pub async fn ensure_ok(response: Response, what: &str) -> Result<Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let sent_bearer = auth::api_token_for(response.url().as_str()).is_some();
    let body = response
        .text()
        .await
        .unwrap_or_else(|_| "<body not readable>".to_string());
    if status == reqwest::StatusCode::UNAUTHORIZED && !sent_bearer {
        let why = if auth::api_token_set() {
            format!(
                "${} goes only to the API ${} names",
                auth::ENV_API_TOKEN,
                auth::ENV_API_URL
            )
        } else {
            format!("${} is not set", auth::ENV_API_TOKEN)
        };
        bail!(
            "{what} returned HTTP {status}: {body}\n\n\
             No bearer was sent: {why}. If this API wants one, set ${} to it and \
             ${} to its token.",
            auth::ENV_API_URL,
            auth::ENV_API_TOKEN
        );
    }
    bail!("{what} returned HTTP {status}: {body}");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An API is reached over https, or over plain http on this machine alone.
    #[test]
    fn plain_http_goes_to_an_api_on_this_machine_alone() {
        for api in [
            "https://api.enclavid.com",
            "http://localhost:8001",
            "http://127.0.0.1:8001",
            "http://[::1]:8001",
        ] {
            assert!(http_client(api).is_ok(), "{api}");
        }
        for api in [
            "http://api.enclavid.com",
            "http://localhost.example.com:8001",
            "http://10.0.0.1:8001",
            "ftp://localhost",
            "not a url",
        ] {
            assert!(http_client(api).is_err(), "{api}");
        }
    }
}
