//! Shared HTTP boilerplate for `session` commands. Centralises:
//!   * the reqwest client (rustls-only — same TLS stack we use elsewhere),
//!   * `Authorization: Bearer <jwt>` from `auth::get_access_token`,
//!   * `X-Session-Token: <cached>` for read endpoints,
//!   * error body capture (we always print the server's JSON error
//!     instead of letting reqwest swallow it).

use anyhow::{Context, Result, bail};
use reqwest::{Client, Method, Response, header};

use crate::auth;

pub fn http_client() -> Result<Client> {
    Client::builder()
        .build()
        .context("building http client")
}

pub async fn fetch_jwt() -> Result<String> {
    auth::get_access_token()
        .await
        .context("no API access token available — see `enclavid cloud login --help`")
}

pub async fn send(
    client: &Client,
    method: Method,
    url: &str,
    jwt: &str,
    session_token: Option<&str>,
    body: Option<serde_json::Value>,
) -> Result<Response> {
    let mut req = client
        .request(method.clone(), url)
        .header(header::AUTHORIZATION, format!("Bearer {jwt}"));
    if let Some(t) = session_token {
        req = req.header("x-session-token", t);
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
/// status code and the server's response body verbatim. Same shape
/// `create-session.sh` prints on failure — easier debugging than
/// `reqwest::Error: status code 422`.
pub async fn ensure_ok(response: Response, what: &str) -> Result<Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let body = response
        .text()
        .await
        .unwrap_or_else(|_| "<body not readable>".to_string());
    bail!("{what} returned HTTP {status}: {body}");
}
