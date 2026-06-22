//! KBS relay handler: forwards a single KBS handshake/key-release leg to
//! whichever KBS the TEE-supplied `endpoint` points at.
//!
//! The broker is a DUMB, STATELESS byte forwarder. The TEE-side driver
//! runs the KBS attestation handshake (RCAR: auth → challenge →
//! attestation → resource) as a state machine and forwards each leg here;
//! this handler just replays method/path/headers/body to the KBS and
//! returns the response verbatim. The released secret is JWE-wrapped to
//! the TEE's ephemeral key, so the broker never sees plaintext key
//! material even though it carries the bytes — same trust posture as the
//! OCI pull courier.

use axum::body::Bytes;
use reqwest::Method;
use tracing::warn;

use broker_protocol::{KbsRelayRequest, KbsRelayResponse};

use crate::error::{BrokerError, decode_body, encode_body};

/// POST /kbs/relay
pub async fn relay(body: Bytes) -> Result<Vec<u8>, BrokerError> {
    let req: KbsRelayRequest = decode_body(&body)?;
    let url = join_url(&req.endpoint, &req.path)?;
    let method = Method::from_bytes(req.method.as_bytes())
        .map_err(|_| BrokerError::BadRequest(format!("invalid method: {}", req.method)))?;

    let client = reqwest::Client::new();
    let mut builder = client.request(method, url).body(req.body);
    for (k, v) in &req.headers {
        builder = builder.header(k, v);
    }
    let resp = builder.send().await.map_err(|e| {
        warn!(endpoint = %req.endpoint, err = %e, "kbs relay failed");
        BrokerError::Internal(format!("kbs relay: {e}"))
    })?;

    let status = resp.status().as_u16();
    // Preserve duplicates (e.g. multiple Set-Cookie) — the TEE driver
    // reads the RCAR session cookie from here.
    let headers = resp
        .headers()
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
        .collect();
    let body = resp
        .bytes()
        .await
        .map_err(|e| BrokerError::Internal(format!("kbs relay body: {e}")))?
        .to_vec();

    encode_body(&KbsRelayResponse {
        status,
        headers,
        body,
    })
}

/// Join `endpoint` + `path` into an absolute http(s) URL. Loud reject on a
/// non-http(s) scheme (the TEE only ever talks to an HTTP KBS through us).
fn join_url(endpoint: &str, path: &str) -> Result<String, BrokerError> {
    let base = endpoint.trim_end_matches('/');
    let url = if path.starts_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    };
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(BrokerError::BadRequest(
            "kbs endpoint must be http(s)".to_string(),
        ));
    }
    Ok(url)
}
