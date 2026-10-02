//! KBS relay handler: forwards a single KBS handshake/key-release leg to
//! whichever KBS the TEE-supplied `endpoint` points at.
//!
//! The hatch is a DUMB, STATELESS byte forwarder. The TEE-side driver
//! runs the KBS attestation handshake (RCAR: auth → challenge →
//! attestation → resource) as a state machine and forwards each leg here;
//! this handler just replays method/path/headers/body to the KBS and
//! returns the response. The released secret is JWE-wrapped to the TEE's
//! ephemeral key, so the hatch never sees plaintext key material even
//! though it carries the bytes — same trust posture as the OCI pull
//! courier.
//!
//! Bounded as a pull is: the broker's answer is read only so far and within a
//! deadline, and a redirect is not followed — it would replay the POST, body
//! and all, to wherever it pointed.

use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use reqwest::Method;
use reqwest::header::SET_COOKIE;
use reqwest::redirect::Policy;
use tracing::warn;

use hatch_protocol::{KbsRelayRequest, KbsRelayResponse};

use crate::AppState;
use crate::error::{HatchError, decode_body, encode_body};

/// An attestation token or a wrapped key fits in far less.
const ANSWER_BYTES: usize = 1 << 20;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Under the TEE's own 20 s for a leg.
const LEG_TIMEOUT: Duration = Duration::from_secs(15);

/// The relay's one client, made at startup.
pub fn client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .redirect(Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(LEG_TIMEOUT)
        .build()?)
}

/// POST /kbs/relay
pub async fn relay(State(state): State<AppState>, body: Bytes) -> Result<Vec<u8>, HatchError> {
    let req: KbsRelayRequest = decode_body(&body)?;
    let url = join_url(&req.endpoint, &req.path)?;
    let method = Method::from_bytes(req.method.as_bytes())
        .map_err(|_| HatchError::BadRequest(format!("invalid method: {}", req.method)))?;

    let mut builder = state.kbs.request(method, url).body(req.body);
    for (k, v) in &req.headers {
        builder = builder.header(k, v);
    }
    let mut resp = builder.send().await.map_err(|e| {
        warn!(endpoint = %req.endpoint, err = %e, "kbs relay failed");
        HatchError::Internal(format!("kbs relay: {e}"))
    })?;

    let status = resp.status().as_u16();
    // The session cookie is all the TEE reads of the headers. Every one is
    // kept: a broker may set it among others.
    let headers = resp
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| {
            v.to_str()
                .ok()
                .map(|v| (SET_COOKIE.to_string(), v.to_string()))
        })
        .collect();
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| HatchError::Internal(format!("kbs relay body: {e}")))?
    {
        if body.len() + chunk.len() > ANSWER_BYTES {
            warn!(endpoint = %req.endpoint, "kbs answer past the limit");
            return Err(HatchError::Internal(format!(
                "kbs relay: answer past {ANSWER_BYTES} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }

    encode_body(&KbsRelayResponse {
        status,
        headers,
        body,
    })
}

/// Join `endpoint` + `path` into an absolute http(s) URL. Loud reject on a
/// non-http(s) scheme (the TEE only ever talks to an HTTP KBS through us).
fn join_url(endpoint: &str, path: &str) -> Result<String, HatchError> {
    let base = endpoint.trim_end_matches('/');
    let url = if path.starts_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    };
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(HatchError::BadRequest(
            "kbs endpoint must be http(s)".to_string(),
        ));
    }
    Ok(url)
}
