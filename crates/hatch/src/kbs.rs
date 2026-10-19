//! One leg of a key broker's attestation handshake, relayed to whichever broker
//! the consumer named.
//!
//! The hatch is a stateless forwarder here. api runs the handshake (Trustee
//! RCAR: auth → attestation → resource) and hands each leg over; this sends it
//! as it came and hands back the answer. The released key is wrapped to api's
//! ephemeral key, so the hatch carries it unread.
//!
//! Bounded as a pull is: the broker's answer is read only so far and within a
//! deadline, and a redirect is not followed — it would replay the POST, body
//! and all, to wherever it pointed.

use std::time::Duration;

use reqwest::Method;
use reqwest::header::SET_COOKIE;
use reqwest::redirect::Policy;

use hatch_rpc::{KbsError, KbsRequest, KbsResponse};
use safe_logger::debug;

/// An attestation token or a wrapped key fits in far less.
const ANSWER_BYTES: usize = 1 << 20;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Under api's own wait for a leg.
const LEG_TIMEOUT: Duration = Duration::from_secs(15);

/// The relay's one client, made at startup.
pub fn client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(LEG_TIMEOUT)
        .build()
}

/// Send one leg and read its answer.
pub async fn relay(client: &reqwest::Client, req: KbsRequest) -> Result<KbsResponse, KbsError> {
    let url = join_url(&req.endpoint, &req.path)?;
    let method = Method::from_bytes(req.method.as_bytes())
        .map_err(|_| KbsError(format!("invalid method: {}", req.method)))?;

    let mut builder = client.request(method, url).body(req.body);
    for (k, v) in &req.headers {
        builder = builder.header(k, v);
    }
    let mut resp = builder.send().await.map_err(|e| {
        debug!("kbs leg to {}: {e}", req.endpoint);
        KbsError("the broker did not answer".into())
    })?;

    let status = resp.status().as_u16();
    // The session cookie is all api reads of the headers. Every one is kept: a
    // broker may set it among others.
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
        .map_err(|_| KbsError("the broker's answer broke off".into()))?
    {
        if body.len() + chunk.len() > ANSWER_BYTES {
            return Err(KbsError(format!("an answer past {ANSWER_BYTES} bytes")));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(KbsResponse {
        status,
        headers,
        body,
    })
}

/// `endpoint` + `path` as an absolute http(s) URL, and nothing else.
fn join_url(endpoint: &str, path: &str) -> Result<String, KbsError> {
    let base = endpoint.trim_end_matches('/');
    let url = if path.starts_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    };
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(KbsError("a broker is reached over http(s)".into()));
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_leg_goes_to_the_brokers_path_over_http() {
        assert_eq!(
            join_url("https://kbs.example:8080/", "/kbs/v0/auth").unwrap(),
            "https://kbs.example:8080/kbs/v0/auth"
        );
        assert_eq!(
            join_url("http://kbs.example", "kbs/v0/auth").unwrap(),
            "http://kbs.example/kbs/v0/auth"
        );
        for refused in ["file:///etc", "kbs.example", "ftp://kbs.example"] {
            assert!(join_url(refused, "/kbs/v0/auth").is_err(), "{refused}");
        }
    }
}
