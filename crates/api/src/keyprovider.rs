//! Artifact-key acquisition ("our keyprovider").
//!
//! Given an encrypted OCI layer's per-artifact [`Key`], produce the
//! ocicrypt [`PrivateLayerBlockCipherOptions`] the TEE decrypts the layer
//! with. We run this dispatch ourselves rather than using ocicrypt's
//! grpc/cmd/native keyprovider transports, because the TEE has no outbound
//! network — the KBS handshake is relayed leg-by-leg through the hatch.
//!
//! - [`Key::Inline`] → the client-supplied bytes ARE the private-opts JSON
//!   (valid only when the session creator owns the artifact).
//! - [`Key::Kbs`]    → run the standard Trustee **RCAR** handshake against
//!   the author's KBS and fetch the layer key as a KBS *resource*. The
//!   resource bytes are the private-opts JSON, JWE-sealed to a per-pull
//!   ephemeral key. See `[[project-trustee-rcar-protocol]]`.

use std::collections::HashMap;

use enclavid_boundary::{AuthN, Untrusted, reason};
use enclavid_crypto::ocicrypt::{self, PrivateLayerBlockCipherOptions};
use enclavid_kbs_client::{RcarSession, SampleEvidence, TeeKeyPair};
use hatch_client::{KbsClient, KbsRequest, KbsResponse};
use session_types::Key;

use crate::boundary::Hatch;

/// Context the [`Key::Kbs`] path needs: the hatch relay client that
/// couriers each RCAR leg to the author's KBS.
pub struct KbsContext<'a> {
    pub kbs: &'a KbsClient<Hatch>,
}

/// Failure obtaining the layer key: which kind, and what went wrong for the
/// debug log — no partial secret in it.
#[derive(Debug)]
pub struct KeyError {
    pub kind: KeyFailure,
    detail: String,
}

/// What a failure to obtain a key says about asking again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyFailure {
    /// Nothing answered this time — the KBS, or the hatch on the way to it — or
    /// this side failed on its own. The same request may succeed later.
    Unanswered,
    /// The KBS answered and released no key: it refused, or what it sent holds
    /// none.
    NotReleased,
    /// The key the session gave inline is not one.
    Invalid,
    /// The artifact does not say which KBS resource holds its key.
    Malformed,
}

impl KeyError {
    pub(crate) fn new(kind: KeyFailure, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

/// Resolve the private block-cipher options for an encrypted layer.
pub async fn obtain_priv_opts(
    annotations: &HashMap<String, String>,
    key: &Key,
    ctx: Option<&KbsContext<'_>>,
) -> Result<PrivateLayerBlockCipherOptions, KeyError> {
    match key {
        Key::Inline(bytes) => ocicrypt::privopts_from_json(bytes)
            .map_err(|e| KeyError::new(KeyFailure::Invalid, e.to_string())),
        Key::Kbs(params) => {
            let ctx = ctx.ok_or_else(|| {
                KeyError::new(KeyFailure::Unanswered, "kbs key requires a KBS context")
            })?;
            let resource = resource_uri(annotations)?;
            kbs_release(&params.endpoint, &resource, ctx).await
        }
    }
}

/// Drive the 3-leg Trustee RCAR handshake to release the layer key.
///
/// The TEE has no outbound network, so each leg is couriered through the
/// hatch's `kbs` call; the hatch is a dumb forwarder threading the
/// `kbs-session-id` cookie's bytes only. The released resource is JWE-
/// sealed to a per-pull ephemeral key minted here, so the hatch never
/// sees the key material even though it carries every byte.
async fn kbs_release(
    endpoint: &str,
    resource: &str,
    ctx: &KbsContext<'_>,
) -> Result<PrivateLayerBlockCipherOptions, KeyError> {
    let resource_path = resource_path(resource)?;

    // Per-pull ephemeral keypair. Its public half is bound into the RCAR
    // report_data; the KBS wraps the released resource's CEK to it. The
    // evidence is CoCo `sample` evidence: the Trustee sample verifier checks
    // only the report_data binding, with no hardware signature behind it, so a
    // broker that releases on it releases to anyone. That is why the measured
    // build takes no broker-released key when a session is created.
    let mut session = RcarSession::new(
        TeeKeyPair::generate()
            .map_err(|e| KeyError::new(KeyFailure::Unanswered, format!("ephemeral key: {e}")))?,
        SampleEvidence,
    );

    // Leg 1 — POST /kbs/v0/auth → nonce + `kbs-session-id` cookie.
    let auth_body = session
        .auth_body()
        .map_err(|e| KeyError::new(KeyFailure::Unanswered, e.to_string()))?;
    let resp = relay(
        ctx,
        endpoint,
        "POST",
        "/kbs/v0/auth",
        json_headers(),
        auth_body,
    )
    .await?
    .trust(reason!(
        AuthN::Indifferent,
        "RCAR handshake plumbing carries no secret; the only released secret is the \
         resource, JWE-sealed to our ephemeral key at leg 3 — tampered or stale \
         handshake bytes only break that unwrap and fail closed"
    ))
    .into_inner();
    require_ok(&resp, "auth")?;
    let cookie = session_cookie(&resp.headers)?;
    session
        .set_challenge(&resp.body)
        .map_err(|e| KeyError::new(KeyFailure::NotReleased, format!("challenge: {e}")))?;

    // Leg 2 — POST /kbs/v0/attest (cookie) → attestation token (200).
    let attest_body = session
        .attest_body()
        .map_err(|e| KeyError::new(KeyFailure::Unanswered, e.to_string()))?;
    let mut headers = json_headers();
    headers.push(("cookie".to_string(), cookie.clone()));
    let resp = relay(
        ctx,
        endpoint,
        "POST",
        "/kbs/v0/attest",
        headers,
        attest_body,
    )
    .await?
    .trust(reason!(
        AuthN::Indifferent,
        "handshake plumbing; release secrecy is enforced at the leg-3 JWE unwrap, which a \
         token from another handshake cannot pass"
    ))
    .into_inner();
    require_ok(&resp, "attest")?;

    // Leg 3 — GET the resource (cookie) → JWE = the layer's private-opts.
    let priv_json = relay(
        ctx,
        endpoint,
        "GET",
        &resource_path,
        vec![("cookie".to_string(), cookie)],
        Vec::new(),
    )
    .await?
    // AuthN is closed by the JWE unwrap: only this enclave's per-pull secret,
    // bound in this handshake's report_data, opens the release, so one from an
    // earlier pull opens under none; and only a holder of this handshake's
    // public key could have wrapped it — over TLS, the broker. Which key is the
    // layer's is settled where the layer ends, by its HMAC against its pinned
    // options.
    .trust_with(AuthN::Verified, |r| {
        require_ok(&r, "resource")?;
        session
            .unwrap_resource(&r.body)
            .map_err(|e| KeyError::new(KeyFailure::NotReleased, format!("jwe unwrap: {e}")))
    })?
    .into_inner();

    ocicrypt::privopts_from_json(&priv_json)
        .map_err(|e| KeyError::new(KeyFailure::NotReleased, e.to_string()))
}

/// Relay one RCAR leg through the hatch, which forwards it verbatim: answered by
/// [`Hatch`]'s declaration and, for who reads it, by the scheme of the broker
/// the consumer named. The KBS response comes back open on `AuthN`, for the
/// caller to answer per leg.
async fn relay(
    ctx: &KbsContext<'_>,
    endpoint: &str,
    method: &str,
    path: &str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> Result<Untrusted<KbsResponse, (AuthN,), Hatch>, KeyError> {
    let req = Hatch::expose(KbsRequest {
        endpoint: endpoint.to_string(),
        method: method.to_string(),
        path: path.to_string(),
        headers,
        body,
    });
    // A session's broker is written `http://` or `https://`: anything else is
    // refused when the session is created.
    let req = if endpoint.starts_with("http://") {
        req.vouch_accept_risk(reason!(
            AuthN::AcceptedRisk,
            "a broker its consumer wrote `http://` is reached in the clear, so the host \
             reads the handshake and which key it asks for, and can answer it; a key it \
             wrapped opens nothing, since the layer's HMAC against its pinned options \
             settles which key is the layer's"
        ))
    } else {
        req.vouch(reason!(
            AuthN::Identified,
            "read by the hatch this leg pins and sent on over TLS that ends inside it, to \
             the broker the consumer named: what is not public in it — the session cookie, \
             the resource the artifact's pinned manifest names — reaches that broker alone"
        ))
    };
    ctx.kbs
        .relay(req)
        .await
        .map_err(|e| KeyError::new(KeyFailure::Unanswered, format!("kbs relay: {e}")))
}

fn json_headers() -> Vec<(String, String)> {
    vec![("content-type".to_string(), "application/json".to_string())]
}

/// A leg that did not answer 200 releases nothing. A KBS that was overloaded,
/// timed out or failed on its side may answer later; any other status is its
/// answer.
fn require_ok(resp: &KbsResponse, leg: &str) -> Result<(), KeyError> {
    if resp.status == 200 {
        return Ok(());
    }
    let kind = match resp.status {
        408 | 429 | 500..=599 => KeyFailure::Unanswered,
        _ => KeyFailure::NotReleased,
    };
    Err(KeyError::new(
        kind,
        format!("kbs {leg} leg returned status {}", resp.status),
    ))
}

/// Extract the `kbs-session-id` cookie from a leg's `Set-Cookie` headers,
/// re-formatted as a `Cookie` header value for the next leg.
fn session_cookie(headers: &[(String, String)]) -> Result<String, KeyError> {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("set-cookie")
            && let Some(rest) = v.strip_prefix("kbs-session-id=")
        {
            let val = rest.split(';').next().unwrap_or("");
            return Ok(format!("kbs-session-id={val}"));
        }
    }
    Err(KeyError::new(
        KeyFailure::NotReleased,
        "auth response missing kbs-session-id cookie",
    ))
}

/// Read the KBS resource URI (`kbs:///<repo>/<type>/<tag>`) from the
/// artifact's `org.opencontainers.image.enc.keys.*` annotation. Author-
/// written and covered by the manifest digest, so the pinned reference
/// integrity-protects which resource the layer key comes from — the hatch
/// / client cannot redirect the TEE to a different key.
fn resource_uri(annotations: &HashMap<String, String>) -> Result<String, KeyError> {
    annotations
        .iter()
        .find(|(k, _)| k.starts_with(ocicrypt::ANNOTATION_KEYS_PREFIX))
        .map(|(_, v)| v.trim().to_string())
        .ok_or_else(|| {
            KeyError::new(
                KeyFailure::Malformed,
                "kbs key: encrypted layer missing enc.keys.* annotation",
            )
        })
}

/// Map a `kbs:///<repo>/<type>/<tag>` resource URI to its KBS request path
/// `/kbs/v0/resource/<repo>/<type>/<tag>`.
fn resource_path(resource: &str) -> Result<String, KeyError> {
    let malformed = || {
        KeyError::new(
            KeyFailure::Malformed,
            "kbs resource must be kbs:///<repo>/<type>/<tag>",
        )
    };
    let rest = resource.strip_prefix("kbs:///").ok_or_else(malformed)?;
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return Err(malformed());
    }
    Ok(format!("/kbs/v0/resource/{rest}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_uri_read_from_enc_keys_annotation() {
        let mut ann = HashMap::new();
        ann.insert(
            format!("{}provider.enclavid-kbs", ocicrypt::ANNOTATION_KEYS_PREFIX),
            "kbs:///myrepo/key/1".to_string(),
        );
        assert_eq!(resource_uri(&ann).unwrap(), "kbs:///myrepo/key/1");
    }

    #[test]
    fn resource_uri_missing_annotation_errors() {
        let ann = HashMap::new();
        assert!(resource_uri(&ann).is_err());
    }

    #[test]
    fn resource_path_maps_well_formed_uri() {
        assert_eq!(
            resource_path("kbs:///myrepo/key/1").unwrap(),
            "/kbs/v0/resource/myrepo/key/1"
        );
    }

    #[test]
    fn resource_path_rejects_malformed() {
        for bad in [
            "myrepo/key/1",
            "kbs:///two/parts",
            "kbs:///a/b/c/d",
            "kbs:///a//c",
        ] {
            assert!(resource_path(bad).is_err(), "should reject {bad}");
        }
    }

    #[test]
    fn session_cookie_extracts_value_dropping_attributes() {
        let headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            (
                "Set-Cookie".to_string(),
                "kbs-session-id=abc123; Path=/; HttpOnly; SameSite=Strict".to_string(),
            ),
        ];
        assert_eq!(session_cookie(&headers).unwrap(), "kbs-session-id=abc123");
    }

    /// A KBS that was overloaded, timed out or failed on its side may release
    /// the key later; any other answer but 200 is its refusal.
    #[test]
    fn a_leg_that_failed_on_the_kbs_side_may_pass_later() {
        let leg = |status| KbsResponse {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        };
        assert!(require_ok(&leg(200), "auth").is_ok());
        for status in [408, 429, 500, 502, 503, 504] {
            let e = require_ok(&leg(status), "auth").unwrap_err();
            assert_eq!(e.kind, KeyFailure::Unanswered, "{status}");
        }
        for status in [400, 401, 403, 404] {
            let e = require_ok(&leg(status), "auth").unwrap_err();
            assert_eq!(e.kind, KeyFailure::NotReleased, "{status}");
        }
    }

    #[test]
    fn session_cookie_absent_errors() {
        let headers = vec![("x".to_string(), "y".to_string())];
        assert!(session_cookie(&headers).is_err());
    }
}
