//! Artifact-key acquisition ("our keyprovider").
//!
//! Given an encrypted OCI layer's per-artifact [`Key`], produce the
//! ocicrypt [`PrivateLayerBlockCipherOptions`] the TEE decrypts the layer
//! with. We run this dispatch ourselves rather than using ocicrypt's
//! grpc/cmd/native keyprovider transports, because the TEE has no outbound
//! network — the KBS handshake is relayed leg-by-leg through the broker.
//!
//! - [`Key::Inline`] → the client-supplied bytes ARE the private-opts JSON
//!   (valid only when the session creator owns the artifact).
//! - [`Key::Kbs`]    → run the standard Trustee **RCAR** handshake against
//!   the author's KBS and fetch the layer key as a KBS *resource*. The
//!   resource bytes are the private-opts JSON, JWE-sealed to a per-pull
//!   ephemeral key. See `[[project-trustee-rcar-protocol]]`.

use std::collections::HashMap;

use broker_client::{
    AuthN, AuthZ, Covert, KbsClient, Key, Replay, Untrusted, boundary, reason,
};
use broker_protocol::{KbsRelayRequest, KbsRelayResponse};
use enclavid_crypto::ocicrypt::{self, PrivateLayerBlockCipherOptions};
use enclavid_kbs_client::{RcarSession, SampleEvidence, TeeKeyPair};

/// Context the [`Key::Kbs`] path needs: the broker relay client that
/// couriers each RCAR leg to the author's KBS.
pub struct KbsContext<'a> {
    pub kbs: &'a KbsClient,
}

/// Failure obtaining the layer key. Mapped to `PullError::Decrypt` by the
/// caller — deliberately opaque (no partial-secret leakage).
#[derive(Debug)]
pub struct KeyError(pub String);

impl KeyError {
    fn msg(m: impl Into<String>) -> Self {
        Self(m.into())
    }
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Resolve the private block-cipher options for an encrypted layer.
pub async fn obtain_priv_opts(
    annotations: &HashMap<String, String>,
    key: &Key,
    ctx: Option<&KbsContext<'_>>,
) -> Result<PrivateLayerBlockCipherOptions, KeyError> {
    match key {
        Key::Inline(bytes) => {
            ocicrypt::privopts_from_json(bytes).map_err(|e| KeyError::msg(e.to_string()))
        }
        Key::Kbs(params) => {
            let ctx = ctx.ok_or_else(|| KeyError::msg("kbs key requires a KBS context"))?;
            let resource = resource_uri(annotations)?;
            kbs_release(&params.endpoint, &resource, ctx).await
        }
    }
}

/// Drive the 3-leg Trustee RCAR handshake to release the layer key.
///
/// The TEE has no outbound network, so each leg is couriered through the
/// broker `/kbs/relay`; the broker is a dumb forwarder threading the
/// `kbs-session-id` cookie's bytes only. The released resource is JWE-
/// sealed to a per-pull ephemeral key minted here, so the broker never
/// sees the key material even though it carries every byte.
async fn kbs_release(
    endpoint: &str,
    resource: &str,
    ctx: &KbsContext<'_>,
) -> Result<PrivateLayerBlockCipherOptions, KeyError> {
    let resource_path = resource_path(resource)?;

    // Per-pull ephemeral keypair. Its public half is bound into the RCAR
    // report_data; the KBS wraps the released resource's CEK to it. Dev
    // presents CoCo `sample` evidence — the Trustee sample verifier checks
    // only the report_data binding, no hardware signature; a real SEV-SNP
    // deployment swaps in an SNP evidence provider here.
    let mut session = RcarSession::new(
        TeeKeyPair::generate().map_err(|e| KeyError::msg(format!("ephemeral key: {e}")))?,
        SampleEvidence,
    );

    // Leg 1 — POST /kbs/v0/auth → nonce + `kbs-session-id` cookie.
    let auth_body = session
        .auth_body()
        .map_err(|e| KeyError::msg(e.to_string()))?;
    let resp = relay(ctx, endpoint, "POST", "/kbs/v0/auth", json_headers(), auth_body)
        .await?
        .trust_unchecked::<AuthN, _>(reason!(
            "RCAR handshake plumbing carries no secret; the only released secret is the \
             resource, JWE-sealed to our ephemeral key at leg 3 — tampered handshake bytes \
             only break that unwrap and fail closed"
        ))
        .trust_unchecked::<AuthZ, _>(reason!(
            "the KBS, not the TEE, authorizes release (resource policy + token)"
        ))
        .trust_unchecked::<Replay, _>(reason!(
            "a stale challenge only breaks the report_data binding and fails the leg-3 unwrap"
        ))
        .into_inner();
    require_ok(&resp, "auth")?;
    let cookie = session_cookie(&resp.headers)?;
    session
        .set_challenge(&resp.body)
        .map_err(|e| KeyError::msg(format!("challenge: {e}")))?;

    // Leg 2 — POST /kbs/v0/attest (cookie) → attestation token (200).
    let attest_body = session
        .attest_body()
        .map_err(|e| KeyError::msg(e.to_string()))?;
    let mut headers = json_headers();
    headers.push(("cookie".to_string(), cookie.clone()));
    let resp = relay(ctx, endpoint, "POST", "/kbs/v0/attest", headers, attest_body)
        .await?
        .trust_unchecked::<AuthN, _>(reason!(
            "handshake plumbing; release secrecy is enforced at the leg-3 JWE unwrap"
        ))
        .trust_unchecked::<AuthZ, _>(reason!(
            "the KBS verifies the evidence and gates the token, not the TEE"
        ))
        .trust_unchecked::<Replay, _>(reason!(
            "attestation binds this handshake's fresh nonce; a replayed token can't unwrap \
             the resource sealed to our per-pull ephemeral key"
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
    // AuthN is closed by the JWE unwrap: only this enclave's per-pull
    // ephemeral secret opens the released resource.
    .trust::<AuthN, _, _, _, _>(|r| {
        require_ok(&r, "resource")?;
        session
            .unwrap_resource(&r.body)
            .map_err(|e| KeyError::msg(format!("jwe unwrap: {e}")))
    })?
    .trust_unchecked::<AuthZ, _>(reason!(
        "the KBS enforces release authorization via its resource policy (Rego) + token; \
         the TEE only consumes the sealed result"
    ))
    .trust_unchecked::<Replay, _>(reason!(
        "the resource is JWE-sealed to a per-pull ephemeral key bound in this handshake's \
         report_data; a replayed blob from a prior pull cannot open under the fresh secret"
    ))
    .into_inner();

    ocicrypt::privopts_from_json(&priv_json).map_err(|e| KeyError::msg(e.to_string()))
}

/// Vouch and relay one RCAR leg through the broker. The leg body is public
/// RCAR material (our ephemeral pubkey, sample evidence, the session
/// cookie); the broker forwards it verbatim and returns the KBS response
/// `Untrusted` for the caller to peel per-leg.
async fn relay(
    ctx: &KbsContext<'_>,
    endpoint: &str,
    method: &str,
    path: &str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> Result<Untrusted<KbsRelayResponse, (AuthN, AuthZ, Replay)>, KeyError> {
    let req = KbsRelayRequest {
        endpoint: endpoint.to_string(),
        method: method.to_string(),
        path: path.to_string(),
        headers,
        body,
    };
    let exposed = boundary::outbound::to_untrusted(req)
        .vouch_unchecked::<AuthN, _>(reason!(
            "the leg carries only public RCAR material — our ephemeral pubkey, the sample \
             evidence, the session cookie; no TEE secret"
        ))
        .vouch_unchecked::<AuthZ, _>(reason!(
            "forwarding the artifact-key handshake to the author's KBS IS the courier op"
        ))
        .vouch_unchecked::<Covert, _>(reason!(
            "endpoint is client-supplied at session create and the resource URI is the \
             artifact's digest-pinned annotation — neither is policy-controlled; leg shape \
             is fixed by the RCAR protocol"
        ));
    ctx.kbs
        .relay(exposed)
        .await
        .map_err(|e| KeyError::msg(format!("kbs relay: {e}")))
}

fn json_headers() -> Vec<(String, String)> {
    vec![("content-type".to_string(), "application/json".to_string())]
}

fn require_ok(resp: &KbsRelayResponse, leg: &str) -> Result<(), KeyError> {
    if resp.status != 200 {
        return Err(KeyError::msg(format!(
            "kbs {leg} leg returned status {}",
            resp.status
        )));
    }
    Ok(())
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
    Err(KeyError::msg("auth response missing kbs-session-id cookie"))
}

/// Read the KBS resource URI (`kbs:///<repo>/<type>/<tag>`) from the
/// artifact's `org.opencontainers.image.enc.keys.*` annotation. Author-
/// written and covered by the manifest digest, so the pinned reference
/// integrity-protects which resource the layer key comes from — the broker
/// / client cannot redirect the TEE to a different key.
fn resource_uri(annotations: &HashMap<String, String>) -> Result<String, KeyError> {
    annotations
        .iter()
        .find(|(k, _)| k.starts_with(ocicrypt::ANNOTATION_KEYS_PREFIX))
        .map(|(_, v)| v.trim().to_string())
        .ok_or_else(|| KeyError::msg("kbs key: encrypted layer missing enc.keys.* annotation"))
}

/// Map a `kbs:///<repo>/<type>/<tag>` resource URI to its KBS request path
/// `/kbs/v0/resource/<repo>/<type>/<tag>`.
fn resource_path(resource: &str) -> Result<String, KeyError> {
    let rest = resource
        .strip_prefix("kbs:///")
        .ok_or_else(|| KeyError::msg("kbs resource must be kbs:///<repo>/<type>/<tag>"))?;
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return Err(KeyError::msg("kbs resource must be kbs:///<repo>/<type>/<tag>"));
    }
    Ok(format!("/kbs/v0/resource/{rest}"))
}
