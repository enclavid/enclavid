//! Artifact-key acquisition ("our keyprovider").
//!
//! Given an encrypted OCI layer's annotations and the per-artifact
//! `key_source`, produce the ocicrypt [`PrivateLayerBlockCipherOptions`]
//! the TEE decrypts the layer with. This is the dispatch the security
//! model calls the keyprovider — we run it ourselves rather than using
//! ocicrypt's grpc/cmd/native transports, because the TEE has no outbound
//! network and the KBS leg is relayed through the broker.
//!
//! - `Plaintext` → never reached (the layer is not encrypted).
//! - `Inbound`   → the client-supplied bytes ARE the private-opts JSON
//!   (owner == session creator).
//! - `Kbs`       → mint an ephemeral keypair, bind it in an attestation
//!   quote, send the wrapped-key blob + token to the owner's KBS through
//!   the broker relay, and unseal the response to the ephemeral key.

use std::collections::HashMap;

use base64ct::{Base64, Encoding};

use broker_client::{
    AuthN, AuthZ, Covert, KbsClient, KbsKey, Key, Replay, boundary, reason,
};
use broker_protocol::{KbsKeyRequest, KbsKeyResponse, KbsRelayRequest, SealedBlob};
use enclavid_attestation::{Attestor, ReportData};
use enclavid_crypto::kbswrap;
use enclavid_crypto::ocicrypt::{self, PrivateLayerBlockCipherOptions};

/// Context the `kbs` key_source needs: the relay client and the attestor
/// for the ephemeral-key-binding quote.
pub struct KbsContext<'a> {
    pub kbs: &'a KbsClient,
    pub attestor: &'a dyn Attestor,
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
            kbs_release(annotations, params, ctx).await
        }
    }
}

async fn kbs_release(
    annotations: &HashMap<String, String>,
    params: &KbsKey,
    ctx: &KbsContext<'_>,
) -> Result<PrivateLayerBlockCipherOptions, KeyError> {
    // The wrapped layer key lives in the artifact's `enc.keys.*`
    // annotation (sealed to the KBS at encrypt time). Opaque to us — we
    // forward it to the KBS, which unwraps and re-seals to our ephemeral
    // key.
    let wrapped = find_wrapped_key(annotations)?;

    // Per-pull ephemeral keypair; the public half is bound in the quote so
    // the KBS releases the secret only to this enclave.
    let (eph_secret, eph_public) = kbswrap::generate_keypair();
    let report = ReportData::for_kbs(eph_public.to_vec());
    let quote = ctx
        .attestor
        .mint(&report)
        .map_err(|e| KeyError::msg(format!("attestation mint: {e}")))?;
    let quote_bytes = serde_json::to_vec(&quote).map_err(|e| KeyError::msg(e.to_string()))?;

    let key_req = KbsKeyRequest {
        quote: quote_bytes,
        tee_ephemeral_pubkey: eph_public.to_vec(),
        token: params.token.clone(),
        wrapped_priv_opts: wrapped,
    };
    let body = broker_protocol::encode(&key_req).map_err(|e| KeyError::msg(e.to_string()))?;

    let relay_req = KbsRelayRequest {
        endpoint: params.endpoint.clone(),
        method: "POST".to_string(),
        path: "/key".to_string(),
        headers: vec![(
            "content-type".to_string(),
            "application/octet-stream".to_string(),
        )],
        body,
    };
    let exposed = boundary::outbound::to_untrusted(relay_req)
        .vouch_unchecked::<AuthN, _>(reason!(
            "request carries only the wrapped-key blob (sealed to the KBS), the \
             token, and the attestation quote — no TEE secret; broker relays it verbatim"
        ))
        .vouch_unchecked::<AuthZ, _>(reason!(
            "forwarding the artifact-key handshake to the owner's KBS IS the courier op"
        ))
        .vouch_unchecked::<Covert, _>(reason!(
            "endpoint+token are client-supplied at session create, not policy-controlled; \
             request shape is fixed by the protocol"
        ));

    let priv_json = ctx
        .kbs
        .relay(exposed)
        .await
        .map_err(|e| KeyError::msg(format!("kbs relay: {e}")))?
        // AuthN is closed by the sealed-box open: forged/substituted bytes
        // cannot open under our per-pull ephemeral secret.
        .trust::<AuthN, _, _, _, _>(|r| {
            if r.status != 200 {
                return Err(KeyError::msg(format!("kbs returned status {}", r.status)));
            }
            let key_resp: KbsKeyResponse =
                broker_protocol::decode(&r.body).map_err(|e| KeyError::msg(e.to_string()))?;
            let sealed = to_sealed(key_resp.sealed)?;
            kbswrap::open(&eph_secret, &sealed)
                .map_err(|_| KeyError::msg("kbs response unseal failed"))
        })?
        .trust_unchecked::<AuthZ, _>(reason!(
            "the KBS enforces release authorization on the token + attestation policy; \
             the TEE only consumes the sealed result"
        ))
        .trust_unchecked::<Replay, _>(reason!(
            "the response is sealed to a per-pull ephemeral key; a replayed blob from a \
             prior pull cannot open under the fresh ephemeral secret"
        ))
        .into_inner();

    ocicrypt::privopts_from_json(&priv_json).map_err(|e| KeyError::msg(e.to_string()))
}

/// Find and base64-decode the first `org.opencontainers.image.enc.keys.*`
/// annotation (the wrapped layer key). Opaque bytes — forwarded to the KBS.
fn find_wrapped_key(annotations: &HashMap<String, String>) -> Result<Vec<u8>, KeyError> {
    let value = annotations
        .iter()
        .find(|(k, _)| k.starts_with(ocicrypt::ANNOTATION_KEYS_PREFIX))
        .map(|(_, v)| v)
        .ok_or_else(|| KeyError::msg("encrypted layer missing enc.keys.* annotation"))?;
    Base64::decode_vec(value).map_err(|e| KeyError::msg(format!("enc.keys base64: {e}")))
}

fn to_sealed(blob: SealedBlob) -> Result<kbswrap::Sealed, KeyError> {
    let sender_pub: [u8; 32] = blob
        .sender_pub
        .try_into()
        .map_err(|_| KeyError::msg("kbs sealed: sender_pub must be 32 bytes"))?;
    let nonce: [u8; 12] = blob
        .nonce
        .try_into()
        .map_err(|_| KeyError::msg("kbs sealed: nonce must be 12 bytes"))?;
    Ok(kbswrap::Sealed {
        sender_pub,
        nonce,
        ciphertext: blob.ciphertext,
    })
}
