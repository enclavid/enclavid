//! Minimal stand-in KBS for the `kbs` key_source path.
//!
//! Test/dev only. A real artifact-key KBS (e.g. Trustee) verifies a full
//! SEV-SNP evidence chain; this stub verifies a [`Quote`] via a supplied
//! [`Attestor`] (the `MockAttestor` in CI), checks the authorization
//! token, unwraps the artifact's layer key (sealed to the KBS at encrypt
//! time), and re-seals it to the TEE's attested ephemeral key.
//!
//! [`release`] is the pure request→response core (CBOR in, CBOR out) so it
//! drops into both an in-process test and a future thin HTTP wrapper that
//! the broker `/kbs/relay` forwards to.

use std::collections::HashSet;
use std::sync::Arc;

use broker_protocol::{KbsKeyRequest, KbsKeyResponse, SealedBlob};
use enclavid_attestation::{Attestor, Quote, ReportData};
use enclavid_crypto::kbswrap;

/// KBS configuration: the X25519 secret artifacts were sealed to, the
/// attestor used to verify quotes, the measurement to pin, and the set of
/// authorized tokens (`None` ⇒ accept any non-empty token).
pub struct KbsConfig {
    pub secret: [u8; 32],
    pub attestor: Arc<dyn Attestor>,
    /// Expected TEE measurement (hex). The quote's measurement must match.
    pub expected_measurement: String,
    pub allowed_tokens: Option<HashSet<String>>,
}

#[derive(Debug)]
pub enum KbsError {
    Decode(String),
    Denied(&'static str),
    Internal(String),
}

impl std::fmt::Display for KbsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KbsError::Decode(m) => write!(f, "kbs decode: {m}"),
            KbsError::Denied(m) => write!(f, "kbs denied: {m}"),
            KbsError::Internal(m) => write!(f, "kbs internal: {m}"),
        }
    }
}

impl std::error::Error for KbsError {}

/// Process a `KbsKeyRequest` (CBOR) and return a `KbsKeyResponse` (CBOR):
/// the artifact's private opts re-sealed to the TEE's ephemeral key.
pub fn release(request_bytes: &[u8], cfg: &KbsConfig) -> Result<Vec<u8>, KbsError> {
    let req: KbsKeyRequest =
        broker_protocol::decode(request_bytes).map_err(|e| KbsError::Decode(e.to_string()))?;

    // 1. Authorization token.
    if req.token.is_empty() {
        return Err(KbsError::Denied("empty token"));
    }
    if let Some(allowed) = &cfg.allowed_tokens {
        if !allowed.contains(&req.token) {
            return Err(KbsError::Denied("token not authorized"));
        }
    }

    // 2. Attestation: the quote must carry our expected measurement and
    //    bind exactly the ephemeral key the request asks us to seal to.
    let quote: Quote =
        serde_json::from_slice(&req.quote).map_err(|e| KbsError::Decode(e.to_string()))?;
    if quote.measurement != cfg.expected_measurement {
        return Err(KbsError::Denied("measurement mismatch"));
    }
    let eph_pub: [u8; 32] = req
        .tee_ephemeral_pubkey
        .clone()
        .try_into()
        .map_err(|_| KbsError::Denied("ephemeral pubkey must be 32 bytes"))?;
    let expected = ReportData::for_kbs(eph_pub.to_vec());
    cfg.attestor
        .verify(&quote, &expected)
        .map_err(|_| KbsError::Denied("quote verification failed"))?;

    // 3. Unwrap the layer key (sealed to us at encrypt time), re-seal to
    //    the attested TEE ephemeral key.
    let wrapped: SealedBlob = broker_protocol::decode(&req.wrapped_priv_opts)
        .map_err(|e| KbsError::Decode(e.to_string()))?;
    let priv_json = kbswrap::open(&cfg.secret, &to_sealed(wrapped)?)
        .map_err(|e| KbsError::Internal(e.to_string()))?;
    let resealed =
        kbswrap::seal(&eph_pub, &priv_json).map_err(|e| KbsError::Internal(e.to_string()))?;

    let resp = KbsKeyResponse {
        sealed: SealedBlob {
            sender_pub: resealed.sender_pub.to_vec(),
            nonce: resealed.nonce.to_vec(),
            ciphertext: resealed.ciphertext,
        },
    };
    broker_protocol::encode(&resp).map_err(|e| KbsError::Internal(e.to_string()))
}

/// Generate a KBS keypair `(secret, public)`. The public key is what the
/// artifact owner seals layer keys to (`enclavid oci push --kbs-pubkey`).
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    kbswrap::generate_keypair()
}

fn to_sealed(blob: SealedBlob) -> Result<kbswrap::Sealed, KbsError> {
    let sender_pub: [u8; 32] = blob
        .sender_pub
        .try_into()
        .map_err(|_| KbsError::Decode("sealed sender_pub must be 32 bytes".to_string()))?;
    let nonce: [u8; 12] = blob
        .nonce
        .try_into()
        .map_err(|_| KbsError::Decode("sealed nonce must be 12 bytes".to_string()))?;
    Ok(kbswrap::Sealed {
        sender_pub,
        nonce,
        ciphertext: blob.ciphertext,
    })
}
