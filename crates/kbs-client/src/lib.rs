//! TEE-side Trustee KBS **RCAR client** (protocol v0.4.0).
//!
//! Transport-free by design: it builds each handshake leg's request body
//! and parses each response, while the **caller** performs the I/O — the
//! hatch `/kbs/relay` in production (no outbound from the TEE), or direct
//! HTTP in tests. The caller threads the `kbs-session-id` cookie. See
//! `[[project-trustee-rcar-protocol]]`.
//!
//! Flow:
//! ```text
//! let mut s = RcarSession::new(TeeKeyPair::generate()?, SampleEvidence);
//! POST /kbs/v0/auth     s.auth_body()       -> s.set_challenge(resp)
//! POST /kbs/v0/attest   s.attest_body()?    -> (200 = token)
//! GET  /kbs/v0/resource/{repo}/{type}/{tag} -> s.unwrap_resource(resp)?  // = the key
//! ```

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use kbs_types::{
    Attestation, Challenge, CompositeEvidence, Request, Response, RuntimeData, Tee, TeePubKey,
};
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha384};

/// RCAR protocol version this client speaks (the live KBS enforces `=`).
pub const KBS_PROTOCOL_VERSION: &str = "0.4.0";
/// JWA alg we advertise in the TEE pubkey; the KBS wraps the CEK with it.
const TEE_PUBKEY_ALG: &str = "RSA-OAEP-256";

#[derive(Debug, thiserror::Error)]
pub enum KbsError {
    #[error("rsa: {0}")]
    Rsa(String),
    #[error("decode kbs message: {0}")]
    Decode(String),
    #[error("jwe: {0}")]
    Jwe(String),
    #[error("protocol: {0}")]
    Protocol(String),
}

/// Ephemeral TEE keypair — the `TeeKeyPair` role: its public half is bound
/// in `runtime_data.tee_pubkey` (and, in prod, in the SNP `report_data`),
/// and the KBS wraps the released resource's CEK to it.
pub struct TeeKeyPair {
    private: RsaPrivateKey,
    public: RsaPublicKey,
}

impl TeeKeyPair {
    pub fn generate() -> Result<Self, KbsError> {
        let mut rng = rand_core::OsRng;
        let private =
            RsaPrivateKey::new(&mut rng, 2048).map_err(|e| KbsError::Rsa(e.to_string()))?;
        let public = RsaPublicKey::from(&private);
        Ok(Self { private, public })
    }

    /// Export as a kbs-types `TeePubKey` (RSA JWK, base64url n/e).
    pub fn to_tee_pubkey(&self) -> TeePubKey {
        TeePubKey::RSA {
            alg: TEE_PUBKEY_ALG.to_string(),
            k_mod: Base64UrlUnpadded::encode_string(&self.public.n().to_bytes_be()),
            k_exp: Base64UrlUnpadded::encode_string(&self.public.e().to_bytes_be()),
        }
    }

    /// Decrypt a KBS `Response` (JWE: RSA-OAEP-256 CEK → A256GCM payload).
    pub fn decrypt_response(&self, response: &Response) -> Result<Vec<u8>, KbsError> {
        // 1. Unwrap the content-encryption key.
        let cek = self
            .private
            .decrypt(Oaep::new::<Sha256>(), &response.encrypted_key)
            .map_err(|e| KbsError::Jwe(format!("unwrap CEK: {e}")))?;

        // 2. AES-256-GCM over ciphertext||tag, AAD = base64url(protected).
        let aad = response
            .protected
            .generate_aad()
            .map_err(|e| KbsError::Jwe(format!("aad: {e}")))?;
        let cipher =
            Aes256Gcm::new_from_slice(&cek).map_err(|e| KbsError::Jwe(format!("cek len: {e}")))?;
        let mut ct = response.ciphertext.clone();
        ct.extend_from_slice(&response.tag);
        cipher
            .decrypt(
                Nonce::from_slice(&response.iv),
                Payload { msg: &ct, aad: &aad },
            )
            .map_err(|_| KbsError::Jwe("gcm decrypt failed".to_string()))
    }
}

/// Produces the evidence for one TEE type. Dev uses [`SampleEvidence`]; a
/// prod SNP provider builds the real `sev` report with the same binding.
pub trait EvidenceProvider {
    fn tee(&self) -> Tee;
    /// `primary_evidence` for the given `report_data` binding (48 bytes:
    /// the SHA-384 the AS expects).
    fn primary_evidence(&self, report_data: &[u8]) -> Value;
}

/// Dev evidence for the CoCo `sample` TEE (no hardware signature; the AS
/// only checks the `report_data` binding).
pub struct SampleEvidence;

impl EvidenceProvider for SampleEvidence {
    fn tee(&self) -> Tee {
        Tee::Sample
    }
    fn primary_evidence(&self, report_data: &[u8]) -> Value {
        json!({ "svn": "1", "report_data": Base64::encode_string(report_data) })
    }
}

/// One RCAR handshake. Build leg bodies, feed responses back; the caller
/// owns the HTTP/relay + cookie.
pub struct RcarSession<E: EvidenceProvider> {
    keypair: TeeKeyPair,
    evidence: E,
    nonce: Option<String>,
}

impl<E: EvidenceProvider> RcarSession<E> {
    pub fn new(keypair: TeeKeyPair, evidence: E) -> Self {
        Self {
            keypair,
            evidence,
            nonce: None,
        }
    }

    pub fn keypair(&self) -> &TeeKeyPair {
        &self.keypair
    }

    /// Leg 1 body — `POST /kbs/v0/auth`.
    pub fn auth_body(&self) -> Result<Vec<u8>, KbsError> {
        let req = Request {
            version: KBS_PROTOCOL_VERSION.to_string(),
            tee: self.evidence.tee(),
            extra_params: json!({}),
        };
        serde_json::to_vec(&req).map_err(|e| KbsError::Decode(e.to_string()))
    }

    /// Parse the leg-1 `Challenge`; stores the nonce for the attest leg.
    pub fn set_challenge(&mut self, body: &[u8]) -> Result<(), KbsError> {
        let challenge: Challenge = serde_json::from_slice(body)
            .map_err(|e| KbsError::Decode(format!("challenge: {e}")))?;
        self.nonce = Some(challenge.nonce);
        Ok(())
    }

    /// Leg 2 body — `POST /kbs/v0/attest`. Binds the TEE pubkey in
    /// `runtime_data` and the SHA-384(report-data) in the evidence.
    pub fn attest_body(&self) -> Result<Vec<u8>, KbsError> {
        let nonce = self
            .nonce
            .clone()
            .ok_or_else(|| KbsError::Protocol("attest before challenge".to_string()))?;
        let tee_pubkey = self.keypair.to_tee_pubkey();
        let report_data = report_data(&tee_pubkey, &nonce, "")?;
        let primary_evidence = self.evidence.primary_evidence(&report_data);

        let attestation = Attestation {
            init_data: None,
            runtime_data: RuntimeData {
                nonce,
                tee_pubkey,
            },
            tee_evidence: CompositeEvidence {
                primary_evidence,
                additional_evidence: String::new(),
            },
        };
        serde_json::to_vec(&attestation).map_err(|e| KbsError::Decode(e.to_string()))
    }

    /// Parse a leg-3 resource `Response` (JWE) and return the plaintext —
    /// the released key bytes.
    pub fn unwrap_resource(&self, body: &[u8]) -> Result<Vec<u8>, KbsError> {
        let response: Response = serde_json::from_slice(body)
            .map_err(|e| KbsError::Decode(format!("response: {e}")))?;
        self.keypair.decrypt_response(&response)
    }
}

/// The `report_data` the AS will expect: `SHA384` over the same JSON object
/// the KBS rebuilds from the attestation — `{ tee-pubkey, nonce,
/// additional-evidence }`. Computed with the same `serde_json` the KBS uses.
fn report_data(
    tee_pubkey: &TeePubKey,
    nonce: &str,
    additional_evidence: &str,
) -> Result<Vec<u8>, KbsError> {
    let runtime_data = json!({
        "tee-pubkey": tee_pubkey,
        "nonce": nonce,
        "additional-evidence": additional_evidence,
    });
    let bytes = serde_json::to_vec(&runtime_data).map_err(|e| KbsError::Decode(e.to_string()))?;
    Ok(Sha384::digest(&bytes).to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_and_attest_bodies_are_wellformed() {
        let mut s = RcarSession::new(TeeKeyPair::generate().unwrap(), SampleEvidence);
        let auth: Value = serde_json::from_slice(&s.auth_body().unwrap()).unwrap();
        assert_eq!(auth["version"], "0.4.0");
        assert_eq!(auth["tee"], "sample");

        // Feed a challenge, then the attest body must carry the bound
        // tee-pubkey + sample evidence whose report_data is 48-byte SHA384.
        s.set_challenge(br#"{"nonce":"AAAA","extra-params":""}"#)
            .unwrap();
        let att: Value = serde_json::from_slice(&s.attest_body().unwrap()).unwrap();
        assert_eq!(att["runtime-data"]["nonce"], "AAAA");
        assert_eq!(att["runtime-data"]["tee-pubkey"]["kty"], "RSA");
        let rd_b64 = att["tee-evidence"]["primary_evidence"]["report_data"]
            .as_str()
            .unwrap();
        assert_eq!(Base64::decode_vec(rd_b64).unwrap().len(), 48);
    }
}
