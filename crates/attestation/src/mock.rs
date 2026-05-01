//! Software-mock backend for the attestation crate.
//!
//! Same wire shape as real SEV-SNP — TEE produces a `Quote`, client
//! verifies it — but signed with a static dev Ed25519 keypair instead of
//! AMD-SP. Used until we have hardware in the lab.
//!
//! The dev keypair is shared between mint and verify side via constructor:
//! a single `MockAttestor` instance holds it. In dev deployments we run
//! ONE instance both in TEE-side (for mint) and in the client-side SDK
//! example (for verify), keys provisioned out of band. Real production
//! flow does not use this — clients pin AMD root + measurement, no shared
//! dev key needed.
//!
//! IMPORTANT: never accept a `Quote { format: "mock-ed25519" }` in
//! production code paths. The `format` field is the discriminator.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, SECRET_KEY_LENGTH};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::{AttestationError, Attestor, Quote, ReportData};

const MOCK_FORMAT: &str = "mock-ed25519";

/// In-memory dev attestor. Generates a fresh keypair on each construction;
/// pair the verifier with the same instance (or with the public key it
/// produces) for round-trip tests. Real deployments will marshal the
/// public side out for client-side SDK consumption.
pub struct MockAttestor {
    signing_key: SigningKey,
    measurement: String,
}

impl MockAttestor {
    /// Random keypair, zero measurement. Suitable for unit tests.
    pub fn new_random() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
            measurement: "0".repeat(64),
        }
    }

    /// Construct from a fixed seed and pinned measurement string. Enables
    /// reproducible builds where a CI step generates the seed once and
    /// bakes both private (for the TEE) and public (for the verifying SDK)
    /// halves into the right places.
    pub fn from_seed(seed: [u8; SECRET_KEY_LENGTH], measurement: impl Into<String>) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
            measurement: measurement.into(),
        }
    }

    /// Public key bytes, for shipping to the verifying side.
    pub fn verifying_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn measurement(&self) -> &str {
        &self.measurement
    }
}

#[derive(Serialize, Deserialize)]
struct MockSignedReport {
    /// Hex of `ReportData::hash()`.
    report_data_hex: String,
    /// Hex of measurement, copied here so verify can check it without
    /// re-reading outer envelope.
    measurement: String,
    /// Hex-encoded Ed25519 signature over JSON without this field.
    signature_hex: String,
}

impl Attestor for MockAttestor {
    fn mint(&self, data: &ReportData) -> Result<Quote, AttestationError> {
        let report_hash = data.hash();

        // Sign the canonical concatenation of (measurement || report_hash)
        // — same logical input that a real SEV-SNP quote would carry.
        let mut message = Vec::with_capacity(self.measurement.len() + report_hash.len());
        message.extend_from_slice(self.measurement.as_bytes());
        message.extend_from_slice(&report_hash);
        let signature: Signature = self.signing_key.sign(&message);

        let payload = MockSignedReport {
            report_data_hex: hex::encode(report_hash),
            measurement: self.measurement.clone(),
            signature_hex: hex::encode(signature.to_bytes()),
        };
        let quote_blob = serde_json::to_vec(&payload)
            .map_err(|e| AttestationError::Backend(format!("serialize mock report: {e}")))?;

        Ok(Quote {
            format: MOCK_FORMAT.to_string(),
            quote_blob,
            measurement: self.measurement.clone(),
        })
    }

    fn verify(&self, quote: &Quote, expected: &ReportData) -> Result<(), AttestationError> {
        if quote.format != MOCK_FORMAT {
            return Err(AttestationError::UnsupportedFormat(quote.format.clone()));
        }

        let payload: MockSignedReport = serde_json::from_slice(&quote.quote_blob)
            .map_err(|e| AttestationError::InvalidQuote(format!("json: {e}")))?;

        if payload.measurement != self.measurement {
            return Err(AttestationError::MeasurementMismatch);
        }

        let expected_hash = expected.hash();
        if payload.report_data_hex != hex::encode(expected_hash) {
            return Err(AttestationError::BindingMismatch);
        }

        let sig_bytes = hex::decode(&payload.signature_hex)
            .map_err(|e| AttestationError::InvalidQuote(format!("sig hex: {e}")))?;
        let sig_array: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| AttestationError::InvalidQuote("signature length".into()))?;
        let signature = Signature::from_bytes(&sig_array);

        let mut message = Vec::with_capacity(self.measurement.len() + expected_hash.len());
        message.extend_from_slice(self.measurement.as_bytes());
        message.extend_from_slice(&expected_hash);

        let verifying_key: VerifyingKey = self.signing_key.verifying_key();
        verifying_key
            .verify(&message, &signature)
            .map_err(|_| AttestationError::BadSignature)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data() -> ReportData {
        ReportData {
            session_id: "ses_01HF7K".to_string(),
            ephemeral_pubkey: vec![0xAA; 32],
            policy_digest: "sha256:7e93fba".to_string(),
        }
    }

    #[test]
    fn roundtrip() {
        let attestor = MockAttestor::new_random();
        let quote = attestor.mint(&sample_data()).unwrap();
        attestor.verify(&quote, &sample_data()).unwrap();
    }

    #[test]
    fn binding_mismatch_rejected() {
        let attestor = MockAttestor::new_random();
        let quote = attestor.mint(&sample_data()).unwrap();
        let mut tampered = sample_data();
        tampered.session_id = "ses_OTHER".to_string();
        let err = attestor.verify(&quote, &tampered).unwrap_err();
        assert!(matches!(err, AttestationError::BindingMismatch));
    }

    #[test]
    fn signature_tamper_rejected() {
        let attestor = MockAttestor::new_random();
        let mut quote = attestor.mint(&sample_data()).unwrap();
        // Flip a byte inside the signed payload
        let pos = quote.quote_blob.len() / 2;
        quote.quote_blob[pos] ^= 0x01;
        let err = attestor.verify(&quote, &sample_data()).unwrap_err();
        // Either parse fails or the binding hash differs or signature breaks
        assert!(matches!(
            err,
            AttestationError::InvalidQuote(_)
                | AttestationError::BindingMismatch
                | AttestationError::BadSignature
                | AttestationError::MeasurementMismatch
        ));
    }

    #[test]
    fn cross_attestor_rejected() {
        // Two attestors with the same pinned measurement (so the
        // measurement check passes) but different signing keys — verify
        // must fall through to signature failure.
        let a = MockAttestor::from_seed([1u8; SECRET_KEY_LENGTH], "0".repeat(64));
        let b = MockAttestor::from_seed([2u8; SECRET_KEY_LENGTH], "0".repeat(64));
        let quote_a = a.mint(&sample_data()).unwrap();
        let err = b.verify(&quote_a, &sample_data()).unwrap_err();
        assert!(matches!(err, AttestationError::BadSignature));
    }
}
