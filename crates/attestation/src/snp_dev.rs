//! Dev SEV-SNP backend.
//!
//! Produces a **real `sev` `AttestationReport`** — the exact struct prod
//! hardware emits, with genuine `report_data`, `measurement`, `guest_svn`,
//! `author_key_digest` fields — so policy/KBS code pins the same fields it
//! will in production. The only difference from prod is the **trust root**:
//! here the report is signed by a software test key instead of an AMD VCEK
//! (whose chain roots in AMD's CA). A verifier (our KBS / an AS) is
//! configured to trust this test key in dev and the AMD root in prod.
//!
//! This is the dev half of the dev/prod-swappable `Attestor`: same trait,
//! same `report_data` binding, same caller code; only the backend (and its
//! trust anchor) changes. The prod `sev-snp` backend reads `/dev/sev-guest`
//! and verifies the AMD VCEK→ASK→ARK chain.
//!
//! IMPORTANT: never accept a `Quote { format: "snp-dev" }` in production —
//! `format` is the discriminator.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, SECRET_KEY_LENGTH};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sev::firmware::guest::AttestationReport;

use crate::{AttestationError, Attestor, Quote, ReportData};

const SNP_DEV_FORMAT: &str = "snp-dev";
/// SNP report version (spec value 2).
const REPORT_VERSION: u32 = 2;

/// Dev SEV-SNP attestor: real report format, test-key signature.
pub struct SnpDevAttestor {
    signing_key: SigningKey,
    measurement: [u8; 48],
}

impl SnpDevAttestor {
    /// Random test key, zero measurement. For unit tests.
    pub fn new_random() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
            measurement: [0u8; 48],
        }
    }

    /// Fixed test key seed + pinned measurement. A CI step generates the
    /// seed once and provisions the public half to the verifying side.
    pub fn from_seed(seed: [u8; SECRET_KEY_LENGTH], measurement: [u8; 48]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
            measurement,
        }
    }

    /// Public (verifying) key — the dev "root" a verifier pins.
    pub fn verifying_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Pinned measurement (hex).
    pub fn measurement_hex(&self) -> String {
        hex::encode(self.measurement)
    }
}

/// Dev quote envelope: the real report plus the test-key signature over it.
/// (Prod carries the signature inside `report.signature` as an AMD VCEK
/// ECDSA; dev keeps that field zero and signs the serialized report here.)
#[derive(Serialize, Deserialize)]
struct SnpDevEnvelope {
    report: AttestationReport,
    signature_hex: String,
}

/// Canonical bytes signed/verified: the JSON of the report (its
/// `signature` field is left at default/zero, so serialize↔deserialize
/// round-trips to identical bytes).
fn canonical(report: &AttestationReport) -> Result<Vec<u8>, AttestationError> {
    serde_json::to_vec(report)
        .map_err(|e| AttestationError::Backend(format!("serialize snp report: {e}")))
}

impl Attestor for SnpDevAttestor {
    fn mint(&self, data: &ReportData) -> Result<Quote, AttestationError> {
        let mut report = AttestationReport::default();
        report.version = REPORT_VERSION;
        report.measurement = self.measurement;
        // The 32-byte binding sits in the low half of the 64-byte slot,
        // exactly as the engine will place it on real hardware.
        report.report_data[..32].copy_from_slice(&data.hash());

        let signature: Signature = self.signing_key.sign(&canonical(&report)?);
        let envelope = SnpDevEnvelope {
            report,
            signature_hex: hex::encode(signature.to_bytes()),
        };
        let quote_blob = serde_json::to_vec(&envelope)
            .map_err(|e| AttestationError::Backend(format!("serialize snp envelope: {e}")))?;

        Ok(Quote {
            format: SNP_DEV_FORMAT.to_string(),
            quote_blob,
            measurement: self.measurement_hex(),
        })
    }

    fn verify(&self, quote: &Quote, expected: &ReportData) -> Result<(), AttestationError> {
        if quote.format != SNP_DEV_FORMAT {
            return Err(AttestationError::UnsupportedFormat(quote.format.clone()));
        }
        let envelope: SnpDevEnvelope = serde_json::from_slice(&quote.quote_blob)
            .map_err(|e| AttestationError::InvalidQuote(format!("json: {e}")))?;

        if envelope.report.measurement != self.measurement {
            return Err(AttestationError::MeasurementMismatch);
        }
        if envelope.report.report_data[..32] != expected.hash() {
            return Err(AttestationError::BindingMismatch);
        }

        let sig_bytes = hex::decode(&envelope.signature_hex)
            .map_err(|e| AttestationError::InvalidQuote(format!("sig hex: {e}")))?;
        let sig_array: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| AttestationError::InvalidQuote("signature length".into()))?;
        let signature = Signature::from_bytes(&sig_array);

        let verifying_key: VerifyingKey = self.signing_key.verifying_key();
        verifying_key
            .verify(&canonical(&envelope.report)?, &signature)
            .map_err(|_| AttestationError::BadSignature)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attestor() -> SnpDevAttestor {
        SnpDevAttestor::from_seed([3u8; SECRET_KEY_LENGTH], [0xab; 48])
    }

    fn data() -> ReportData {
        ReportData::for_kbs(vec![9u8; 32])
    }

    #[test]
    fn round_trip_real_report_fields() {
        let a = attestor();
        let quote = a.mint(&data()).unwrap();
        assert_eq!(quote.format, "snp-dev");
        // The quote carries a genuine sev AttestationReport.
        let env: SnpDevEnvelope = serde_json::from_slice(&quote.quote_blob).unwrap();
        assert_eq!(env.report.version, REPORT_VERSION);
        assert_eq!(env.report.measurement, [0xab; 48]);
        assert_eq!(&env.report.report_data[..32], &data().hash());
        a.verify(&quote, &data()).unwrap();
    }

    #[test]
    fn wrong_binding_rejected() {
        let a = attestor();
        let quote = a.mint(&data()).unwrap();
        let other = ReportData::for_kbs(vec![1u8; 32]);
        assert!(matches!(
            a.verify(&quote, &other),
            Err(AttestationError::BindingMismatch)
        ));
    }

    #[test]
    fn foreign_key_rejected() {
        let quote = attestor().mint(&data()).unwrap();
        // Different test root must not verify.
        let foreign = SnpDevAttestor::from_seed([7u8; SECRET_KEY_LENGTH], [0xab; 48]);
        assert!(matches!(
            foreign.verify(&quote, &data()),
            Err(AttestationError::BadSignature)
        ));
    }

    #[test]
    fn wrong_measurement_rejected() {
        let quote = attestor().mint(&data()).unwrap();
        let other = SnpDevAttestor::from_seed([3u8; SECRET_KEY_LENGTH], [0x00; 48]);
        assert!(matches!(
            other.verify(&quote, &data()),
            Err(AttestationError::MeasurementMismatch)
        ));
    }
}
