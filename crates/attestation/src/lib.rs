//! Attestation: produces and verifies hardware-signed quotes that bind
//! TEE-side ephemeral pubkeys to session metadata.
//!
//! The protocol-level shape is fixed and matches `architecture.md ::
//! Client-Facing Session Creation`:
//!
//! ```text
//! report_data = sha256(session_id || ephemeral_pubkey || policy_digest)
//! quote       = Sign(measurement || report_data)
//! ```
//!
//! The signing/verification backend is pluggable. Real production uses
//! AMD SEV-SNP (VCEK→ARK→AMD root chain). The `mock` feature swaps in a
//! software Ed25519 signer for dev / CI / pre-hardware milestones — same
//! shape over the wire, same call sites in callers, only the trust value
//! of a passing `verify()` differs.
//!
//! Callers MUST treat any quote whose `format` is not `sev-snp` as
//! development-only and refuse it in production builds. See `Quote::format`.

mod error;

pub use error::AttestationError;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Wire format for an attestation quote returned to clients.
///
/// Stable shape across backends — clients verify by computing their own
/// `report_data` from the session response and asking the matching backend
/// (mock vs sev-snp) to validate `quote_blob` carries that value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quote {
    /// Identifies the signing backend. Production clients refuse anything
    /// other than `"sev-snp"`. Currently `"mock-ed25519"` for dev.
    pub format: String,
    /// Backend-defined signed payload. For mock: JSON-encoded
    /// `MockSignedReport` plus a 64-byte Ed25519 signature, base64 wrapped
    /// at the outer envelope. For sev-snp: raw quote bytes (later).
    pub quote_blob: Vec<u8>,
    /// Hex-encoded sha256 of TEE measurement / launch digest. Clients pin
    /// this in their config: only the platform releases they trust.
    /// In mock mode, set from a CI-provided value or zeroed.
    pub measurement: String,
}

/// Bound fields a quote attests to. Matches the protocol's `report_data`
/// inputs verbatim — any change here is a wire-protocol change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportData {
    pub session_id: String,
    pub ephemeral_pubkey: Vec<u8>,
    pub policy_digest: String,
}

impl ReportData {
    /// Canonical 32-byte hash that lands in the SEV-SNP `report_data` slot.
    /// Same computation runs in mint and verify; any divergence breaks
    /// verification.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.session_id.as_bytes());
        h.update(b"\x00");
        h.update(&self.ephemeral_pubkey);
        h.update(b"\x00");
        h.update(self.policy_digest.as_bytes());
        h.finalize().into()
    }
}

/// Backend trait — all signing/verification details live behind this.
pub trait Attestor: Send + Sync {
    /// Mint a quote binding `data`. Backend handles measurement injection,
    /// signing-key access, and quote formatting.
    fn mint(&self, data: &ReportData) -> Result<Quote, AttestationError>;

    /// Verify `quote` carries `expected` as its bound report_data and was
    /// signed by a key the backend trusts.
    ///
    /// On success returns `()`; on failure returns a typed error indicating
    /// which check failed (signature, binding mismatch, format).
    fn verify(&self, quote: &Quote, expected: &ReportData) -> Result<(), AttestationError>;
}

#[cfg(feature = "mock")]
mod mock;
#[cfg(feature = "mock")]
pub use mock::MockAttestor;
