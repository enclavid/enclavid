//! Attestation: produces and verifies hardware-signed quotes that bind
//! session metadata to a specific TEE measurement.
//!
//! The protocol-level shape is fixed:
//!
//! ```text
//! report_data = sha256(session_id || policy_digest)
//! quote       = Sign(measurement || report_data)
//! ```
//!
//! Per-instance binding (TLS cert hash → TEE measurement) is a separate
//! attestation produced at TEE boot and verified by the client during
//! TLS handshake — that step is what authenticates the recipient TEE
//! identity. Per-session quotes returned in `POST /sessions` only
//! bind session-specific data (session_id, policy_digest) to the
//! same measurement.
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
    pub policy_digest: String,
    /// Optional extra binding for the artifact-key (KBS) leg: the TEE's
    /// ephemeral public key. When `Some`, it is folded into `hash()` so a
    /// KBS can confirm the report came from the same enclave that owns the
    /// key it wraps the secret to. `None` for ordinary session quotes —
    /// the hash is then bit-identical to the original two-field form.
    pub kbs_binding: Option<Vec<u8>>,
    /// Optional binding for the intra-fleet RA-TLS leg: the DER
    /// `SubjectPublicKeyInfo` of the ephemeral TLS cert the peer minted. When
    /// `Some`, it is folded into `hash()` under its OWN domain tag, so the quote
    /// authenticates "this measurement owns this TLS key" during the handshake.
    /// `None` for session / KBS quotes (their hashes stay bit-identical).
    pub ratls_binding: Option<Vec<u8>>,
}

impl ReportData {
    /// Report data for an ordinary per-session quote (no KBS binding).
    pub fn session(session_id: String, policy_digest: String) -> Self {
        Self {
            session_id,
            policy_digest,
            kbs_binding: None,
            ratls_binding: None,
        }
    }

    /// Report data for an artifact-key (KBS) request: binds the TEE's
    /// ephemeral public key so the KBS releases the secret only to this
    /// enclave's key. `session_id`/`policy_digest` are empty — the KBS
    /// gates on measurement + the ephemeral key, not session identity, so
    /// it can recompute this from the request without enclavid internals.
    pub fn for_kbs(ephemeral_pubkey: Vec<u8>) -> Self {
        Self {
            session_id: String::new(),
            policy_digest: String::new(),
            kbs_binding: Some(ephemeral_pubkey),
            ratls_binding: None,
        }
    }

    /// Report data for an intra-fleet RA-TLS cert: binds the DER
    /// `SubjectPublicKeyInfo` of the ephemeral TLS cert so the peer's quote
    /// authenticates the TLS key it presents during the handshake. `session_id`/
    /// `policy_digest` are empty — RA-TLS gates on measurement + the TLS key, not
    /// session identity — so both ends recompute this from the cert alone.
    pub fn for_ratls(spki_der: Vec<u8>) -> Self {
        Self {
            session_id: String::new(),
            policy_digest: String::new(),
            kbs_binding: None,
            ratls_binding: Some(spki_der),
        }
    }

    /// Canonical 32-byte hash that lands in the SEV-SNP `report_data` slot.
    /// Same computation runs in mint and verify; any divergence breaks
    /// verification.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.session_id.as_bytes());
        h.update(b"\x00");
        h.update(self.policy_digest.as_bytes());
        if let Some(binding) = &self.kbs_binding {
            h.update(b"\x00");
            h.update(binding);
        }
        if let Some(spki) = &self.ratls_binding {
            // OWN domain tag: a RA-TLS cert binding must never collide with a
            // session or KBS quote (cross-protocol confusion defence).
            h.update(b"\x00ratls-spki\x00");
            h.update(spki);
        }
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

#[cfg(feature = "snp-dev")]
mod snp_dev;
#[cfg(feature = "snp-dev")]
pub use snp_dev::SnpDevAttestor;
