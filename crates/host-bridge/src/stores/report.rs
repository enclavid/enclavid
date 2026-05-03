use std::sync::Arc;

use enclavid_untrusted::{Exposed, Untrusted};
use prost::Message;
use tonic::transport::Channel;

use crate::error::BridgeError;
use crate::proto::report::Report;
use crate::proto::report_store::report_store_client::ReportStoreClient;
use crate::proto::report_store::AppendRequest;
use crate::transport::GrpcChannel;

/// Append-only store for anonymous applicant reports against policies.
/// Entries keyed by `policy_digest` so the platform aggregates reports
/// per policy. No session_id is included in the payload — reports are
/// unlinkable to specific applicants by construction at the storage
/// layer.
#[derive(Clone)]
pub struct ReportStore {
    client: ReportStoreClient<Channel>,
    /// Recipient pubkey for sealing reports before exposure to the
    /// host (age recipient: hybrid X25519 + AES). The host stores
    /// opaque ciphertext; only the platform can open these.
    /// Phase A: caller injects (placeholder).
    /// Phase B: derived from attestation / KMS-bound material.
    /// `Arc` so cloning the store stays cheap.
    platform_pubkey: Arc<Vec<u8>>,
}

impl ReportStore {
    pub fn new(channel: GrpcChannel, platform_pubkey: Vec<u8>) -> Self {
        Self {
            client: ReportStoreClient::new(channel),
            platform_pubkey: Arc::new(platform_pubkey),
        }
    }

    /// Caller passes a typed `Report`; the bridge encodes, seals
    /// under `platform_pubkey`, and releases the ciphertext to the
    /// host. Encoding inside the store (vs. caller-side
    /// `encode_to_vec`) prevents passing arbitrary or wrong-type
    /// bytes, mirroring `SessionStore`'s typed `SetMetadata` /
    /// `SetState` markers.
    pub async fn append(
        &self,
        policy_digest: &str,
        report: &Report,
    ) -> Result<Untrusted<u64>, BridgeError> {
        let plaintext = report.encode_to_vec();
        // TODO encrypt: hybrid age-encrypt `plaintext` to
        // `self.platform_pubkey` BEFORE wrapping. This is the seal step
        // that produces the `Exposed<Vec<u8>>` — same shape as
        // WriteField::build_op for SessionStore ops.
        //
        // Protection model (after the seal lands): host sees opaque
        // ciphertext only the platform operator can open; the
        // recipient pubkey is bound to a long-lived platform identity
        // distinct from any per-session material. Entries are
        // partitioned by `policy_digest` and carry no session_id, so
        // the host cannot link an appended report back to a specific
        // applicant session — per-policy aggregation is the only
        // observation available.
        //
        // What the platform operator sees if they decrypt: only the
        // bounded `Report` schema —
        //   - `policy_id` / `policy_hash` (public policy identifiers)
        //   - `client_id` (workspace id of the platform consumer)
        //   - `reason` (fixed enum: requesting-too-much / unexpected
        //     fields / suspicious-values / other)
        //   - `field_labels` (labels from the policy's own display
        //     schema — already public to the applicant in the consent
        //     prompt)
        //   - `timestamp`
        //   - `details`: free-form text the applicant typed in the
        //     report form. Length-bounded; intended as complaint
        //     context, not as a side-channel for applicant data.
        // Notably absent: biometrics, document images, decrypted
        // identity fields, or any cross-session correlator. None of
        // the verification pipeline's applicant-side data lands in
        // a Report by construction.
        let _ = &self.platform_pubkey;
        let sealed: Exposed<Vec<u8>> = Exposed::expose(plaintext);

        let response = self
            .client
            .clone()
            .append(AppendRequest {
                policy_digest: policy_digest.to_string(),
                data: sealed.release(),
            })
            .await?;
        Ok(Untrusted::new(response.into_inner().length))
    }
}
