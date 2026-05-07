//! Public attestation manifest endpoint for the applicant frontend.
//!
//! The frontend pulls this on every page load to display the
//! "verified enclave" status: it compares `measurement` against
//! `reference.expected_measurement` and shows a check / cross.
//!
//! Phase A — mocked structurally-valid data:
//! Both `measurement` and `reference.expected_measurement` are
//! hardcoded to the same zero-string so the equality check always
//! succeeds. The fields, types, and HTTP contract match what Phase B
//! will produce, so the frontend can be implemented against this
//! shape now and continue working unchanged once real attestation
//! lands. Phase B will:
//!   * extract `measurement` from a live SP-signed quote minted by
//!     `Attestor::mint` at startup,
//!   * embed `expected_measurement` + `commit_sha` from CI / git at
//!     build time,
//!   * include the quote bytes so the frontend can verify the
//!     AMD-SP cert chain in JS.
//!
//! Public endpoint, no auth — manifest is per-instance, not
//! per-session, so reading it leaks nothing beyond what's already
//! published in source.

use std::sync::Arc;

use axum::response::Json;
use axum::routing::{MethodRouter, get};
use serde::Serialize;

use crate::state::AppState;

#[derive(Serialize)]
pub struct AttestationManifest {
    /// Identifies the attestation backend. `"mock-ed25519"` in dev,
    /// `"amd-sev-snp"` in production. Frontends can refuse non-prod
    /// formats based on deployment posture.
    pub format: String,
    /// Hex sha256 of the TEE measurement / launch digest. Identical
    /// across all sessions on this instance.
    pub measurement: String,
    /// Reference values published alongside the source release —
    /// what the running binary *should* measure to. The frontend
    /// shows a green check if `measurement == reference.expected_measurement`.
    pub reference: AttestationReference,
}

#[derive(Serialize)]
pub struct AttestationReference {
    pub source_url: String,
    pub commit_sha: String,
    pub expected_measurement: String,
}

// Phase A constants. Both measurement values match so the frontend
// always sees a green "verified" pill. Real values flow in via
// `Attestor` + build-time env in Phase B.
const MOCK_MEASUREMENT: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const MOCK_COMMIT_SHA: &str = "phase-a-mock";
const MOCK_SOURCE_URL: &str = "https://github.com/enclavid/enclavid";

/// Route factory. Public — no auth layer attached at the router.
pub(super) fn get_attestation() -> MethodRouter<Arc<AppState>> {
    get(attestation)
}

async fn attestation() -> Json<AttestationManifest> {
    Json(AttestationManifest {
        format: "mock-ed25519".to_string(),
        measurement: MOCK_MEASUREMENT.to_string(),
        reference: AttestationReference {
            source_url: MOCK_SOURCE_URL.to_string(),
            commit_sha: MOCK_COMMIT_SHA.to_string(),
            expected_measurement: MOCK_MEASUREMENT.to_string(),
        },
    })
}
