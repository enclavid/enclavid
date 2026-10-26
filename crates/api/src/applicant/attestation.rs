use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, get};
use base64ct::{Base64, Encoding};
use serde::Serialize;

use enclavid_boundary::{AuthZ, Replay, reason};
use storage_client::Metadata;

use crate::state::AppState;

/// The session's quote, as `POST /sessions` answered its consumer with it.
#[derive(Serialize)]
pub struct AttestationResponse {
    /// Which backend minted it — `sev-snp` on hardware.
    pub format: String,
    /// The signed payload, base64-standard: for `sev-snp`, a CBOR envelope of
    /// the firmware's report and the AMD certificates that endorse it.
    pub quote: String,
}

/// Route factory. Public (no auth layer) — see `applicant::router`.
pub(super) fn get_attestation() -> MethodRouter<Arc<AppState>> {
    get(attestation)
}

/// GET /api/v1/sessions/{id}/attestation — public, no auth.
///
/// The page asks for it as it opens, before the applicant has a key, and checks
/// it itself: up to AMD's root, for the session id in its own address, and for
/// the build that address names. Served as it was minted at the creation, not
/// minted per request, whose rate a caller would choose.
async fn attestation(
    Path(session_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<AttestationResponse>, StatusCode> {
    let ((metadata_opt,), _version) = state
        .session_store
        .read(&session_id, (Metadata,))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let metadata = metadata_opt
        .trust(reason!(
            AuthZ::NoPrincipal,
            r#"
Public like /status: the page asks before the applicant holds a key. The
quote binds only the session id, which the asker already holds, to the
measurement and the part, which are no secret.
        "#
        ))
        .trust(reason!(
            Replay::Harmless,
            r#"
The quote is written once, with the creation, and never changes: an
older snapshot holds the same one.
        "#
        ))
        .into_inner()
        .ok_or(StatusCode::NOT_FOUND)?;

    let quote = metadata.quote.ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(AttestationResponse {
        format: quote.format,
        quote: Base64::encode_string(&quote.blob),
    }))
}
