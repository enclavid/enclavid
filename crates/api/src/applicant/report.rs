use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, post};
use serde::Deserialize;

use enclavid_host_bridge::{Report, ReportReason};

use crate::state::AppState;

use super::auth::CallerKey;
use super::shared::fetch_metadata;

#[derive(Deserialize)]
pub struct ReportBody {
    pub reason: String,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub field_labels: Option<Vec<String>>,
}

/// Route factory. Auth attached at router level via
/// `.layer(auth(AuthMode::Verify))` — see `applicant::router`.
pub(super) fn post_report() -> MethodRouter<Arc<AppState>> {
    post(report)
}

/// POST /session/:id/report — submits an anonymous report against the
/// policy. Authenticated via the bearer-key auth layer to prove session
/// participation, but `session_id` is stripped before storage so reports
/// cannot be linked back to the applicant.
async fn report(
    Path(session_id): Path<String>,
    State(state): State<Arc<AppState>>,
    // Extracted to enforce that the auth layer ran. The key value
    // itself is unused; participation proof is the only thing we need.
    _caller: CallerKey,
    Json(body): Json<ReportBody>,
) -> Result<StatusCode, StatusCode> {
    let reason = parse_reason(&body.reason).ok_or(StatusCode::BAD_REQUEST)?;
    let metadata = fetch_metadata(&state, &session_id).await?;

    // TODO: read actual policy_hash from SessionState once persisted.
    let policy_hash = Vec::new();
    // Reports are anonymous and partitioned by policy. We use
    // `policy_digest` (immutable) as the partition key so audit-log
    // readers see the exact bytes that ran, not a tag that may have
    // been rotated.
    let report = Report {
        policy_id: metadata.policy_digest.clone(),
        client_id: metadata.workspace_id.clone(),
        policy_hash,
        reason: reason.into(),
        details: body.details.unwrap_or_default(),
        field_labels: body.field_labels.unwrap_or_default(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    };

    // Accept "Ok" as the host's claim of append. A lying host that
    // silently drops reports would suppress audit signal — operational
    // concern (alert on dropped reports via separate health check),
    // not a confidentiality break. Sealing under platform pubkey
    // happens inside `ReportStore::append`.
    state
        .report_store
        .append(&metadata.policy_digest, &report)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .trust_unchecked();

    Ok(StatusCode::NO_CONTENT)
}

fn parse_reason(s: &str) -> Option<ReportReason> {
    match s {
        "requesting_too_much_data" => Some(ReportReason::RequestingTooMuchData),
        "unexpected_fields" => Some(ReportReason::UnexpectedFields),
        "suspicious_values" => Some(ReportReason::SuspiciousValues),
        "other" => Some(ReportReason::Other),
        _ => None,
    }
}
