use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use prost::Message;
use serde::Deserialize;

use enclavid_session_store::{Report, ReportReason};

use crate::auth::BearerKey;
use crate::state::AppState;

use super::shared::{fetch_metadata, verify_claim, PLATFORM_KEY};

#[derive(Deserialize)]
pub struct ReportBody {
    pub reason: String,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub field_labels: Option<Vec<String>>,
}

/// POST /session/:id/report — submits an anonymous report against the
/// policy. Authenticated via BearerKey to prove session participation,
/// but `session_id` is stripped before storage so reports cannot be
/// linked back to the applicant.
pub async fn post_report(
    Path(session_id): Path<String>,
    State(state): State<Arc<AppState>>,
    BearerKey(applicant_key): BearerKey,
    Json(body): Json<ReportBody>,
) -> Result<StatusCode, StatusCode> {
    verify_claim(&state, &session_id, &applicant_key).await?;

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

    state
        .report_store
        .append(&metadata.policy_digest, report.encode_to_vec(), PLATFORM_KEY)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

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
