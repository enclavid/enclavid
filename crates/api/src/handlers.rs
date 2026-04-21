use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Json;
use prost::Message;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};

use enclavid_engine::policy::{Decision, RunResources};
use enclavid_engine::{EvalArgs, RunStatus, SessionState};
use enclavid_session_store::{
    biometric_request, call_event, document_request, suspended, CaptureItem, DisplayField,
    LivenessMode, Passport, Report, ReportReason, SessionMetadata,
};

use crate::auth::BearerKey;
use crate::input::parse_input;
use crate::state::{AppState, ApplicantKey};

// TODO: real TEE key (KMS attestation-bound)
const TEE_KEY: &[u8] = &[0u8; 32];
// TODO: real platform key
const PLATFORM_KEY: &[u8] = &[0u8; 32];

#[derive(Serialize)]
pub struct StatusResponse {
    pub initialized: bool,
    pub completed: bool,
}

#[derive(Deserialize)]
pub struct InitQuery {
    #[serde(default)]
    pub force: bool,
}

/// Response for run-triggering endpoints (`init`, `input`). Internally-tagged
/// enum — the `status` field carries the variant discriminator, other fields
/// carry variant-specific payload.
#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SessionProgress {
    Completed { decision: DecisionView },
    AwaitingInput { request: RequestView },
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionView {
    Approved,
    Rejected,
    RejectedRetryable,
    Review,
}

/// JSON-friendly view of a pending suspension request. Mirrors the proto
/// `suspended::Request` variants but in a shape the frontend can consume
/// without prost decoding.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RequestView {
    Passport,
    IdCard,
    DriversLicense,
    Liveness { mode: LivenessModeView },
    Consent { fields: Vec<DisplayFieldView> },
    VerificationSet { alternatives: Vec<Vec<CaptureItemView>> },
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LivenessModeView {
    SelfieVideo,
    Unknown,
}

#[derive(Serialize)]
pub struct DisplayFieldView {
    pub label: String,
    pub value: String,
}

/// CaptureItem with data fields stripped — only the "ask" shape, for
/// rendering alternatives in verification-set flows.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CaptureItemView {
    Passport,
    IdCard,
    DriversLicense,
    Liveness { mode: LivenessModeView },
}

#[derive(Deserialize)]
pub struct ReportBody {
    pub reason: String,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub field_labels: Option<Vec<String>>,
}

/// GET /session/:id/status — public, no auth
pub async fn get_status(
    Path(session_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<StatusResponse>, StatusCode> {
    state
        .metadata_store
        .get(&session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let initialized = state
        .state_store
        .exists(&session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(StatusResponse {
        initialized,
        completed: false,
    }))
}

/// POST /session/:id/init — claims session with a client key
pub async fn post_init(
    Path(session_id): Path<String>,
    Query(query): Query<InitQuery>,
    State(state): State<Arc<AppState>>,
    BearerKey(applicant_key): BearerKey,
) -> Result<Json<SessionProgress>, StatusCode> {
    let metadata = fetch_metadata(&state, &session_id).await?;
    let args = parse_args(&metadata)?;

    let existing = state
        .state_store
        .get(&session_id, applicant_key.expose_secret(), TEE_KEY)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if existing.is_some() && !query.force {
        return Err(StatusCode::CONFLICT);
    }

    if query.force {
        state
            .state_store
            .delete(&session_id)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        state.applicant_keys.invalidate(&session_id).await;
    }

    let resources = build_resources(&state, &session_id, &metadata);

    let (status, session_state) = state
        .runner
        .run(&state.policy, SessionState::default(), args, resources)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state
        .state_store
        .put(&session_id, &session_state, applicant_key.expose_secret(), TEE_KEY)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state
        .applicant_keys
        .insert(session_id.clone(), Arc::new(applicant_key))
        .await;

    Ok(Json(progress_from(status)))
}

/// POST /session/:id/input — submits media for a suspended session
pub async fn post_input(
    Path(session_id): Path<String>,
    State(state): State<Arc<AppState>>,
    BearerKey(applicant_key): BearerKey,
    body: axum::body::Bytes,
) -> Result<Json<SessionProgress>, StatusCode> {
    verify_claim(&state, &session_id, &applicant_key).await?;

    let metadata = fetch_metadata(&state, &session_id).await?;
    let args = parse_args(&metadata)?;

    let mut session_state = state
        .state_store
        .get(&session_id, applicant_key.expose_secret(), TEE_KEY)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Attach user input to the last Suspended request's typed data field.
    apply_input(&mut session_state, &body)?;

    let resources = build_resources(&state, &session_id, &metadata);

    let (status, session_state) = state
        .runner
        .run(&state.policy, session_state, args, resources)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state
        .state_store
        .put(&session_id, &session_state, applicant_key.expose_secret(), TEE_KEY)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(progress_from(status)))
}

/// POST /session/:id/report — submits an anonymous report against the policy.
/// Authenticated via BearerKey to prove session participation, but session_id
/// is stripped before storage so reports cannot be linked to the user.
pub async fn post_report(
    Path(session_id): Path<String>,
    State(state): State<Arc<AppState>>,
    BearerKey(applicant_key): BearerKey,
    Json(body): Json<ReportBody>,
) -> Result<StatusCode, StatusCode> {
    verify_claim(&state, &session_id, &applicant_key).await?;

    let reason = parse_reason(&body.reason).ok_or(StatusCode::BAD_REQUEST)?;
    let metadata = fetch_metadata(&state, &session_id).await?;

    // TODO: read actual policy_hash from SessionState once persisted
    let policy_hash = Vec::new();
    let report = Report {
        policy_id: metadata.policy_id.clone(),
        client_id: metadata.client_id.clone(),
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
        .append(&metadata.policy_id, report.encode_to_vec(), PLATFORM_KEY)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

async fn fetch_metadata(
    state: &AppState,
    session_id: &str,
) -> Result<SessionMetadata, StatusCode> {
    state
        .metadata_store
        .get(session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)
}

fn parse_args(metadata: &SessionMetadata) -> Result<Vec<(String, EvalArgs)>, StatusCode> {
    parse_input(&metadata.input).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
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

/// Verifies the provided applicant key matches the one that claimed the session.
/// If the cache was evicted or pod restarted, accept and re-populate —
/// state is still decryptable since the applicant holds the key.
async fn verify_claim(
    state: &AppState,
    session_id: &str,
    applicant_key: &ApplicantKey,
) -> Result<(), StatusCode> {
    match state.applicant_keys.get(session_id).await {
        Some(existing) if existing.expose_secret() == applicant_key.expose_secret() => Ok(()),
        Some(_) => Err(StatusCode::FORBIDDEN),
        None => {
            let cloned = applicant_key.expose_secret().clone();
            state
                .applicant_keys
                .insert(
                    session_id.to_string(),
                    Arc::new(SecretBox::new(Box::new(cloned))),
                )
                .await;
            Ok(())
        }
    }
}

/// Build per-run resources from AppState + session metadata.
fn build_resources(
    state: &AppState,
    session_id: &str,
    metadata: &SessionMetadata,
) -> RunResources {
    RunResources {
        disclosure_store: state.disclosure_store.clone(),
        session_id: session_id.to_string(),
        client_pk: metadata.client_public_key.as_bytes().to_vec(),
    }
}

/// Attach user input to the currently-Suspended event's typed data field.
/// MVP parsing: raw body bytes per variant (passport=single image,
/// consent=first byte bool). ID card / drivers license / biometric /
/// verification-set require multipart parsing — not yet implemented.
fn apply_input(session: &mut SessionState, body: &[u8]) -> Result<(), StatusCode> {
    let last = session.events.last_mut().ok_or(StatusCode::CONFLICT)?;
    let Some(call_event::Status::Suspended(sus)) = last.status.as_mut() else {
        return Err(StatusCode::CONFLICT);
    };
    let Some(request) = sus.request.as_mut() else {
        return Err(StatusCode::CONFLICT);
    };

    match request {
        suspended::Request::Document(doc) => match doc.kind.as_mut() {
            Some(document_request::Kind::Passport(_)) => {
                doc.kind = Some(document_request::Kind::Passport(Passport {
                    image: Some(body.to_vec()),
                }));
            }
            _ => return Err(StatusCode::NOT_IMPLEMENTED),
        },
        suspended::Request::Consent(c) => {
            c.accepted = Some(body.first().map(|&b| b != 0).unwrap_or(false));
        }
        _ => return Err(StatusCode::NOT_IMPLEMENTED),
    }
    Ok(())
}

fn progress_from(status: RunStatus) -> SessionProgress {
    match status {
        RunStatus::Completed(decision) => SessionProgress::Completed {
            decision: decision_view(decision),
        },
        RunStatus::Suspended(req) => SessionProgress::AwaitingInput {
            request: request_view(&req),
        },
    }
}

fn decision_view(d: Decision) -> DecisionView {
    match d {
        Decision::Approved => DecisionView::Approved,
        Decision::Rejected => DecisionView::Rejected,
        Decision::RejectedRetryable => DecisionView::RejectedRetryable,
        Decision::Review => DecisionView::Review,
    }
}

fn request_view(req: &suspended::Request) -> RequestView {
    match req {
        suspended::Request::Document(doc) => match doc.kind.as_ref() {
            Some(document_request::Kind::Passport(_)) => RequestView::Passport,
            Some(document_request::Kind::IdCard(_)) => RequestView::IdCard,
            Some(document_request::Kind::DriversLicense(_)) => RequestView::DriversLicense,
            None => RequestView::Passport, // unreachable under normal flow
        },
        suspended::Request::Biometric(bio) => match bio.kind.as_ref() {
            Some(biometric_request::Kind::Liveness(l)) => RequestView::Liveness {
                mode: liveness_mode_view(l.mode),
            },
            None => RequestView::Liveness { mode: LivenessModeView::Unknown },
        },
        suspended::Request::Consent(c) => RequestView::Consent {
            fields: c.fields.iter().map(display_field_view).collect(),
        },
        suspended::Request::VerificationSet(vs) => RequestView::VerificationSet {
            alternatives: vs
                .alternatives
                .iter()
                .map(|g| g.items.iter().map(capture_item_view).collect())
                .collect(),
        },
    }
}

fn liveness_mode_view(mode: i32) -> LivenessModeView {
    if mode == LivenessMode::SelfieVideo as i32 {
        LivenessModeView::SelfieVideo
    } else {
        LivenessModeView::Unknown
    }
}

fn display_field_view(f: &DisplayField) -> DisplayFieldView {
    DisplayFieldView {
        label: f.label.clone(),
        value: f.value.clone(),
    }
}

fn capture_item_view(item: &CaptureItem) -> CaptureItemView {
    use enclavid_session_store::capture_item;
    match item.item.as_ref() {
        Some(capture_item::Item::Passport(_)) => CaptureItemView::Passport,
        Some(capture_item::Item::IdCard(_)) => CaptureItemView::IdCard,
        Some(capture_item::Item::DriversLicense(_)) => CaptureItemView::DriversLicense,
        Some(capture_item::Item::Liveness(l)) => CaptureItemView::Liveness {
            mode: liveness_mode_view(l.mode),
        },
        None => CaptureItemView::Passport, // unreachable under normal flow
    }
}
