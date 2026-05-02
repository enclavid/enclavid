use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, post};
use secrecy::ExposeSecret;

use crate::state::AppState;

use super::auth::CallerKey;
use super::shared::{
    build_resources, fetch_metadata, lookup_policy, parse_args, TEE_KEY,
};
use super::views::{progress_from, SessionProgress};

/// Route factory: bare `post(handler)` MethodRouter. Auth attached at
/// router level via `.layer(auth())` — see `applicant::router`.
pub(super) fn post_connect() -> MethodRouter<Arc<AppState>> {
    post(connect)
}

/// POST /session/:id/connect — applicant binds a bearer key to the
/// session and gets the current progress. Idempotent: first call
/// initializes state and runs the policy from scratch; subsequent
/// calls with the same key replay existing state and return the same
/// suspension point (cheap — replay path skips host calls). A
/// different key on an already-claimed session is rejected at the
/// auth layer with 403; recovery requires `DELETE /session/:id/state`
/// first (no auth, by design — see reset.rs).
async fn connect(
    Path(session_id): Path<String>,
    State(state): State<Arc<AppState>>,
    CallerKey(applicant_key): CallerKey,
) -> Result<Json<SessionProgress>, StatusCode> {
    let metadata = fetch_metadata(&state, &session_id).await?;
    let args = parse_args(&metadata)?;

    // Existence claim is host-controlled; once decrypt is in place,
    // content of Some is integrity-verified by AEAD. We accept None at
    // face value — a lying host hiding a real blob just makes us
    // replay from default state (disruptive UX, not a leak).
    let session_state = state
        .state_store
        .get(&session_id, applicant_key.expose_secret(), TEE_KEY)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .trust_unchecked()
        .unwrap_or_default();

    let resources = build_resources(&state, &session_id, &metadata);
    let policy = lookup_policy(&state, &session_id).await?;

    let (status, session_state) = state
        .runner
        .run(&policy, session_state, args, resources)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // We accept "Ok" as the host's claim that the encrypted blob was
    // persisted. Not verifiable: a host that silently drops writes
    // causes the next /connect to replay from default state —
    // disruptive but not a confidentiality break (no plaintext leaks).
    state
        .state_store
        .put(&session_id, &session_state, applicant_key.expose_secret(), TEE_KEY)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .trust_unchecked();

    Ok(Json(progress_from(status)))
}
