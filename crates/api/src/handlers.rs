use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Json;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};

use enclavid_engine::RunOutcome;

use crate::auth::BearerKey;
use crate::state::{AppState, ClientKey};

// TODO: real TEE key (KMS attestation-bound)
const TEE_KEY: &[u8] = &[0u8; 32];

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

#[derive(Serialize)]
pub struct OutcomeResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
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
    BearerKey(client_key): BearerKey,
) -> Result<Json<OutcomeResponse>, StatusCode> {
    state
        .metadata_store
        .get(&session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let existing = state
        .state_store
        .get(&session_id, client_key.expose_secret(), TEE_KEY)
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
        state.client_keys.invalidate(&session_id).await;
    }

    let mut session_state = Default::default();
    let outcome = state
        .runner
        .run(&mut session_state)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state
        .state_store
        .put(&session_id, &session_state, client_key.expose_secret(), TEE_KEY)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state
        .client_keys
        .insert(session_id.clone(), Arc::new(client_key))
        .await;

    Ok(Json(outcome_to_response(outcome)))
}

/// POST /session/:id/input — submits media for a suspended session
pub async fn post_input(
    Path(session_id): Path<String>,
    State(state): State<Arc<AppState>>,
    BearerKey(client_key): BearerKey,
    body: axum::body::Bytes,
) -> Result<Json<OutcomeResponse>, StatusCode> {
    verify_claim(&state, &session_id, &client_key).await?;

    let mut session_state = state
        .state_store
        .get(&session_id, client_key.expose_secret(), TEE_KEY)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if session_state.passport.is_none() {
        session_state.passport = Some(body.to_vec());
    } else if session_state.liveness_frames.is_empty() {
        session_state.liveness_frames = vec![body.to_vec()];
    }

    let outcome = state
        .runner
        .run(&mut session_state)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state
        .state_store
        .put(&session_id, &session_state, client_key.expose_secret(), TEE_KEY)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(outcome_to_response(outcome)))
}

/// Verifies the provided client key matches the one that claimed the session.
/// If the cache was evicted or pod restarted, accept and re-populate —
/// state is still decryptable since client holds the key.
async fn verify_claim(
    state: &AppState,
    session_id: &str,
    client_key: &ClientKey,
) -> Result<(), StatusCode> {
    match state.client_keys.get(session_id).await {
        Some(existing) if existing.expose_secret() == client_key.expose_secret() => Ok(()),
        Some(_) => Err(StatusCode::FORBIDDEN),
        None => {
            let cloned = client_key.expose_secret().clone();
            state
                .client_keys
                .insert(
                    session_id.to_string(),
                    Arc::new(SecretBox::new(Box::new(cloned))),
                )
                .await;
            Ok(())
        }
    }
}

fn outcome_to_response(outcome: RunOutcome) -> OutcomeResponse {
    match outcome {
        RunOutcome::Completed => OutcomeResponse {
            status: "completed",
            request: None,
        },
        RunOutcome::Suspended(media_request) => OutcomeResponse {
            status: "awaiting_input",
            request: Some(format!("{media_request:?}").to_lowercase()),
        },
    }
}
