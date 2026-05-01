use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Json;
use secrecy::ExposeSecret;
use serde::Deserialize;

use enclavid_engine::SessionState;

use crate::auth::BearerKey;
use crate::state::AppState;

use super::shared::{
    build_resources, fetch_metadata, lookup_policy, parse_args, TEE_KEY,
};
use super::views::{progress_from, SessionProgress};

#[derive(Deserialize)]
pub struct StartQuery {
    #[serde(default)]
    pub force: bool,
}

/// POST /session/:id/start — applicant claims a session with a freshly
/// minted bearer key and begins the verification flow. First call wins;
/// subsequent calls return 409 unless `?force=true`, in which case the
/// existing state is dropped and the session restarts.
pub async fn post_start(
    Path(session_id): Path<String>,
    Query(query): Query<StartQuery>,
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
    let policy = lookup_policy(&state, &session_id).await?;

    let (status, session_state) = state
        .runner
        .run(&policy, SessionState::default(), args, resources)
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
