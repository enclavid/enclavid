//! `POST /api/v1/sessions/{id}/warmup` — have a session's composition compiled
//! and kept before its applicant connects.
//!
//! No body: what is compiled is what the session pins, read from its sealed
//! metadata. The answer is `202 Accepted` at once; the compile runs after it, and
//! a composition already kept, or already being compiled for the same consumer,
//! is not compiled again. Nothing is answered about how it went: the session's
//! first round meets any failure, as it would without a warmup. A session that
//! will not run again has nothing to warm, and is answered `409 Conflict`.
//!
//! The same as `"warmup": true` on the creation, for a session created without
//! it. Authorized as a creation is: it spends what the creation would have — one
//! compile — and nothing more.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{MethodRouter, post};

use hatch_client::{Metadata, SessionStatus, outbound_session_id};

use crate::client_state::ClientState;
use crate::compositions::Composition;

use super::auth::{Principal, SessionToken, trust_metadata};

/// Route factory: bare `post(handler)` MethodRouter. Auth is attached at the
/// router level via `.layer(auth(op))` — see `client::router`.
pub(super) fn post_warmup() -> MethodRouter<Arc<ClientState>> {
    post(warmup)
}

async fn warmup(
    State(state): State<Arc<ClientState>>,
    Principal(presented_principal): Principal,
    SessionToken(presented_token): SessionToken,
    Path(session_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let ((metadata_untrusted,), _version) = state
        .session_store
        .read(outbound_session_id(&session_id), (Metadata,))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let metadata = trust_metadata(metadata_untrusted, &presented_token, &presented_principal)?;
    if metadata.status != SessionStatus::Running {
        return Err(StatusCode::CONFLICT);
    }
    let composition = Composition::of(&metadata).ok_or_else(|| {
        safe_logger::debug!("client/warmup: metadata.client missing for {session_id}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let compositions = state.compositions.clone();
    tokio::spawn(async move { compositions.warm(composition).await });
    Ok(StatusCode::ACCEPTED)
}
