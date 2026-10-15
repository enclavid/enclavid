//! `POST /api/v1/sessions/{id}/warmup` — prepare a session to run before its
//! applicant connects.
//!
//! No body: what is prepared is what the session pins, read from its sealed
//! metadata ([`crate::init::prepare`]). The answer is `202 Accepted` at once; the
//! preparation runs after it, and a composition already kept, or already being
//! compiled for the same consumer, is not compiled again. It leaves the
//! composition held by the execution-worker, so a round soon after starts
//! without waiting for it; the applicant's page asks the same when its
//! applicant comes later (`crate::applicant`). Nothing is answered
//! about how it went: a session that cannot be prepared is marked so, and the
//! consumer reads why in its view of the session. A session that will not run
//! again has nothing to prepare, and is answered `409 Conflict`.
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
use crate::init;

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
    let ((metadata_untrusted,), version) = state
        .session_store
        .read(outbound_session_id(&session_id), (Metadata,))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let metadata = trust_metadata(metadata_untrusted, &presented_token, &presented_principal)?;
    if metadata.status != SessionStatus::Running {
        return Err(StatusCode::CONFLICT);
    }
    init::warm_in_background(
        state.compositions.clone(),
        state.session_store.clone(),
        session_id,
        version,
        metadata,
    );
    Ok(StatusCode::ACCEPTED)
}
