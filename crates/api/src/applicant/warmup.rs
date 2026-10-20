//! `POST /api/v1/sessions/{id}/warmup` — the applicant's page asks for the
//! session to be made ready to run while the applicant is still drawing their
//! key, so that the first round finds its composition held.
//!
//! The consumer's own warmup (`crate::client`) prepares a session when it is
//! created; one whose applicant comes days later finds that gone from the
//! execution-worker's cache, and this brings it back, from L2 or compiled.
//! What is prepared is what the session pins, read from its sealed metadata
//! ([`crate::init::prepare`]). The answer is `202 Accepted` at once, and says
//! nothing about how it went: a session that cannot be prepared is marked so,
//! and the applicant's next request is answered as it would be. A session that
//! will not run again has nothing to prepare: `409 Conflict`.
//!
//! Unauthenticated, as `/status` is: the applicant has no key yet. It asks for
//! nothing the session's own `/connect` would not, and at most one warmup of a
//! session is under way at a time; the session's `/connect` prepares it as well.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{MethodRouter, post};

use enclavid_boundary::{AuthZ, Replay, reason};
use session_types::SessionStatus;
use storage_client::Metadata;

use crate::init;
use crate::state::AppState;

/// Route factory. Public (no auth layer) — see `applicant::router`.
pub(super) fn post_warmup() -> MethodRouter<Arc<AppState>> {
    post(warmup)
}

async fn warmup(Path(session_id): Path<String>, State(state): State<Arc<AppState>>) -> StatusCode {
    let Ok(((metadata,), version)) = state.session_store.read(&session_id, (Metadata,)).await
    else {
        return StatusCode::INTERNAL_SERVER_ERROR;
    };
    let Some(metadata) = metadata
        .trust_accept_risk(reason!(
            AuthZ::AcceptedRisk,
            "anyone holding the session's link may cause its preparation, and with it \
             the write that marks a session that cannot run, as its /connect would"
        ))
        .trust(reason!(
            Replay::Harmless,
            "stale metadata prepares what the session pinned all the same, and a failure \
             found on it is marked by a write the version guards"
        ))
        .into_inner()
    else {
        return StatusCode::NOT_FOUND;
    };
    if metadata.status != SessionStatus::Running {
        return StatusCode::CONFLICT;
    }
    init::warm_in_background(
        state.compositions.clone(),
        state.session_store.clone(),
        session_id,
        version,
        metadata,
    );
    StatusCode::ACCEPTED
}
