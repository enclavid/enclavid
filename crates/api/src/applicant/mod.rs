//! Applicant-facing API: per-session endpoints used by the verification
//! frontend. Each handler in its own file for navigability; shared
//! helpers and JSON view types live in their own modules.
//!
//! Auth model mirrors the client API: a single `enforce` middleware,
//! attached per-route via `.layer(auth())`. See `auth.rs` for cache
//! semantics. `/status` (GET) and `/state` (DELETE, recovery path) are
//! intentionally unauthenticated and bypass the layer at the router.

mod auth;
mod connect;
mod input;
mod persister;
mod report;
mod reset;
mod shared;
mod status;
mod views;

use std::sync::Arc;

use axum::Router;
use axum::middleware::from_fn_with_state;

use crate::state::AppState;

use self::auth::enforce;

/// Build the applicant-facing router with all route declarations.
/// Endpoint inventory lives here — colocated with auth posture — so
/// the surface is auditable in one place.
pub fn router(state: Arc<AppState>) -> Router {
    let auth = || from_fn_with_state(state.clone(), enforce);

    Router::new()
        .route("/session/{id}/status", status::get_status())
        .route("/session/{id}/state", reset::delete_state())
        .route("/session/{id}/connect", connect::post_connect().layer(auth()))
        .route("/session/{id}/input", input::post_input().layer(auth()))
        .route("/session/{id}/report", report::post_report().layer(auth()))
        .with_state(state)
}

