//! Applicant-facing API: per-session endpoints used by the verification
//! frontend. Each handler in its own file for navigability; shared
//! helpers and JSON view types live in their own modules.

mod input;
mod report;
mod shared;
mod start;
mod status;
mod views;

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};

use crate::state::AppState;

/// Build the applicant-facing router with all route declarations.
/// Endpoint inventory lives here — colocated with the handlers — so the
/// surface is auditable in one place.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/session/{id}/status", get(status::get_status))
        .route("/session/{id}/start", post(start::post_start))
        .route("/session/{id}/input", post(input::post_input))
        .route("/session/{id}/report", post(report::post_report))
        .with_state(state)
}
