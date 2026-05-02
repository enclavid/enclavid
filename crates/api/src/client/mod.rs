//! Client-facing API: session lifecycle endpoints.
//!
//! Routes:
//!   POST /api/v1/sessions             — create (PendingInit)
//!   POST /api/v1/sessions/:id/init    — deliver wrapped K_client
//!   GET  /api/v1/sessions/:id/status  — poll
//!   GET  /api/v1/sessions/:id/shared-data — pull consented data (post-completion)
//!
//! See architecture.md → Client-Facing Session Creation for the protocol
//! shape and threat model. Counterparts to the applicant API live in
//! the sibling `applicant` module — different audience, different auth
//! (JWT via host vs BearerKey), different state.

mod auth;
mod create;
mod init;
mod status;

use std::sync::Arc;

use axum::Router;
use axum::extract::Extension;
use axum::middleware::from_fn_with_state;
use tower::ServiceBuilder;

use enclavid_host_bridge::ClientOperation;

use crate::client_state::ClientState;

use self::auth::enforce;

/// Build the client-facing router.
///
/// Each handler module exposes a `verb_action() -> MethodRouter` factory
/// returning a bare `post(handler)` / `get(handler)` route. Auth is
/// attached uniformly at the router via `.layer(auth(op))` — a closure
/// that captures `state` once and produces a per-route auth stack
/// (`from_fn_with_state(enforce)` + `Extension(op)`) in the right layer
/// order. Tower's outer-runs-first ordering means this stack has to be
/// per-route — see `auth::enforce` for the rationale.
pub fn router(state: Arc<ClientState>) -> Router {
    let auth = |op: ClientOperation| {
        ServiceBuilder::new()
            .layer(from_fn_with_state(state.clone(), enforce))
            .layer(Extension(op))
    };

    Router::new()
        .route(
            "/api/v1/sessions",
            create::post_create().layer(auth(ClientOperation::SessionCreate)),
        )
        .route(
            "/api/v1/sessions/{id}/init",
            init::post_init().layer(auth(ClientOperation::SessionInit)),
        )
        .route(
            "/api/v1/sessions/{id}/status",
            status::get_status().layer(auth(ClientOperation::SessionRead)),
        )
        .with_state(state)
}
