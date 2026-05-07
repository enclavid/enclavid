//! Client-facing API: session lifecycle endpoints.
//!
//! Routes:
//!   POST /api/v1/sessions                    — create + activate (one shot)
//!   GET  /api/v1/sessions/:id                — read session view (status,
//!                                              policy, disclosure count, ...)
//!   GET  /api/v1/sessions/:id/disclosures    — pull age-encrypted disclosure
//!                                              entries (opaque ciphertext)
//!
//! Session creation is a single endpoint: the client supplies the
//! policy ref + K_client + disclosure pubkey in one body, the TEE
//! validates K_client against the policy's manifest annotation,
//! mints attestation, persists metadata (K_client encrypted under
//! TEE_key), and returns the session_id ready for applicant
//! interaction. Policy artifact pull/decrypt/compile happens lazily
//! at applicant /connect, so abandoned sessions don't pay
//! compile-cost and TEE restarts don't strand in-flight work.
//!
//! See architecture.md → Client-Facing Session Creation for the
//! protocol shape and threat model. Counterparts to the applicant
//! API live in the sibling `applicant` module — different audience,
//! different auth (JWT via host vs BearerKey), different state.

mod auth;
mod create;
mod disclosures;
mod session;

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
    // ServiceBuilder layer order: the first `.layer(...)` is the
    // OUTERMOST (runs first on the request). `Extension(op)` must
    // wrap `enforce` so the operation tag is already in the request
    // extensions by the time the middleware reads it.
    let auth = |op: ClientOperation| {
        ServiceBuilder::new()
            .layer(Extension(op))
            .layer(from_fn_with_state(state.clone(), enforce))
    };

    Router::new()
        .route(
            "/api/v1/sessions",
            create::post_create().layer(auth(ClientOperation::SessionCreate)),
        )
        .route(
            "/api/v1/sessions/{id}",
            session::get_session().layer(auth(ClientOperation::SessionRead)),
        )
        .route(
            "/api/v1/sessions/{id}/disclosures",
            disclosures::get_disclosures().layer(auth(ClientOperation::DataRead)),
        )
        .with_state(state)
}
