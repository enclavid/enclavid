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
//! policy ref + disclosure pubkey + per-plugin pins in one body, the
//! TEE mints attestation, persists metadata (AEAD-sealed under
//! tee_seal_key), and returns the session_id ready for applicant
//! interaction. Policy artifact pull + compile happens lazily at
//! applicant /connect, so abandoned sessions don't pay compile-cost
//! and TEE restarts don't strand in-flight work.
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
use axum::http::header::{AUTHORIZATION, HeaderName};
use axum::middleware::from_fn_with_state;
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;

use hatch_client::ClientOperation;

use crate::client_state::ClientState;

use self::auth::enforce;

/// Per-session capability bearer client sends on every read endpoint.
/// Mirrors `client::auth::SESSION_TOKEN_HEADER`; duplicated as a
/// constant here so the sensitive-headers layer can reference it
/// without dragging the auth module into the public surface of
/// `mod.rs`.
const SESSION_TOKEN_HEADER: HeaderName = HeaderName::from_static("x-session-token");

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
        // Mark auth-bearing request headers as sensitive. Two
        // payoffs: (1) when http/2 is enabled, sensitive headers go
        // out as `literal never-indexed` and skip HPACK's dynamic
        // table — closes the CRIME-style compression side-channel
        // on the JWT and X-Session-Token; (2) any `tracing` / Debug
        // formatting of the headers map renders `Sensitive` in
        // place of the value, so accidental `?headers` logs don't
        // leak credentials. Marking is per-byte metadata only, no
        // payload mutation.
        .layer(SetSensitiveRequestHeadersLayer::new([
            AUTHORIZATION,
            SESSION_TOKEN_HEADER,
        ]))
        // Outermost safety net: any panic from a handler / dependency
        // / async runtime is caught and converted to a clean 500
        // response instead of aborting the connection. Our handlers
        // shouldn't panic (errors go through Result + ok_or), but
        // this guards against unexpected sources (deps, OOM-like
        // conditions) — especially important for a long-running TEE
        // service where aborted connections add operational noise
        // and a hard crash forces re-attestation.
        .layer(CatchPanicLayer::new())
        .with_state(state)
}
