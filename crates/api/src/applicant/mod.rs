//! Applicant-facing API: per-session endpoints used by the verification
//! frontend, plus the static frontend assets themselves. Each handler in
//! its own file for navigability; shared helpers and JSON view types
//! live in their own modules.
//!
//! Auth model mirrors the client API: a single `enforce` middleware,
//! attached per-route via `.layer(auth())`. See `auth.rs` for cache
//! semantics. `/status` (GET) and `/state` (DELETE, recovery path) are
//! intentionally unauthenticated and bypass the layer at the router.
//!
//! Static assets:
//! The applicant frontend is served from this same surface, compiled
//! into this binary rather than read from a directory — see
//! `crate::assets` and `build.rs`. So one launch digest covers both
//! the page and the handlers it calls, and an applicant asking what
//! code they are running has one number to check rather than two.
//!
//! The page is served at `/` and its files at their own paths; nothing
//! else. Its client-side routes live in the URL fragment
//! (`/#/session/<id>/...`), which a browser never sends, so every
//! in-page address arrives here as `/`. Any other path no API route
//! claimed is a 404 — see `crate::assets::lookup` for why the page is
//! not served there too.
//!
//! **Empty in dev:** a build that was not given the built page carries
//! no assets and answers 404. Run Vite (`pnpm dev`) alongside and let
//! it proxy API paths here — see `frontend/vite.config.ts`. An
//! attested build cannot be produced without the page at all; `build.rs`
//! refuses.

mod auth;
mod callbacks;
mod connect;
mod input;
pub(crate) mod media_store;
mod persister;
mod reset;
mod shared;
mod status;
mod views;

use std::sync::Arc;

use axum::Router;
use axum::http::header::AUTHORIZATION;
use axum::http::{Method, StatusCode, Uri, header};
use axum::middleware::from_fn;
use axum::response::{IntoResponse, Response};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;

use crate::state::AppState;

use self::auth::enforce;

/// Build the applicant-facing router with all route declarations.
/// Endpoint inventory lives here — colocated with auth posture and
/// static-asset wiring — so the surface is auditable in one place.
pub fn router(state: Arc<AppState>) -> Router {
    let auth = || from_fn(enforce);

    // Applicant API routes live under the same `/api/v1/sessions/...`
    // prefix as the client API (see `client::router`) for a consistent
    // surface across the two audiences. The page calls them by paths
    // relative to itself, so wherever the page was reached the calls
    // follow. The page is served by the fallback below, at the root and
    // at a session's link (`/<session id>`); its steps live in the
    // fragment.
    let routes = Router::new()
        .route("/api/v1/sessions/{id}/status", status::get_status())
        .route("/api/v1/sessions/{id}/state", reset::delete_state())
        .route(
            "/api/v1/sessions/{id}/connect",
            connect::post_connect().layer(auth()),
        )
        .route(
            "/api/v1/sessions/{id}/input/{slot_id}",
            input::post_input().layer(auth()),
        );

    // The page, out of this binary. Not a directory the host named: it is
    // compiled in, so the bytes a browser runs are covered by the same launch
    // digest as the handlers above. A developer build has an empty table and
    // answers 404 — Vite serves the page on its own port there.
    let routes = routes.fallback(page);

    // Mark the bearer the applicant sends on /connect /input as
    // sensitive. See `client::router` for the rationale; same posture
    // applies here — http/2 HPACK side-channel + tracing-safe Debug
    // formatting. Applicant flow only uses `Authorization`; there's
    // no X-Session-Token equivalent on this surface.
    let routes = routes.layer(SetSensitiveRequestHeadersLayer::new([AUTHORIZATION]));

    // Outermost safety net: see client/mod.rs for rationale. Caches
    // panics from any source into clean 500s.
    routes.layer(CatchPanicLayer::new()).with_state(state)
}

/// What the page is allowed to be reached from.
///
/// The applicant is the sole auditor of a consent screen, so the screen must not
/// be paintable by anyone else: `frame-ancestors` stops it being framed,
/// `base-uri` stops a relative reference being re-pointed, and `object-src`
/// closes the one embed the other two do not cover.
///
/// Deliberately NOT a `default-src`. A strict source policy has to be checked
/// against what the bundler actually emits — Vite inlines module preloads — and
/// an unverified one that breaks the page is worse than a narrow one that holds.
const PAGE_POLICY: &str = "frame-ancestors 'none'; base-uri 'none'; object-src 'none'";

/// Serve the compiled-in page at `/`, and its files at their own paths, for
/// anything no API route claimed — see `crate::assets::lookup`.
async fn page(method: Method, uri: Uri) -> Response {
    if !matches!(method, Method::GET | Method::HEAD) {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let Some(asset) = crate::assets::lookup(uri.path()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    (
        [
            (header::CONTENT_TYPE, asset.content_type),
            (header::CACHE_CONTROL, crate::assets::cache_control(asset)),
            (header::CONTENT_SECURITY_POLICY, PAGE_POLICY),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            // The page's address names the session, and the group and build
            // the gateway routed it to. A browser sends that whole address as
            // the `Referer` of every request the page makes, its own calls to
            // this api included — so none is sent.
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        asset.bytes,
    )
        .into_response()
}
