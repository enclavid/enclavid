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
//! The applicant frontend (HTML/CSS/JS) is normally served from the
//! same listener so its origin matches the API origin (no CORS, same
//! TLS cert pinned by attestation, browser sees one identity). The
//! asset directory is supplied via `ENCLAVID_FRONTEND_DIR`. SPA-style
//! fallback: any path that doesn't match an API route or a real file
//! collapses to `index.html` so client-side routing (e.g.
//! `/session/<id>/...` URLs) loads the same app shell. Note this
//! means a 404 on a missing asset (e.g. a stale
//! `/assets/main.<hash>.js`) still serves index.html — acceptable for
//! production builds with content-hashed asset names.
//!
//! **Optional in dev:** if `ENCLAVID_FRONTEND_DIR` is unset, the api
//! binary skips static serving entirely. Run Vite dev (`npm run
//! dev`) on the frontend in parallel and let it proxy API paths
//! here — see `frontend/vite.config.ts` for the proxy config. HMR
//! works, the api stays focused on JSON. In production-equivalent
//! deployment the env var IS required; otherwise visitors landing on
//! `/session/<id>/` get a 404.

mod attestation;
mod auth;
mod connect;
mod input;
mod media_store;
mod persister;
mod reset;
mod shared;
mod status;
mod views;

use std::sync::Arc;

use axum::Router;
use axum::http::header::AUTHORIZATION;
use axum::middleware::from_fn_with_state;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::services::{ServeDir, ServeFile};

use crate::state::AppState;

use self::auth::enforce;

/// Build the applicant-facing router with all route declarations.
/// Endpoint inventory lives here — colocated with auth posture and
/// static-asset wiring — so the surface is auditable in one place.
pub fn router(state: Arc<AppState>) -> Router {
    let auth = || from_fn_with_state(state.clone(), enforce);

    // Applicant API routes live under the same `/api/v1/sessions/...`
    // prefix as the client API (see `client::router`) for a consistent
    // surface across the two audiences. The user-facing SPA route in
    // the browser stays `/session/<id>/...` (short, pretty) — handled
    // by the ServeDir fallback below; only the JSON endpoints under
    // it are versioned/plural.
    let routes = Router::new()
        // Public per-instance attestation manifest. Mounted ahead of
        // the SPA fallback so `/.well-known/...` paths don't get
        // swallowed by ServeDir.
        .route("/.well-known/attestation", attestation::get_attestation())
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

    // Static SPA bundle — optional. Skip the fallback when
    // `ENCLAVID_FRONTEND_DIR` is unset so dev workflows can run Vite
    // dev (with HMR) on a separate port and proxy API paths here.
    let routes = match std::env::var("ENCLAVID_FRONTEND_DIR") {
        Ok(dir) => {
            let index = format!("{dir}/index.html");
            routes.fallback_service(ServeDir::new(&dir).fallback(ServeFile::new(index)))
        }
        Err(_) => routes,
    };

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
