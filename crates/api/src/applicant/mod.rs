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
mod persister;
mod report;
mod reset;
mod shared;
mod status;
mod views;

use std::sync::Arc;

use axum::Router;
use axum::middleware::from_fn_with_state;
use tower_http::services::{ServeDir, ServeFile};

use crate::state::AppState;

use self::auth::enforce;

/// Build the applicant-facing router with all route declarations.
/// Endpoint inventory lives here — colocated with auth posture and
/// static-asset wiring — so the surface is auditable in one place.
pub fn router(state: Arc<AppState>) -> Router {
    let auth = || from_fn_with_state(state.clone(), enforce);

    let routes = Router::new()
        // Public per-instance attestation manifest. Mounted ahead of
        // the SPA fallback so `/.well-known/...` paths don't get
        // swallowed by ServeDir.
        .route("/.well-known/attestation", attestation::get_attestation())
        .route("/session/{id}/status", status::get_status())
        .route("/session/{id}/state", reset::delete_state())
        .route("/session/{id}/connect", connect::post_connect().layer(auth()))
        .route("/session/{id}/input/{slot_id}", input::post_input().layer(auth()))
        .route("/session/{id}/report", report::post_report().layer(auth()));

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

    routes.with_state(state)
}
