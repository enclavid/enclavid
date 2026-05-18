//! `enclavid session ...` — talk to the Enclavid API for session
//! lifecycle: create, read state, pull + decrypt disclosures.
//!
//! Auth comes from `auth::get_access_token` (env API_TOKEN → M2M →
//! cached cloud login). API endpoint comes from `$ENCLAVID_API_URL`
//! (default `http://localhost:8001`). The applicant URL printed by
//! `create` comes from `$ENCLAVID_APPLICANT_URL` (default
//! `http://localhost:5173`).
//!
//! `create` caches the returned `client_session_token` and the
//! disclosure-key secret under `~/.config/enclavid/sessions/<id>/`
//! so subsequent `get` / `disclosures` work without re-passing them.

pub mod cache;
pub mod create;
pub mod disclosures;
pub mod get;
mod transport;

/// `$ENCLAVID_API_URL` resolver — same lookup pattern as other CLI
/// env overrides. Defaulting to localhost is fine because non-local
/// production CLI usage will set this explicitly (or get it through
/// discovery, when discovery starts publishing it).
pub fn api_url() -> String {
    std::env::var("ENCLAVID_API_URL").unwrap_or_else(|_| "http://localhost:8001".to_string())
}

/// `$ENCLAVID_APPLICANT_URL` resolver — base origin of the applicant
/// SPA. Used only for printing the "open this in a browser" hint
/// after `session create`. Default targets `pnpm dev` on :5173; set
/// to `http://localhost:8002` when api serves built static instead.
pub fn applicant_url() -> String {
    std::env::var("ENCLAVID_APPLICANT_URL").unwrap_or_else(|_| "http://localhost:5173".to_string())
}
