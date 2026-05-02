//! Per-route authorization for the applicant-facing API.
//!
//! Uniform model across all authenticated routes (`/connect`, `/input`,
//! `/report`): parse the `Authorization: Bearer <base64>` header, then
//! verify (or establish) the claim against the in-memory cache of
//! per-session keys. The handler downstream extracts `CallerKey` from
//! request extensions.
//!
//! Cache semantics:
//!
//! - match → ok, pass through
//! - mismatch → 403 (someone else has already claimed this session;
//!   recovery requires `DELETE /session/:id/state` first)
//! - empty → accept and populate. After a TEE restart the cache is
//!   rebuilt from the first matching call. Real security is the
//!   decrypt step in the handler — wrong key fails there regardless.
//!
//! `/status` and `/state` (DELETE) are intentionally unauthenticated
//! and bypass this layer at the router level.

use std::sync::Arc;

use axum::extract::{FromRequestParts, Path, Request, State};
use axum::http::{header, request::Parts, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use base64ct::{Base64, Encoding};
use secrecy::{ExposeSecret, SecretBox};

use crate::state::{AppState, ApplicantKey};

/// Applicant key attached to a request by `enforce`. Handlers extract
/// this to encrypt/decrypt session state. `Arc` so it can be cloned
/// cheaply between extension storage and `applicant_keys` cache.
#[derive(Clone)]
pub(super) struct CallerKey(pub Arc<ApplicantKey>);

impl<S> FromRequestParts<S> for CallerKey
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<CallerKey>()
            .cloned()
            // 500 here means the auth layer didn't run — a router wiring
            // bug, not a runtime auth failure. Surfacing as 500 makes
            // such bugs loud rather than silently treated as "no auth
            // required".
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

pub(super) async fn enforce(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let key = parse_bearer(&req)?;
    let key_arc = Arc::new(SecretBox::new(Box::new(key)));

    match state.applicant_keys.get(&session_id).await {
        Some(existing) if existing.expose_secret() == key_arc.expose_secret() => {}
        Some(_) => return Err(StatusCode::FORBIDDEN),
        None => {
            state
                .applicant_keys
                .insert(session_id.clone(), key_arc.clone())
                .await;
        }
    }

    req.extensions_mut().insert(CallerKey(key_arc));
    Ok(next.run(req).await)
}

fn parse_bearer(req: &Request) -> Result<Vec<u8>, StatusCode> {
    let header = req
        .headers()
        .get(header::AUTHORIZATION)
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_str()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let token = header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;
    Base64::decode_vec(token).map_err(|_| StatusCode::UNAUTHORIZED)
}
