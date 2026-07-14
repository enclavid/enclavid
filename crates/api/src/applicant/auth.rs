//! Per-route authentication for the applicant-facing API.
//!
//! Uniform model across the authenticated routes (`/connect`, `/input`):
//! parse the `Authorization: Bearer <base64>` header into a [`CallerKey`]
//! (the applicant's session token) and attach it to the request
//! extensions. The handler downstream extracts `CallerKey` and uses it as
//! the inner AEAD layer key for session state + media.
//!
//! There is NO key table here. A wrong key is rejected CRYPTOGRAPHICALLY,
//! not by a lookup: session state is sealed under the applicant token, so a
//! mismatched bearer fails to open it at the state read in the extractor,
//! which surfaces as **403** (see `shared::SessionRunCtx` +
//! `BridgeError::Crypto`). The frontend treats that 403 as "wrong key /
//! different device" and offers `/reset`. First-claim is implicit: a fresh
//! session has no state, so the first `/connect` establishes it under
//! whatever key is presented; `/reset` deletes the state, making the
//! session claimable again with a new key.
//!
//! `/status` and `/state` (DELETE) are intentionally unauthenticated and
//! bypass this layer at the router level.

use std::sync::Arc;

use axum::extract::{FromRequestParts, Request};
use axum::http::{header, request::Parts, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use base64ct::{Base64, Encoding};
use secrecy::SecretBox;

use crate::state::ApplicantSessionToken;

/// Applicant key attached to a request by `enforce`. The `SessionRunCtx`
/// extractor clones this `Arc` out of the request extensions to become the
/// per-round SOLE strong owner of the token; the persister / media store hold
/// only `Weak`s to it (see `SessionRunCtx`). `Arc` so that clone is cheap and
/// the token lives in a single allocation.
#[derive(Clone)]
pub(super) struct CallerKey(pub Arc<ApplicantSessionToken>);

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

pub(super) async fn enforce(mut req: Request, next: Next) -> Result<Response, StatusCode> {
    // Parse the bearer into the applicant session token and attach it. No
    // lookup, no claim table: a wrong key can't open the AEAD-sealed state,
    // so it is rejected at the state read (403), not here. A missing /
    // malformed header is the only thing this layer rejects (401).
    let key = parse_bearer(&req)?;
    let key_arc = Arc::new(SecretBox::new(Box::new(key)));
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
