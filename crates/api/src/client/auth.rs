//! Per-route authorization for the client-facing API.
//!
//! Composition strategy (assembled inline at the router):
//!
//!     post(handler).layer(
//!         ServiceBuilder::new()
//!             .layer(Extension(ClientOperation::Foo))            // outer
//!             .layer(from_fn_with_state(state, auth::enforce))   // inner
//!             .into_inner()
//!     )
//!
//! Tower's `ServiceBuilder` layer order: the **first** `.layer(...)` is
//! the outermost (runs first on the request). So `Extension(op)` wraps
//! `enforce` — at runtime the request hits Extension first, which
//! inserts the per-route operation into request extensions, then
//! `enforce` runs and reads it via the `Extension<ClientOperation>`
//! extractor. On success it injects `HostRef(host_ref)` into
//! request extensions so the handler downstream can read it; on
//! failure short-circuits 401 / 403.
//!
//! A single auth layer at the router level wouldn't work — at that
//! position the auth middleware would run before any per-route
//! Extension is set. The two have to live inside the same per-route
//! stack with the right ordering.

use std::sync::Arc;

use axum::extract::{Extension, FromRequestParts, Request, State};
use axum::http::{HeaderName, StatusCode, header, request::Parts};
use axum::middleware::Next;
use axum::response::Response;
use base64ct::{Base64, Encoding};

use enclavid_host_bridge::{AuthN, AuthVerdict, ClientOperation, Replay, reason};

use crate::client_state::ClientState;

/// Per-session capability header. Carries the `client_session_token`
/// the TEE issued at `POST /sessions` (base64-encoded 32 random bytes).
/// Required on every client-side read endpoint. See docs/security-model.md
/// → "HTTP transport convention".
pub(super) const SESSION_TOKEN_HEADER: HeaderName = HeaderName::from_static("x-session-token");

/// HostRef context attached to a request by `enforce`. Handlers
/// extract this to learn which tenant the caller is bound to;
/// downstream session-ownership checks compare against it.
#[derive(Clone, Debug)]
pub(super) struct HostRef(pub String);

impl<S> FromRequestParts<S> for HostRef
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<HostRef>()
            .cloned()
            // 500 here means the protective layer didn't run — a router
            // wiring bug, not a runtime auth failure. Surfacing as 500
            // makes sure such bugs are loud rather than silently treated
            // as "no auth required".
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

/// Per-session bearer the client supplies in `X-Session-Token`. Read
/// endpoints extract this and compare its SHA-256 against
/// `SessionMetadata.client_session_token_hash`. Decoded from base64
/// at extraction time so handlers compare raw bytes (constant-time).
///
/// Missing or malformed header → 401 (transport-level auth failure).
/// Hash mismatch (handler-side) → 404 (don't leak which-session info).
#[derive(Clone, Debug)]
pub(super) struct SessionToken(pub Vec<u8>);

impl<S> FromRequestParts<S> for SessionToken
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let raw = parts
            .headers
            .get(&SESSION_TOKEN_HEADER)
            .ok_or(StatusCode::UNAUTHORIZED)?
            .to_str()
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        let bytes = Base64::decode_vec(raw.trim()).map_err(|_| StatusCode::UNAUTHORIZED)?;
        Ok(SessionToken(bytes))
    }
}

/// Verify a presented `client_session_token` against the SHA-256 hash
/// stored in session metadata. SHA-256 the bytes, then compare
/// constant-time. Returns Ok if match, Err(404) otherwise.
///
/// `404` instead of `403` is deliberate — we don't want to leak
/// existence-of-session information to an attacker probing with
/// random tokens.
pub(super) fn verify_session_token(
    presented: &[u8],
    stored_hash: &[u8],
) -> Result<(), StatusCode> {
    use sha2::{Digest, Sha256};
    let computed = Sha256::digest(presented);
    if computed.len() == stored_hash.len() && constant_time_eq(&computed, stored_hash) {
        Ok(())
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// Constant-time byte slice equality. Length-prefix check above this
/// caller ensures equal length; XOR-fold avoids the early-exit timing
/// leak `==` would have. Fine for 32-byte SHA-256 outputs where
/// timing is irrelevant in practice but cheap to do right.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Auth middleware body. Reads the operation from request extensions
/// (placed there by the outer `Extension(op)` layer in the per-route
/// `ServiceBuilder` stack) and forwards the Authorization header to the
/// host-side Auth service. On success injects `HostRef(host_ref)`
/// for the handler to extract.
pub(super) async fn enforce(
    State(state): State<Arc<ClientState>>,
    Extension(op): Extension<ClientOperation>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    // Identity verification is delegated to the host: the TEE has no
    // network stack and no way to validate a credential itself. The
    // host receives the Authorization header, talks to the identity
    // provider, and tells us the tenant this credential belongs to.
    // We accept its word.
    //
    // What goes wrong if the host lies:
    //
    //   1. Host claims an invalid credential is authentic → a fake
    //      caller reaches /sessions create.
    //   2. Host claims a valid credential belongs to tenant X when
    //      it actually belongs to Y → attempted impersonation.
    //   3. Host denies valid credentials → denial of service.
    //
    // Why none of these escalate to applicant-data leak:
    //
    //   * /sessions creation requires `client_policy_key` (the policy-decryption
    //     age secret), validated synchronously against the policy's
    //     `validator` manifest annotation. client_policy_key lives in the
    //     legitimate client's HSM / KMS, not on our infrastructure —
    //     without it, the validator decrypt fails and the handler
    //     returns 422 before persisting anything. A fake or
    //     impersonated caller never gets a session at all.
    //   * The attestation quote binds (session_id, policy_digest) to
    //     this TEE's measurement; it's signed by hardware (AMD-SP) and
    //     unforgeable by the host. If a real client is tricked into
    //     using a spoofed session_id, quote verification on their side
    //     fails and they refuse to deliver further inputs.
    //
    // What's left as residual risk:
    //
    //   * Resource consumption — repeated /sessions attempts with
    //     wrong client_policy_key burn registry-pull bandwidth and audit-log
    //     volume.
    //   * Reputation / spam — surface for phishing where the attacker
    //     uses spoofed session_ids to confuse legitimate clients
    //     (mitigated by attestation as above).
    //
    // Both are operationally mitigated, not cryptographically:
    //   - Rate limit per tenant on session creation.
    //   - Audit log every authorize outcome to an append-only sink.
    //   - Alert on bursts of /sessions failures or unusual
    //     tenant-create patterns (signature of a host substitution).
    //
    // See architecture.md → Network Isolation → "External content fetch"
    // for the full threat-model write-up.
    let verdict = state
        .auth
        .authorize(auth_header, op)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .trust_unchecked::<AuthN, _>(reason!(r#"
TEE has nothing to verify a credential against — host parses
tokens, TEE never sees them. A lying host can claim an invalid
credential is valid or substitute a different host_ref.
Neither escalates: /sessions needs client_policy_key (validated against
the policy's manifest validator annotation, secret held by the
legitimate client) — without it the create returns 422 and
nothing is persisted.
        "#))
        .trust_unchecked::<Replay, _>(reason!(r#"
Stale verdict (yesterday's answer for today's request — e.g.
accepting a since-revoked credential) caps at the same place:
spurious denial or a stalled caller who can't progress past
the client_policy_key validator check. No data leak path.
        "#))
        .into_inner();
    let host_ref = match verdict {
        AuthVerdict::Allowed(t) => t.0,
        AuthVerdict::Unauthenticated => return Err(StatusCode::UNAUTHORIZED),
        AuthVerdict::PermissionDenied => return Err(StatusCode::FORBIDDEN),
    };
    req.extensions_mut().insert(HostRef(host_ref));

    Ok(next.run(req).await)
}
