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
//! extractor. On success it injects `Tenant(tenant_id)` into
//! request extensions so the handler downstream can read it; on
//! failure short-circuits 401 / 403.
//!
//! A single auth layer at the router level wouldn't work — at that
//! position the auth middleware would run before any per-route
//! Extension is set. The two have to live inside the same per-route
//! stack with the right ordering.

use std::sync::Arc;

use axum::extract::{Extension, FromRequestParts, Request, State};
use axum::http::{StatusCode, header, request::Parts};
use axum::middleware::Next;
use axum::response::Response;

use enclavid_host_bridge::{AuthN, AuthVerdict, ClientOperation, Replay, reason};

use crate::client_state::ClientState;

/// Tenant context attached to a request by `enforce`. Handlers
/// extract this to learn which tenant the caller is bound to;
/// downstream session-ownership checks compare against it.
#[derive(Clone, Debug)]
pub(super) struct Tenant(pub String);

impl<S> FromRequestParts<S> for Tenant
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Tenant>()
            .cloned()
            // 500 here means the protective layer didn't run — a router
            // wiring bug, not a runtime auth failure. Surfacing as 500
            // makes sure such bugs are loud rather than silently treated
            // as "no auth required".
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

/// Auth middleware body. Reads the operation from request extensions
/// (placed there by the outer `Extension(op)` layer in the per-route
/// `ServiceBuilder` stack) and forwards the Authorization header to the
/// host-side Auth service. On success injects `Tenant(tenant_id)`
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
    //   * /sessions creation requires `K_client` (the policy-decryption
    //     age secret), validated synchronously against the policy's
    //     `validator` manifest annotation. K_client lives in the
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
    //     wrong K_client burn registry-pull bandwidth and audit-log
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
credential is valid or substitute a different tenant_id.
Neither escalates: /sessions needs K_client (validated against
the policy's manifest validator annotation, secret held by the
legitimate client) — without it the create returns 422 and
nothing is persisted.
        "#))
        .trust_unchecked::<Replay, _>(reason!(r#"
Stale verdict (yesterday's answer for today's request — e.g.
accepting a since-revoked credential) caps at the same place:
spurious denial or a stalled caller who can't progress past
the K_client validator check. No data leak path.
        "#))
        .into_inner();
    let tenant_id = match verdict {
        AuthVerdict::Allowed(t) => t.0,
        AuthVerdict::Unauthenticated => return Err(StatusCode::UNAUTHORIZED),
        AuthVerdict::PermissionDenied => return Err(StatusCode::FORBIDDEN),
    };
    req.extensions_mut().insert(Tenant(tenant_id));

    Ok(next.run(req).await)
}
