//! Per-route authorization for the client-facing API.
//!
//! Composition strategy (assembled inline at the router):
//!
//!     post(handler).layer(
//!         ServiceBuilder::new()
//!             .layer(from_fn_with_state(state, auth::enforce))   // inner
//!             .layer(Extension(ClientOperation::Foo))            // outer
//!             .into_inner()
//!     )
//!
//! Layer order in `ServiceBuilder` is outer-on-top, so the second
//! `.layer(...)` (Extension) ends up wrapping the first (`enforce`).
//! At runtime the request hits Extension first, which inserts the
//! per-route operation into request extensions; then `enforce` runs and
//! reads it via the `Extension<ClientOperation>` extractor. On success
//! it injects `Workspace(workspace_id)` into request extensions so the
//! handler downstream can read it; on failure short-circuits 401 / 403.
//!
//! A single auth layer at the router level wouldn't work — at that
//! position the auth middleware is the outermost and runs before any
//! per-route Extension would be set. The two have to live inside the
//! same per-route stack with the right ordering.

use std::sync::Arc;

use axum::extract::{Extension, FromRequestParts, Request, State};
use axum::http::{StatusCode, header, request::Parts};
use axum::middleware::Next;
use axum::response::Response;

use enclavid_session_store::{AuthError, ClientOperation};

use crate::client_state::ClientState;

/// Workspace context attached to a request by `enforce`. Handlers
/// extract this to learn which workspace the caller is bound to;
/// downstream tenant-boundary checks (session ownership) compare
/// against it.
#[derive(Clone, Debug)]
pub(super) struct Workspace(pub String);

impl<S> FromRequestParts<S> for Workspace
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Workspace>()
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
/// host-side Auth service. On success injects `Workspace(workspace_id)`
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
    // provider, and tells us the workspace this credential belongs to.
    // We accept its word.
    //
    // What goes wrong if the host lies:
    //
    //   1. Host claims an invalid credential is authentic → a fake
    //      `PendingInit` session is created.
    //   2. Host claims a valid credential belongs to workspace X when
    //      it actually belongs to Y → attempted impersonation.
    //   3. Host denies valid credentials → denial of service.
    //
    // Why none of these escalate to applicant-data leak:
    //
    //   * To progress past `/init`, the caller must supply `K_client`
    //     wrapped to the session's ephemeral pubkey. `K_client` lives
    //     in the legitimate client's HSM/KMS, not on our infrastructure.
    //     A fake or impersonated session sits in `PendingInit` forever
    //     and is garbage-collected — the policy never decrypts, the
    //     applicant flow never starts, no data flows.
    //   * The attestation quote is signed by hardware (AMD-SP) and binds
    //     (session_id, ephemeral_pubkey, policy_digest). The host can't
    //     forge it; if a real client is somehow tricked into using a
    //     spoofed session, the quote verification on their side fails
    //     and they refuse to send `K_client`.
    //
    // What's left as residual risk:
    //
    //   * Resource consumption — fake `PendingInit` sessions burn
    //     storage space, ephemeral keys in cache, audit-log volume.
    //   * Reputation / spam — surface for phishing where the attacker
    //     uses fake sessions to confuse legitimate clients.
    //
    // Both are operationally mitigated, not cryptographically:
    //   - Rate limit per workspace on session creation.
    //   - Audit log every authorize outcome to an append-only sink.
    //   - Alert on bursts of `FailedInit` or unusual workspace-create
    //     patterns (signature of a host substitution).
    //
    // See architecture.md → Network Isolation → "External content fetch"
    // for the full threat-model write-up.
    let workspace_id = match state.auth.authorize(auth_header, op).await {
        Ok(ws) => ws.trust_unchecked(),
        Err(AuthError::Unauthenticated) => return Err(StatusCode::UNAUTHORIZED),
        Err(AuthError::PermissionDenied) => return Err(StatusCode::FORBIDDEN),
        Err(AuthError::Transport(_)) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };
    req.extensions_mut().insert(Workspace(workspace_id));

    Ok(next.run(req).await)
}
