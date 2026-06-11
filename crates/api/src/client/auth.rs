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
//! extractor. On success it injects `Principal(principal)` into
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

use enclavid_host_bridge::{
    AuthN, AuthVerdict, AuthZ, ClientOperation, Replay, SessionMetadata, Untrusted, reason,
};

use crate::client_state::ClientState;

/// Per-session capability header. Carries the `client_session_token`
/// the TEE issued at `POST /sessions` (base64-encoded 32 random bytes).
/// Required on every client-side read endpoint. See docs/security-model.md
/// → "HTTP transport convention".
pub(super) const SESSION_TOKEN_HEADER: HeaderName = HeaderName::from_static("x-session-token");

/// Principal context attached to a request by `enforce`. Carries the
/// optional authenticated identity from the auth verdict — `None`
/// means the host's auth scheme didn't produce a principal (Allowed
/// but anonymous; not currently used in MVP but the type allows for
/// it). TEE doesn't act on the value — it's pure attribution data
/// the create handler forwards to host-side storage via `SetPrincipal`.
#[derive(Clone, Debug)]
pub(super) struct Principal(pub Option<String>);

impl<S> FromRequestParts<S> for Principal
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Principal>()
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

/// Peel both trust scopes off an already-decrypted
/// `Untrusted<Option<SessionMetadata>, (AuthZ, Replay)>` for a
/// Client-side read endpoint: discharge AuthZ via
/// `check_client_access` (token + principal match), trust Replay
/// (metadata fields stable across session lifetime), and unwrap the
/// `Option`. Returns the verified `SessionMetadata` ready for the
/// handler to consume.
///
/// (Decryption / AEAD-unseal already happened inside
/// `SessionStore::read`; this function operates purely on the trust
/// machinery wrapping the decrypted value.)
///
/// Mirrors `applicant/shared.rs::fetch_metadata` for the Client side:
/// callers do the storage read themselves (so e.g. `/disclosures`
/// keeps its batched `(Metadata, Disclosure)` read), then hand the
/// resulting `Untrusted` here for the auth peel.
///
/// Errors:
///   * `404 NOT_FOUND` — metadata absent, or token/principal mismatch
///     (uniform reject; no session-existence leak).
///   * `500 INTERNAL_SERVER_ERROR` — malformed metadata
///     (`client`/`access` block absent — TEE-side invariant violation).
pub(super) fn trust_metadata(
    metadata: Untrusted<Option<SessionMetadata>, (AuthZ, Replay)>,
    presented_token: &[u8],
    presented_principal: &Option<String>,
) -> Result<SessionMetadata, StatusCode> {
    metadata
        .trust::<AuthZ, _, _, _, _>(|opt_md| -> Result<_, StatusCode> {
            {
                let md = opt_md.as_ref().ok_or(StatusCode::NOT_FOUND)?;
                check_client_access(md, presented_token, presented_principal)?;
            }
            Ok(opt_md)
        })?
        .trust_unchecked::<Replay, _>(reason!(r#"
Metadata fields (status, policy_ref, client.ref, ...) are stable
across the session lifetime; a stale snapshot answers the same
values the current snapshot would. AEAD-binding to session_id
(AAD) prevents substitution with another session's metadata. For
endpoints that pair this read with another list (e.g. disclosures),
the freshness of that list is checked by its own AuthN trust gate
against metadata's running hash.
        "#))
        .into_inner()
        .ok_or_else(|| {
            // Predicate already rejected None via NOT_FOUND, so this
            // arm is defensive against future-edit drift only.
            eprintln!("trust_metadata: metadata unexpectedly None");
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

/// Client-side AuthZ predicate body — verifies both layers of the
/// access gate against the session's sealed metadata:
///
///   1. `client_session_token`: SHA-256 of the presented bearer must
///      match `metadata.client.access.session_token_hash`. Defends
///      against host-malice + intra-tenant insider.
///   2. `principal`: the auth verdict's principal must equal the one
///      pinned at create-time. Defends against cross-tenant attacks
///      via stolen credentials.
///
/// Returned errors:
///   * 500 — malformed metadata (`client` / `access` block absent;
///     TEE-side invariant violation, not a runtime auth failure).
///   * 404 — token or principal mismatch (uniform reject — don't
///     leak session-existence info to wrong principals).
///
/// Used as the predicate inside `.trust::<AuthZ>(...)` on every
/// client-side read endpoint so the AuthZ scope on metadata is
/// **physically discharged by this check**, not blanket-trusted.
pub(super) fn check_client_access(
    metadata: &SessionMetadata,
    presented_token: &[u8],
    presented_principal: &Option<String>,
) -> Result<(), StatusCode> {
    let access = metadata
        .client
        .as_ref()
        .and_then(|c| c.access.as_ref())
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    verify_session_token_hash(presented_token, &access.session_token_hash)?;
    if access.principal != *presented_principal {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(())
}

/// SHA-256 the presented bytes and compare constant-time against the
/// stored hash. Mismatch → 404 (uniform with other auth failures —
/// don't leak which-session info to attacker probing random tokens).
fn verify_session_token_hash(
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
/// host-side Auth service. On success injects `Principal(principal)`
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
credential is valid or substitute a different principal.
Neither escalates: /sessions needs client_policy_key (validated against
the policy's manifest validator annotation, secret held by the
legitimate client) — without it the create returns 422 and
nothing is persisted.
        "#))
        .trust_unchecked::<AuthZ, _>(reason!(r#"
The AuthVerdict IS the authorisation answer for this request —
there is no second access decision to gate on top of it.
        "#))
        .trust_unchecked::<Replay, _>(reason!(r#"
Stale verdict (yesterday's answer for today's request — e.g.
accepting a since-revoked credential) caps at the same place:
spurious denial or a stalled caller who can't progress past
the client_policy_key validator check. No data leak path.
        "#))
        .into_inner();
    let principal = match verdict {
        AuthVerdict::Allowed { principal } => principal.map(|p| p.0),
        AuthVerdict::Unauthenticated => return Err(StatusCode::UNAUTHORIZED),
        AuthVerdict::PermissionDenied => return Err(StatusCode::FORBIDDEN),
    };
    req.extensions_mut().insert(Principal(principal));

    Ok(next.run(req).await)
}
