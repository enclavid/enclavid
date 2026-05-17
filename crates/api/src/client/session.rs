use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, get};
use serde::Serialize;

use enclavid_host_bridge::{AuthZ, Metadata, Replay, SessionStatus, reason};

use crate::client_state::ClientState;
use crate::dto;

use super::auth::{SessionToken, verify_session_token};

#[derive(Serialize)]
pub struct ResolvedPolicyView {
    /// Full pinned OCI reference from session metadata.
    pub reference: String,
    /// Convenience: digest substring extracted from `reference`.
    pub digest: String,
}

#[derive(Serialize)]
pub struct SessionView {
    pub session_id: String,
    /// Lifecycle label, serialized as snake_case
    /// (`"running"`, `"completed"`, ...) via the shared
    /// `dto::SessionStatusDef` remote definition.
    #[serde(with = "dto::SessionStatusDef")]
    pub status: SessionStatus,
    pub policy: ResolvedPolicyView,
    /// The client's own reconciliation key, echoed back as supplied at
    /// session create. Skipped when missing so the JSON shape stays
    /// minimal for clients who never set it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ref: Option<String>,
    /// Number of disclosure entries the engine has appended for this
    /// session. Mirrors the same field in the future webhook payload
    /// so client SDKs can deserialize both shapes with one struct.
    /// Counter rather than bool to support delta-detection at the
    /// webhook receiver (`new_count - last_seen_count` = how many new
    /// disclosures arrived since the last poll/notification).
    pub disclosures: u64,
    /// Unix seconds at session create time. Surfaced for ops /
    /// observability (age, latency); not a security signal.
    pub created_at: u64,
}

/// Route factory: bare `get(handler)` MethodRouter. Auth attached at
/// router level via `.layer(auth(op))` — see `client::router`.
pub(super) fn get_session() -> MethodRouter<Arc<ClientState>> {
    get(read)
}

async fn read(
    State(state): State<Arc<ClientState>>,
    SessionToken(presented_token): SessionToken,
    Path(session_id): Path<String>,
) -> Result<Json<SessionView>, StatusCode> {
    // Read encrypted metadata. AEAD-bound to session_id so the host
    // can't substitute another session's blob. Everything we surface
    // here (status, policy, count, created_at) lives inside this
    // single pull — the persister keeps `disclosure_count` and the
    // running `disclosure_hash` chain atomic with each AppendDisclosure
    // write, so we never need to pull the actual disclosure list
    // (entries can be tens of KB) just to compute a counter.
    let ((metadata_opt,), _version) = state
        .session_store
        .read(&session_id, (Metadata,))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Metadata: AuthN cleared at decode (AEAD). AuthZ enforced via
    // `client_session_token` — crypto-bound per-session capability the
    // client supplied at create. Host can't forge it (TLS-protected
    // from host view), so this closes the host-lies-in-verdict hole
    // that the previous `host_ref == verdict.host_ref` check could
    // not cover. Absent metadata or wrong token collapses to 404 so
    // we don't leak session-existence to wrong tenants. Host-side
    // gate (revocation, rate-limit) runs ahead of TEE via the auth
    // middleware on the route.
    let metadata = metadata_opt
        .trust_unchecked::<AuthZ, _>(reason!(r#"
Token capability check is below this `trust_unchecked` — once
verify_session_token() passes, the caller has proven session
ownership cryptographically. Host's auth middleware additionally
validated the Authorization JWT before invoking the handler.
        "#))
        .trust_unchecked::<Replay, _>(reason!(r#"
Metadata fields (status, policy_ref, client_ref, ...) are
stable across the session lifetime; a stale snapshot answers
the same value the current snapshot would. AEAD-binding to
session_id (AAD) prevents substitution with another session's
metadata.
        "#))
        .into_inner()
        .ok_or(StatusCode::NOT_FOUND)?;

    verify_session_token(&presented_token, &metadata.client_session_token_hash)?;

    let status = SessionStatus::try_from(metadata.status)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let digest = crate::policy_pull::split_pinned_ref(&metadata.policy_ref)
        .map(|(_, d)| d.to_string())
        .unwrap_or_default();

    Ok(Json(SessionView {
        session_id,
        status,
        policy: ResolvedPolicyView {
            reference: metadata.policy_ref,
            digest,
        },
        client_ref: if metadata.client_ref.is_empty() {
            None
        } else {
            Some(metadata.client_ref)
        },
        disclosures: metadata.disclosure_count,
        created_at: metadata.created_at,
    }))
}
