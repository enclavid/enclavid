use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, get};
use serde::Serialize;

use hatch_client::{Metadata, SessionStatus, public_session_id};

use crate::client_state::ClientState;
use crate::dto::{self, ResolvedPolicyView};

use super::auth::{Principal, SessionToken, trust_metadata};

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
    Principal(presented_principal): Principal,
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
    let ((metadata_untrusted,), _version) = state
        .session_store
        .read(public_session_id(&session_id), (Metadata,))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Discharge AuthZ (token + principal) and Replay scopes via the
    // shared helper; returns verified `SessionMetadata`.
    let metadata = trust_metadata(
        metadata_untrusted,
        &presented_token,
        &presented_principal,
    )?;

    // `metadata.client` is `Option<Client>` purely because of proto3
    // semantics: sub-messages are always presence-tracked at the
    // wire level (proto3 has no `required` for messages). TEE always
    // populates `client` at session create, and `check_client_access`
    // inside the trust predicate above already returns 500 on the
    // malformed-None path — so None here is unreachable in practice.
    // We still `.ok_or` (not `.expect`) to fail gracefully instead
    // of panicking; aborts at this layer would corrupt the HTTP
    // response and add noise to logs without operational benefit.
    let client = metadata.client.ok_or_else(|| {
        eprintln!(
            "client/session: metadata.client unexpectedly None for {session_id} \
             — TEE invariant violation (always populated at create)",
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

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
        client_ref: if client.r#ref.is_empty() {
            None
        } else {
            Some(client.r#ref)
        },
        disclosures: metadata.disclosure_count,
        created_at: metadata.created_at,
    }))
}
