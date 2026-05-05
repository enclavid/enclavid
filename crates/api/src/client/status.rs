use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, get};
use serde::Serialize;

use enclavid_host_bridge::{AuthZ, Metadata, Replay, SessionStatus, reason};

use crate::client_state::ClientState;

use super::auth::Workspace;

#[derive(Serialize)]
pub struct ResolvedPolicyView {
    pub name: String,
    pub digest: String,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub session_id: String,
    pub status: &'static str,
    pub policy: ResolvedPolicyView,
    /// The client's own reconciliation key, echoed back as supplied at
    /// session create. Skipped when missing so the JSON shape stays
    /// minimal for clients who never set it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
    /// True if the engine has emitted at least one disclosure entry
    /// for this session. Mirrors the `has_shared_data` flag in the
    /// future webhook payload — clients use it to decide whether
    /// `/shared-data` will return anything.
    pub has_shared_data: bool,
    /// Unix seconds at session create time. Surfaced for ops /
    /// observability (age, latency); not a security signal.
    pub created_at: u64,
}

/// Route factory: bare `get(handler)` MethodRouter. Auth attached at
/// router level via `.layer(auth(op))` — see `client::router`.
pub(super) fn get_status() -> MethodRouter<Arc<ClientState>> {
    get(status)
}

async fn status(
    State(state): State<Arc<ClientState>>,
    Workspace(workspace_id): Workspace,
    Path(session_id): Path<String>,
) -> Result<Json<StatusResponse>, StatusCode> {
    // Read encrypted metadata only. Status comes from
    // `metadata.status` (TEE-trust copy, AEAD-bound to session_id).
    // Disclosure count comes from `metadata.disclosure_count`,
    // which the persister maintains atomically with each
    // AppendDisclosure write — so we never need to pull the actual
    // disclosure list (entries can be tens of KB) just to compute a
    // boolean.
    let ((metadata_opt,), _version) = state
        .session_store
        .read(&session_id, (Metadata,))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Metadata: AuthN cleared at decode (AEAD). AuthZ checked
    // inline — workspace_id match is the whole point of fetching
    // metadata here, and absent or wrong-workspace metadata
    // collapses to 404 so we don't leak existence of other
    // workspaces' sessions.
    let metadata = metadata_opt
        .trust::<AuthZ, _, _, _>(|m| match m {
            Some(m) if m.workspace_id == workspace_id => Ok(()),
            _ => Err(StatusCode::NOT_FOUND),
        })?
        .trust_unchecked::<Replay, _>(reason!(r#"
Stale metadata only affects which historical workspace_id we
check against. AEAD-binding to session_id ensures we're never
comparing a different session's metadata.
        "#))
        .into_inner()
        .expect("AuthZ predicate validated Some");

    let has_shared_data = metadata.disclosure_count > 0;

    let status = SessionStatus::try_from(metadata.status)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(StatusResponse {
        session_id,
        status: status_label(status),
        policy: ResolvedPolicyView {
            name: metadata.policy_name,
            digest: metadata.policy_digest,
        },
        external_ref: if metadata.external_ref.is_empty() {
            None
        } else {
            Some(metadata.external_ref)
        },
        has_shared_data,
        created_at: metadata.created_at,
    }))
}

fn status_label(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::Running => "running",
        SessionStatus::Completed => "completed",
        SessionStatus::Failed => "failed",
        SessionStatus::Expired => "expired",
        SessionStatus::Unspecified => "unspecified",
    }
}
