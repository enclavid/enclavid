use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, get};
use base64ct::{Base64, Encoding};
use serde::Serialize;

use enclavid_host_bridge::{AuthN, AuthZ, Disclosure, Metadata, Replay, reason};

use crate::client_state::ClientState;
use crate::disclosure_hash;

use super::auth::Workspace;

#[derive(Serialize)]
pub struct DisclosuresResponse {
    /// Each entry is one age-encrypted record sealed to the
    /// workspace's `client_disclosure_pubkey` (provided at session
    /// create). Base64-standard for JSON wire safety; client decodes
    /// then opens with the matching age identity. Order is append
    /// order — index `i` is the i-th disclosure the engine emitted.
    pub items: Vec<String>,
}

/// Route factory: bare `get(handler)` MethodRouter. Auth attached at
/// router level via `.layer(auth(op))` — see `client::router`.
pub(super) fn get_disclosures() -> MethodRouter<Arc<ClientState>> {
    get(read)
}

async fn read(
    State(state): State<Arc<ClientState>>,
    Workspace(workspace_id): Workspace,
    Path(session_id): Path<String>,
) -> Result<Json<DisclosuresResponse>, StatusCode> {
    // Pull metadata + disclosure list in a single Read RPC. Metadata
    // is the workspace-ownership gate AND the source of truth for the
    // running `disclosure_hash` chain — we recompute the chain over
    // the host-served list and compare, so any host fabrication /
    // truncation / reorder / swap-with-other-list shows up as a hash
    // mismatch.
    let ((metadata_opt, disclosures), _version) = state
        .session_store
        .read(&session_id, (Metadata, Disclosure))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // AuthZ via metadata: absent or wrong-workspace collapses to 404
    // so we don't leak existence of other workspaces' sessions.
    let metadata = metadata_opt
        .trust::<AuthZ, _, _, _>(|m| match m {
            Some(m) if m.workspace_id == workspace_id => Ok(()),
            _ => Err(StatusCode::NOT_FOUND),
        })?
        .trust_unchecked::<Replay, _>(reason!(r#"
Workspace_id is set at /sessions create and never changes, so
a stale metadata snapshot still answers the workspace-ownership
question correctly. AEAD-binding to session_id (AAD) prevents
substitution with another session's metadata.
        "#))
        .into_inner()
        .expect("AuthZ predicate validated Some");

    // AuthN on the list is discharged by recomputing the
    // `disclosure_hash` chain and comparing to the AEAD-sealed copy
    // in metadata. Any host substitution at the byte level (forge,
    // reorder, swap with another list, truncate) changes the chain
    // → mismatch → we refuse the response. 500 keeps the failure
    // path consistent with other host misbehaviours here.
    let items = disclosures
        .trust::<AuthN, _, _, _>(|items| {
            let expected = disclosure_hash::fold(&session_id, items);
            if expected == metadata.disclosure_hash {
                Ok(())
            } else {
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        })?
        .trust_unchecked::<Replay, _>(reason!(r#"
Two replay angles to consider:
  * Stale list against current metadata's disclosure_hash —
    caught by the chain check above (mismatch → 500).
  * Full-snapshot rollback (host serves a coherent older
    metadata + list pair) — chain still validates; consumer
    sees older state. Stateless-TEE limitation; requires an
    external freshness oracle (TPM monotonic counter /
    append-only log) to close.
        "#))
        .into_inner();

    Ok(Json(DisclosuresResponse {
        items: items.iter().map(|b| Base64::encode_string(b)).collect(),
    }))
}
