use std::str::FromStr;
use std::sync::Arc;

use age::x25519::Identity;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, post};
use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};

use enclavid_session_store::SessionStatus;

use crate::client_state::ClientState;
use crate::policy_pull;

use super::auth::Workspace;

#[derive(Deserialize)]
pub struct InitSessionRequest {
    /// Base64-encoded age envelope: client wraps `K_client` (their
    /// `AGE-SECRET-KEY-1...` string, the secret half of the X25519
    /// identity) to the session's ephemeral_pubkey returned at create.
    pub wrapped_k_client: String,
}

#[derive(Serialize)]
pub struct InitSessionResponse {
    pub status: &'static str,
    pub d_enc: String,
    pub d_plain: String,
}

/// Route factory: bare `post(handler)` MethodRouter. Auth attached at
/// router level via `.layer(auth(op))` — see `client::router`.
pub(super) fn post_init() -> MethodRouter<Arc<ClientState>> {
    post(init)
}

async fn init(
    State(state): State<Arc<ClientState>>,
    Workspace(workspace_id): Workspace,
    Path(session_id): Path<String>,
    Json(body): Json<InitSessionRequest>,
) -> Result<Json<InitSessionResponse>, StatusCode> {
    // Trust gates: tenant boundary + state machine. The host is not
    // trusted on metadata content — these checks are what makes the
    // record usable downstream.
    let mut metadata = state
        .metadata_store
        .get(&session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?
        .trust(|m| {
            // Pretend the session doesn't exist rather than leaking
            // that one does for another workspace.
            if m.workspace_id != workspace_id {
                return Err(StatusCode::NOT_FOUND);
            }
            if m.status != SessionStatus::PendingInit as i32 {
                return Err(StatusCode::CONFLICT);
            }
            Ok(())
        })?;

    // Pull the ephemeral identity from in-memory cache. If gone (TTL
    // elapsed or pod restart), the session is unrecoverable — transition
    // to Expired so subsequent calls report consistently.
    let identity = match state.ephemeral_identities.get(&session_id).await {
        Some(id) => id,
        None => {
            metadata.status = SessionStatus::Expired as i32;
            let _ = state.metadata_store.put(&session_id, &metadata).await;
            return Err(StatusCode::GONE);
        }
    };

    // Unwrap K_client. Decode → age decrypt → parse as Identity. Failure
    // at any step => FailedInit (domain failure, distinct from transport
    // / 5xx errors).
    let wrapped =
        Base64::decode_vec(&body.wrapped_k_client).map_err(|_| StatusCode::BAD_REQUEST)?;
    let k_client = match unwrap_k_client(&wrapped, &identity) {
        Ok(k) => k,
        Err(_) => {
            metadata.status = SessionStatus::FailedInit as i32;
            let _ = state.metadata_store.put(&session_id, &metadata).await;
            return Err(StatusCode::UNPROCESSABLE_ENTITY);
        }
    };

    // Pull and decrypt the policy artifact. Digests are re-verified
    // inside `pull_and_decrypt`; the host is not trusted on content.
    let decrypted = match policy_pull::pull_and_decrypt(
        &state.registry,
        &metadata.workspace_id,
        &metadata.policy_name,
        &metadata.policy_digest,
        &k_client,
    )
    .await
    {
        Ok(d) => d,
        Err(_) => {
            metadata.status = SessionStatus::FailedInit as i32;
            let _ = state.metadata_store.put(&session_id, &metadata).await;
            return Err(StatusCode::UNPROCESSABLE_ENTITY);
        }
    };

    // Compile the decrypted wasm into a `Component` and stash under
    // session_id. The applicant API reads from the same cache on /input.
    // A compile error here is a real problem (wasm corrupted or built
    // against an incompatible runtime version) — surface as FailedInit
    // so the client can rebuild and retry.
    let component = match state.runner.compile(&decrypted.wasm_bytes) {
        Ok(c) => Arc::new(c),
        Err(_) => {
            metadata.status = SessionStatus::FailedInit as i32;
            let _ = state.metadata_store.put(&session_id, &metadata).await;
            return Err(StatusCode::UNPROCESSABLE_ENTITY);
        }
    };
    state.policies.insert(session_id.clone(), component).await;

    // Transition to Running. Persist d_enc/d_plain for audit; drop the
    // ephemeral identity from the cache so a leaked process dump can't
    // revive past wrapped blobs.
    metadata.status = SessionStatus::Running as i32;
    metadata.d_enc = decrypted.d_enc.clone();
    metadata.d_plain = decrypted.d_plain.clone();
    state
        .metadata_store
        .put(&session_id, &metadata)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state.ephemeral_identities.invalidate(&session_id).await;

    Ok(Json(InitSessionResponse {
        status: "running",
        d_enc: decrypted.d_enc,
        d_plain: decrypted.d_plain,
    }))
}

/// Decrypt a wrapped K_client envelope. The plaintext is the
/// `AGE-SECRET-KEY-1...` string the client generated via `enclavid keygen`.
/// All failure modes collapse to a unit error — caller treats them
/// uniformly as FailedInit. We deliberately do not surface details: an
/// attacker probing with garbage payloads should not learn whether the
/// envelope was malformed, the recipient was wrong, or the secret didn't
/// parse as an identity.
fn unwrap_k_client(wrapped: &[u8], ephemeral: &Identity) -> Result<Identity, ()> {
    use std::io::Read;
    let decryptor = age::Decryptor::new(wrapped).map_err(|_| ())?;
    let mut reader = decryptor
        .decrypt(std::iter::once(ephemeral as &dyn age::Identity))
        .map_err(|_| ())?;
    let mut out = Vec::new();
    reader.read_to_end(&mut out).map_err(|_| ())?;
    let s = std::str::from_utf8(&out).map_err(|_| ())?.trim();
    Identity::from_str(s).map_err(|_| ())
}
