use std::str::FromStr;
use std::sync::Arc;

use age::x25519::Identity;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, post};
use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};

use enclavid_host_bridge::{
    AuthN, AuthZ, BridgeError, Metadata, Replay, SessionStatus, SetMetadata, SetStatus, Status,
    WriteField, reason,
};

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
    let ((status_opt, metadata_opt), version) = state
        .session_store
        .read(&session_id, (Status, Metadata))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let status_opt = status_opt
        .trust_unchecked::<AuthN, _>(reason!(r#"
Status is host plaintext, used here for routing only. The actual
security boundary is the AEAD-verified workspace check on metadata
below — a lying status byte changes which branch we take, not
who can see what.
        "#))
        .trust_unchecked::<Replay, _>(reason!(r#"
Stale status routes us into /init re-run, which converges via
host-side version-CAS at write time — either we hit the
idempotent-Running branch or the PendingInit flow, both safe.
        "#))
        .into_inner();

    // Metadata: AuthN cleared at decode (AEAD). AuthZ checked inline:
    // metadata.workspace_id must match the authenticated caller's
    // workspace, otherwise we collapse the result to a NOT_FOUND-shaped
    // error so we don't leak existence of other workspaces' sessions.
    let metadata_opt = metadata_opt
        .trust::<AuthZ, _, _, _>(|m| match m {
            Some(m) if m.workspace_id == workspace_id => Ok(()),
            Some(_) => Err(StatusCode::CONFLICT),
            None => Err(StatusCode::NOT_FOUND),
        })?
        .trust_unchecked::<Replay, _>(reason!(r#"
/init is idempotent w.r.t. stale metadata — Running branch
returns existing d_*/d_plain, PendingInit branch re-runs init
which CAS-fails on stomped version and falls into the idempotent
path on re-read.
        "#))
        .into_inner();

    let version = version
        .trust_unchecked::<AuthN, _>(reason!(r#"
Version is a CAS token only. A lying host either fails our next
write (DoS) or stomps a concurrent winner (UX regression). No
data leak path opens.
        "#))
        .trust_unchecked::<Replay, _>(reason!(r#"
Staleness on the version manifests as CAS mismatch at write
time — we fall through into the idempotent re-read path, no
unsafe state lands.
        "#))
        .into_inner();

    let metadata_some = metadata_opt.expect("AuthZ predicate validated Some");

    let mut metadata = match status_opt {
        // Already initialized. Treat as idempotent success: return
        // the same d_enc/d_plain a fresh /init would produce. Covers
        // legitimate client retry-after-success.
        Some(SessionStatus::Running) => {
            return Ok(Json(InitSessionResponse {
                status: "running",
                d_enc: metadata_some.d_enc,
                d_plain: metadata_some.d_plain,
            }));
        }
        // The legitimate path: PendingInit, matching workspace.
        Some(SessionStatus::PendingInit) => metadata_some,
        // Wrong status (FailedInit / Expired / Completed).
        Some(_) => return Err(StatusCode::CONFLICT),
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Pull the ephemeral identity from in-memory cache. If gone (TTL
    // elapsed or pod restart), the session is unrecoverable — transition
    // to Expired so subsequent calls report consistently.
    let identity = match state.ephemeral_identities.get(&session_id).await {
        Some(id) => id,
        None => {
            // Best-effort terminal-state write. Pass the expected
            // version so we don't stomp a concurrent winner; on
            // version mismatch we just give up — best-effort.
            let ops: &[&dyn WriteField] = &[&SetStatus(SessionStatus::Expired)];
            let _ = state
                .session_store
                .write(&session_id, Some(version), ops)
                .await;
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
            let ops: &[&dyn WriteField] = &[&SetStatus(SessionStatus::FailedInit)];
            let _ = state
                .session_store
                .write(&session_id, Some(version), ops)
                .await;
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
            let ops: &[&dyn WriteField] = &[&SetStatus(SessionStatus::FailedInit)];
            let _ = state
                .session_store
                .write(&session_id, Some(version), ops)
                .await;
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
            let ops: &[&dyn WriteField] = &[&SetStatus(SessionStatus::FailedInit)];
            let _ = state
                .session_store
                .write(&session_id, Some(version), ops)
                .await;
            return Err(StatusCode::UNPROCESSABLE_ENTITY);
        }
    };
    state.policies.insert(session_id.clone(), component).await;

    // Transition to Running. Persist d_enc/d_plain into metadata for
    // audit; drop the ephemeral identity from the cache so a leaked
    // process dump can't revive past wrapped blobs.
    metadata.d_enc = decrypted.d_enc.clone();
    metadata.d_plain = decrypted.d_plain.clone();
    // Atomic update with version check: host applies only if the
    // session's version is still `version`. VersionMismatch means
    // a concurrent /init beat us (race) or we're a sequential
    // retry — either way, fall back to the idempotent path: re-read,
    // and if the session is now Running for our workspace, return
    // the existing d_*/d_plain instead of erroring.
    let ops: &[&dyn WriteField] = &[
        &SetMetadata(&metadata),
        &SetStatus(SessionStatus::Running),
    ];
    match state
        .session_store
        .write(&session_id, Some(version), ops)
        .await
    {
        Ok(_) => {}
        Err(BridgeError::VersionMismatch) => {
            let ((status_opt, metadata_opt), _version) = state
                .session_store
                .read(&session_id, (Status, Metadata))
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let status_opt = status_opt
                .trust_unchecked::<AuthN, _>(reason!(r#"
Fallback re-read: status is used for routing only here, same
intent as the initial read up top.
                "#))
                .trust_unchecked::<Replay, _>(reason!(r#"
Fallback re-read IS the convergence path on detected staleness —
we accept whatever the host now reports and let the match below
decide.
                "#))
                .into_inner();
            // Same AuthZ pattern as the initial read above: the
            // workspace check is the predicate, not a downstream
            // match arm. Anything that doesn't match collapses to
            // CONFLICT — we don't leak existence of other
            // workspaces' sessions and we don't accept a host's
            // attempt to substitute a different workspace's
            // metadata on the fallback path.
            let metadata_some = metadata_opt
                .trust::<AuthZ, _, _, _>(|m| match m {
                    Some(m) if m.workspace_id == workspace_id => Ok(()),
                    _ => Err(StatusCode::CONFLICT),
                })?
                .trust_unchecked::<Replay, _>(reason!(r#"
Fallback accepts whatever metadata host actually committed for
our workspace; downstream match handles the status.
                "#))
                .into_inner()
                .expect("AuthZ predicate validated Some");
            return match status_opt {
                Some(SessionStatus::Running) => Ok(Json(InitSessionResponse {
                    status: "running",
                    d_enc: metadata_some.d_enc,
                    d_plain: metadata_some.d_plain,
                })),
                _ => Err(StatusCode::CONFLICT),
            };
        }
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
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
