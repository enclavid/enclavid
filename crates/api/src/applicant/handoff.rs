//! Carrying a session to another device: the page that holds it asks for a
//! hand-over, shows it to the other device as a code, and the other device takes
//! the session over with a key of its own.
//!
//! The device that takes a session never adopts a key it was given. A key from
//! outside the page would be a key someone else may hold: the consumer writes
//! the applicant's link and could put one there, then read every consent screen
//! the applicant is shown, before the applicant accepts it. So the taker brings
//! its own key, and the take locks the session's data keys under that key alone:
//! whoever held the session before — the applicant's other device, or whoever
//! showed the code — is shut out by it. The take adds a fresh data key too,
//! which everything is sealed under from then on, so a key that held the
//! session before reaches only what was sealed while it held it — even with
//! every copy of the record the host kept, and the seal key besides.
//!
//! A hand-over is good against the one lock it was made against: once that lock
//! is replaced — by a take, its own page's included, or a reset and a claim —
//! the hand-over opens nothing, even should the lock come back under the same
//! key. So the page that showed a code takes its own session over when the code
//! is put away, and every code it showed dies with that.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, get, post};
use base64ct::{Base64UrlUnpadded, Encoding};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};

use enclavid_boundary::{AuthZ, Covert, Replay, reason};
use session_types::{SessionMetadata, SessionStatus};
use storage_client::boundary::Storage;
use storage_client::{
    Handoff, Metadata, MetadataOp, SealedState, SetMetadata, SetState, StateBinding, StateOp,
    StoreError, encode_padded, lock_data_keys, lock_digest, unlock_data_keys,
};

use crate::state::AppState;

use super::auth::CallerKey;

/// How long a hand-over may be taken after it was made: long enough to point a
/// phone at a screen, short enough that a photo of the code goes stale.
const HANDOFF_SECS: u64 = 10 * 60;

/// A hand-over, for the page to carry to the other device.
#[derive(Serialize)]
pub struct HandoffResponse {
    /// Sealed by this side, base64url: opened by nothing but this side, and good
    /// for one take.
    pub handoff: String,
}

/// What the other device takes a session over with.
#[derive(Deserialize)]
pub struct TakeoverRequest {
    /// The hand-over, as [`HandoffResponse`] gave it.
    pub handoff: String,
}

/// Route factory. Auth attached at router level — see `applicant::router`.
pub(super) fn post_handoff() -> MethodRouter<Arc<AppState>> {
    post(handoff)
}

/// Route factory. Auth attached at router level — see `applicant::router`.
pub(super) fn post_takeover() -> MethodRouter<Arc<AppState>> {
    post(takeover)
}

/// Route factory. Auth attached at router level — see `applicant::router`.
pub(super) fn get_held() -> MethodRouter<Arc<AppState>> {
    get(held)
}

/// GET /api/v1/sessions/{id}/held — whether the caller's key still holds the
/// session: 204 when it opens the session's lock, 403 when it does not, 409
/// when no applicant holds the session. Reads the metadata alone and never
/// claims a session — unlike `/connect`, which claims one no applicant holds —
/// so a page that showed a code can watch with it for the session being taken.
///
/// A 403 here means the key, and nothing else: a page drops the key it holds on
/// one. So a record that does not open — what the host gets by altering it — is
/// a 500, which says nothing about the key.
async fn held(
    Path(session_id): Path<String>,
    State(state): State<Arc<AppState>>,
    CallerKey(applicant_key): CallerKey,
) -> StatusCode {
    let ((metadata,), _version) = match state.session_store.read(&session_id, (Metadata,)).await {
        Ok(read) => read,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    };
    let Some(metadata) = metadata
        .trust(reason!(
            AuthZ::Matched,
            "the caller's key must open the lock this metadata keeps the data key in, below"
        ))
        .trust_accept_risk(reason!(
            Replay::AcceptedRisk,
            "answered with a status and nothing else: a record put back from before can \
             make an older key look like it holds the session, which a round under it \
             then finds is not so"
        ))
        .into_inner()
    else {
        return StatusCode::NOT_FOUND;
    };
    let Some(lock) = metadata.data_key_lock.as_deref() else {
        return StatusCode::CONFLICT;
    };
    match unlock_data_keys(&session_id, lock, applicant_key.expose_secret()) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::FORBIDDEN,
    }
}

/// POST /api/v1/sessions/{id}/handoff — a hand-over of the session: the
/// caller's key and the lock it opens, sealed by this side with the time it may
/// be taken until. Only a key that opens the session gets one, and only while
/// an applicant holds a running session: a hand-over never claims a session.
/// 410 once the lock holds all the keys it can: a take would have no key to add,
/// so the session is handed over no more, and no code is made that no take
/// could end.
async fn handoff(
    Path(session_id): Path<String>,
    State(state): State<Arc<AppState>>,
    CallerKey(applicant_key): CallerKey,
) -> Result<Json<HandoffResponse>, StatusCode> {
    let ((metadata,), _version) = state
        .session_store
        .read(&session_id, (Metadata,))
        .await
        .map_err(refused)?;
    let metadata = metadata
        .trust(reason!(
            AuthZ::Matched,
            "the caller's key must open the lock this metadata keeps the data key in, below"
        ))
        .trust_accept_risk(reason!(
            Replay::AcceptedRisk,
            "a record put back from before holds an older lock, which an older key opens; \
             taking the hand-over opens the lock the record holds then, and writes under \
             the version it read"
        ))
        .into_inner()
        .ok_or(StatusCode::NOT_FOUND)?;
    let lock = held_lock(&metadata)?;
    let keys = unlock_data_keys(&session_id, lock, applicant_key.expose_secret())
        .map_err(|_| StatusCode::FORBIDDEN)?;
    if keys.is_full() {
        return Err(StatusCode::GONE);
    }

    let sealed = state
        .session_store
        .seal_handoff(
            &session_id,
            &Handoff {
                key: SecretBox::new(Box::new(applicant_key.expose_secret().clone())),
                lock: lock_digest(lock),
                until_unix_secs: now().saturating_add(HANDOFF_SECS),
            },
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(HandoffResponse {
        handoff: Base64UrlUnpadded::encode_string(&sealed),
    }))
}

/// POST /api/v1/sessions/{id}/takeover — take the session over with the
/// caller's key: the hand-over's key opens the lock, and the data keys, with a
/// fresh one beside them, are locked under the caller's key in its place. The
/// state is written again under the fresh key, beside the new lock it is bound
/// to; the media stay as they are, each under the key it was sealed under. 204
/// once it lands, after which the hand-over — and every other made against the
/// replaced lock — opens nothing; 403 for a hand-over that is not this
/// session's, has expired, or whose lock is gone; 409 for a session whose lock
/// holds all the keys it can.
async fn takeover(
    Path(session_id): Path<String>,
    State(state): State<Arc<AppState>>,
    CallerKey(new_key): CallerKey,
    Json(request): Json<TakeoverRequest>,
) -> Result<StatusCode, StatusCode> {
    let sealed_handoff =
        Base64UrlUnpadded::decode_vec(&request.handoff).map_err(|_| StatusCode::FORBIDDEN)?;
    let handed = state
        .session_store
        .open_handoff(&session_id, &sealed_handoff)
        .map_err(|_| StatusCode::FORBIDDEN)?;
    if now() > handed.until_unix_secs {
        return Err(StatusCode::FORBIDDEN);
    }

    let ((metadata, sealed_state), version) = state
        .session_store
        .read(&session_id, (Metadata, SealedState))
        .await
        .map_err(refused)?;
    let metadata = metadata
        .trust(reason!(
            AuthZ::Matched,
            "the hand-over's key must open the lock this metadata keeps the data key in, below"
        ))
        .trust_accept_risk(reason!(
            Replay::AcceptedRisk,
            "a session that moved under this read refuses the write below, which names the \
             version read with it; a whole record put back from before passes that check, \
             the rollback a round's load accepts too"
        ))
        .into_inner()
        .ok_or(StatusCode::NOT_FOUND)?;
    let lock = held_lock(&metadata)?;
    // The lock the hand-over was made against, and no other: one taken since,
    // or dropped by a reset and made again, leaves the hand-over dead even when
    // the key it carries holds the session anew.
    if lock_digest(lock) != handed.lock {
        return Err(StatusCode::FORBIDDEN);
    }
    let data_keys = unlock_data_keys(&session_id, lock, handed.key.expose_secret())
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let session_state = state
        .session_store
        .open_state(&session_id, sealed_state, &metadata, data_keys.current())
        .map_err(refused)?
        .trust(reason!(
            Replay::Fresh,
            "written back below under the version read with it, so a stale one is refused"
        ))
        .into_inner()
        .ok_or(StatusCode::CONFLICT)?;
    // Fed straight back as the write's CAS token below: it can only make the
    // write refuse.
    let version = version
        .trust(reason!(
            Replay::Harmless,
            "a stale value can only make the write refuse"
        ))
        .into_inner();

    // From the take on, everything is sealed under a key the session's earlier
    // holders never had: theirs opens only what was sealed while they held it.
    // A session whose lock can hold no more keys takes no more takes.
    let taken_keys = data_keys.and_another().ok_or(StatusCode::CONFLICT)?;
    let mut taken = metadata;
    // A key no AEAD takes — not 32 bytes — can lock nothing.
    taken.data_key_lock = Some(
        lock_data_keys(&session_id, &taken_keys, new_key.expose_secret())
            .map_err(|_| StatusCode::FORBIDDEN)?,
    );
    let set_state = SetState {
        state: Storage::expose_builder::<StateOp, _>(&session_state)
            .vouch_with(Covert::Transformed, encode_padded)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        data_key: taken_keys.current(),
        binding: StateBinding::of(&taken),
    };
    let set_metadata = SetMetadata(Storage::expose_builder::<MetadataOp, _>(&taken).vouch(
        reason!(
            Covert::AlreadyHeld,
            "sealed under tee_seal_key; a lock is one size however many keys it holds, \
             so one replacing another leaves the metadata's size as it was"
        ),
    ));
    let ops = state
        .session_store
        .seal(&session_id, &[&set_metadata, &set_state])
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .vouch(reason!(
            Covert::Bounded,
            "a fixed pair, so the count says only that a take happened"
        ));
    match state.session_store.write(Some(version), ops).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        // A round, or another take, landed since the read: nothing was taken.
        Err(StoreError::VersionMismatch) => Err(StatusCode::CONFLICT),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// The lock of a running session an applicant holds; 409 for any other — one
/// no applicant holds yet has nothing to hand over, and one that ended takes
/// no hand.
fn held_lock(metadata: &SessionMetadata) -> Result<&[u8], StatusCode> {
    if metadata.status != SessionStatus::Running {
        return Err(StatusCode::CONFLICT);
    }
    metadata
        .data_key_lock
        .as_deref()
        .ok_or(StatusCode::CONFLICT)
}

/// A store failure as the answer to the request: a seal that does not open is
/// what a host gets by altering the record, read as a key that opens nothing
/// (403); anything else is a real 500.
fn refused(e: StoreError) -> StatusCode {
    match e {
        StoreError::Crypto(_) => StatusCode::FORBIDDEN,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
