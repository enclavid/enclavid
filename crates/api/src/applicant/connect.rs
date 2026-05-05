use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use tokio::sync::Mutex;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, post};
use secrecy::ExposeSecret;

use enclavid_host_bridge::{AuthN, Replay, State as StateField, reason};

use crate::state::AppState;

use super::auth::CallerKey;
use super::persister::SessionPersister;
use super::shared::{build_resources, fetch_metadata, lookup_policy, parse_args};
use super::views::{progress_from, SessionProgress};

/// Route factory: bare `post(handler)` MethodRouter. Auth attached at
/// router level via `.layer(auth())` — see `applicant::router`.
pub(super) fn post_connect() -> MethodRouter<Arc<AppState>> {
    post(connect)
}

/// POST /session/:id/connect — applicant binds a bearer key to the
/// session and gets the current progress. Idempotent: first call
/// initializes state and runs the policy from scratch; subsequent
/// calls with the same key replay existing state and return the same
/// suspension point (cheap — replay path skips host calls). A
/// different key on an already-claimed session is rejected at the
/// auth layer with 403; recovery requires `DELETE /session/:id/state`
/// first (no auth, by design — see reset.rs).
async fn connect(
    Path(session_id): Path<String>,
    State(state): State<Arc<AppState>>,
    CallerKey(applicant_key): CallerKey,
) -> Result<Json<SessionProgress>, StatusCode> {
    let metadata = fetch_metadata(&state, &session_id).await?;
    let args = parse_args(&metadata)?;

    // Existence claim is host-controlled; content of Some is
    // AEAD-integrity-verified at decode (AuthN cleared, AuthZ implicit
    // by holding the right applicant_key). We accept None at face
    // value — a lying host hiding a real blob just makes us replay
    // from default state (disruptive UX, not a leak). The version
    // seeds the persister's per-call writes within this run.
    let ((state_opt,), version) = state
        .session_store
        .read(
            &session_id,
            (StateField {
                applicant_key: applicant_key.expose_secret(),
            },),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let session_state = state_opt
        .trust_unchecked::<Replay, _>(reason!(r#"
Stale state is bounded by per-call version-CAS during the run.
The first write on a stale snapshot fails with VersionMismatch
and the run aborts cleanly — replay from the latest persisted
state on retry.
        "#))
        .into_inner()
        .unwrap_or_default();

    let version = version
        .trust_unchecked::<AuthN, _>(reason!(r#"
Version is a CAS token only. A lying host either fails our
writes (DoS) or stomps a concurrent winner (UX regression). No
data leak path.
        "#))
        .trust_unchecked::<Replay, _>(reason!(r#"
Staleness on the version manifests as CAS mismatch on first
persist; same containment as above.
        "#))
        .into_inner();

    // Per-run persister: engine fires `on_session_change` after each
    // committed CallEvent, persister seals disclosures to the client
    // recipient pubkey then writes (SetState + AppendDisclosures)
    // in one atomic SessionStore.write per host call. One run = N
    // writes (one per host call), not one final flush; persister
    // threads the version through the run's writes.
    let persister = Arc::new(SessionPersister {
        session_store: state.session_store.clone(),
        session_id: session_id.clone(),
        applicant_key: applicant_key.expose_secret().to_vec(),
        client_pk: metadata.client_disclosure_pubkey.clone(),
        current_version: AtomicU64::new(version),
        metadata: Mutex::new(metadata.clone()),
    });
    let resources = build_resources(persister);
    let policy = lookup_policy(&state, &session_id, &metadata).await?;

    let (status, _session_state) = state
        .runner
        .run(&policy, session_state, args, resources)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(progress_from(status)))
}
