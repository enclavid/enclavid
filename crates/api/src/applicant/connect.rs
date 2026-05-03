use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, post};
use secrecy::ExposeSecret;

use enclavid_host_bridge::State as StateField;

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

    // Existence claim is host-controlled; once decrypt is in place,
    // content of Some is integrity-verified by AEAD. We accept None at
    // face value — a lying host hiding a real blob just makes us
    // replay from default state (disruptive UX, not a leak).
    let (state_opt,) = state
        .session_store
        .read(
            &session_id,
            (StateField {
                applicant_key: applicant_key.expose_secret(),
            },),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .trust_unchecked();
    let session_state = state_opt.unwrap_or_default();

    // Per-run persister: engine fires `on_session_change` after each
    // committed CallEvent, persister seals disclosures to the client
    // recipient pubkey then writes (SetState + AppendDisclosures) in
    // one atomic SessionStore.write. One run = N writes (one per host
    // call), not one final flush.
    let persister = Arc::new(SessionPersister {
        session_store: state.session_store.clone(),
        session_id: session_id.clone(),
        applicant_key: applicant_key.expose_secret().to_vec(),
        client_pk: metadata.client_disclosure_pubkey.as_bytes().to_vec(),
    });
    let resources = build_resources(persister);
    let policy = lookup_policy(&state, &session_id).await?;

    let (status, _session_state) = state
        .runner
        .run(&policy, session_state, args, resources)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(progress_from(status)))
}
