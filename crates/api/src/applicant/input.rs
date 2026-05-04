use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, post};
use secrecy::ExposeSecret;

use enclavid_engine::SessionState;
use enclavid_host_bridge::{
    AuthN, Passport, Replay, State as StateField, call_event, document_request, reason, suspended,
};

use crate::state::AppState;

use super::auth::CallerKey;
use super::persister::SessionPersister;
use super::shared::{build_resources, fetch_metadata, lookup_policy, parse_args};
use super::views::{progress_from, SessionProgress};

/// Route factory. Auth attached at router level via
/// `.layer(auth(AuthMode::Verify))` — see `applicant::router`.
pub(super) fn post_input() -> MethodRouter<Arc<AppState>> {
    post(input)
}

/// POST /session/:id/input — submits applicant media for the suspended
/// step. Continues the policy flow.
async fn input(
    Path(session_id): Path<String>,
    State(state): State<Arc<AppState>>,
    CallerKey(applicant_key): CallerKey,
    body: axum::body::Bytes,
) -> Result<Json<SessionProgress>, StatusCode> {
    let metadata = fetch_metadata(&state, &session_id).await?;
    let args = parse_args(&metadata)?;

    // Existence is host-controlled; absence collapses to NOT_FOUND.
    // Content of Some is AEAD-integrity-verified at decode (AuthN
    // cleared, AuthZ implicit by holding the right applicant_key).
    // The version seeds the persister's per-call writes within this
    // run.
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

    let mut session_state = state_opt
        .trust_unchecked::<Replay, _>(reason!(r#"
Stale state bounded by per-call version-CAS during the run —
first persist fails with VersionMismatch on stomped version,
run aborts and client retries against fresh state.
        "#))
        .into_inner()
        .ok_or(StatusCode::NOT_FOUND)?;

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

    // Attach user input to the last Suspended request's typed data field.
    apply_input(&mut session_state, &body)?;

    // Per-run persister: engine fires `on_session_change` after each
    // committed CallEvent, persister seals disclosures to the client
    // recipient pubkey then writes (SetState + AppendDisclosures)
    // in one atomic SessionStore.write per host call. Concurrent
    // /input or /connect for the same session bumps the version
    // past us; our next write fails with VersionMismatch and the
    // run aborts cleanly — replay from latest persisted state on
    // retry.
    let persister = Arc::new(SessionPersister {
        session_store: state.session_store.clone(),
        session_id: session_id.clone(),
        applicant_key: applicant_key.expose_secret().to_vec(),
        client_pk: metadata.client_disclosure_pubkey.clone(),
        current_version: AtomicU64::new(version),
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

/// Attach applicant input to the currently-Suspended event's typed data
/// field. MVP parsing: raw body bytes per variant (passport = single
/// image, consent = first byte bool). ID card / drivers license /
/// biometric / verification-set require multipart parsing — not yet
/// implemented.
fn apply_input(session: &mut SessionState, body: &[u8]) -> Result<(), StatusCode> {
    let last = session.events.last_mut().ok_or(StatusCode::CONFLICT)?;
    let Some(call_event::Status::Suspended(sus)) = last.status.as_mut() else {
        return Err(StatusCode::CONFLICT);
    };
    let Some(request) = sus.request.as_mut() else {
        return Err(StatusCode::CONFLICT);
    };

    match request {
        suspended::Request::Document(doc) => match doc.kind.as_mut() {
            Some(document_request::Kind::Passport(_)) => {
                doc.kind = Some(document_request::Kind::Passport(Passport {
                    image: Some(body.to_vec()),
                }));
            }
            _ => return Err(StatusCode::NOT_IMPLEMENTED),
        },
        suspended::Request::Consent(c) => {
            c.accepted = Some(body.first().map(|&b| b != 0).unwrap_or(false));
        }
        _ => return Err(StatusCode::NOT_IMPLEMENTED),
    }
    Ok(())
}
