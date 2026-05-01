//! Shared helpers and ambient TEE-side secrets used by the applicant
//! handlers. Keep tightly scoped — anything reused by multiple handlers
//! belongs here, anything used by exactly one belongs in that handler's
//! own file.

use std::sync::Arc;

use axum::http::StatusCode;
use secrecy::{ExposeSecret, SecretBox};

use enclavid_engine::policy::RunResources;
use enclavid_engine::{Component, EvalArgs};
use enclavid_session_store::SessionMetadata;

use crate::input::parse_input;
use crate::state::{AppState, ApplicantKey};

// TODO: real TEE key (KMS attestation-bound).
pub(super) const TEE_KEY: &[u8] = &[0u8; 32];
// TODO: real platform key.
pub(super) const PLATFORM_KEY: &[u8] = &[0u8; 32];

pub(super) async fn fetch_metadata(
    state: &AppState,
    session_id: &str,
) -> Result<SessionMetadata, StatusCode> {
    state
        .metadata_store
        .get(session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)
        // Applicant flow has no per-session info to cross-check metadata
        // against — security relies on `verify_claim` (applicant holds
        // the session-claiming key) plus the K_client encryption chain
        // ensuring host-side metadata tampering breaks the policy
        // decryption / attestation chain. Document the delegation here
        // so callers don't have to.
        .map(|m| m.trust_unchecked())
}

pub(super) fn parse_args(
    metadata: &SessionMetadata,
) -> Result<Vec<(String, EvalArgs)>, StatusCode> {
    parse_input(&metadata.input).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Verify the provided applicant key matches the one that claimed the
/// session. If the cache was evicted or the pod restarted, accept and
/// re-populate — state is still decryptable since the applicant holds
/// the key.
pub(super) async fn verify_claim(
    state: &AppState,
    session_id: &str,
    applicant_key: &ApplicantKey,
) -> Result<(), StatusCode> {
    match state.applicant_keys.get(session_id).await {
        Some(existing) if existing.expose_secret() == applicant_key.expose_secret() => Ok(()),
        Some(_) => Err(StatusCode::FORBIDDEN),
        None => {
            let cloned = applicant_key.expose_secret().clone();
            state
                .applicant_keys
                .insert(
                    session_id.to_string(),
                    Arc::new(SecretBox::new(Box::new(cloned))),
                )
                .await;
            Ok(())
        }
    }
}

/// Build per-run resources from AppState + session metadata.
pub(super) fn build_resources(
    state: &AppState,
    session_id: &str,
    metadata: &SessionMetadata,
) -> RunResources {
    RunResources {
        disclosure_store: state.disclosure_store.clone(),
        session_id: session_id.to_string(),
        client_pk: metadata.client_disclosure_pubkey.as_bytes().to_vec(),
    }
}

/// Look up the compiled policy for a session. The component is inserted
/// into the cache on /init (client API). Cache miss means either /init
/// was never called or the entry was evicted past TTL — both manifest as
/// 410 Gone, matching how the client API reports lost ephemeral state.
pub(super) async fn lookup_policy(
    state: &AppState,
    session_id: &str,
) -> Result<Arc<Component>, StatusCode> {
    state
        .policies
        .get(session_id)
        .await
        .ok_or(StatusCode::GONE)
}
