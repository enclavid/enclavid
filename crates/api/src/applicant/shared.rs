//! Shared helpers and ambient TEE-side secrets used by the applicant
//! handlers. Keep tightly scoped — anything reused by multiple handlers
//! belongs here, anything used by exactly one belongs in that handler's
//! own file.

use std::sync::Arc;

use axum::http::StatusCode;

use enclavid_engine::policy::RunResources;
use enclavid_engine::{Component, EvalArgs, SessionListener};
use enclavid_host_bridge::{AuthZ, Metadata, Replay, SessionMetadata, reason};

use crate::input::parse_input;
use crate::state::AppState;

pub(super) async fn fetch_metadata(
    state: &AppState,
    session_id: &str,
) -> Result<SessionMetadata, StatusCode> {
    // Applicant flow has no per-session info to cross-check metadata
    // against — security relies on the bearer-key auth layer plus the
    // K_client encryption chain ensuring host-side metadata tampering
    // breaks the policy decryption / attestation chain. We accept the
    // host's existence claim and content at face value here; the trust
    // delegation is concentrated in `trust_unchecked` so callers don't
    // have to repeat the analysis.
    let ((metadata,), _version) = state
        .session_store
        .read(session_id, (Metadata,))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    metadata
        .trust_unchecked::<AuthZ, _>(reason!(r#"
Applicant flow doesn't authenticate per-workspace, so we have
no workspace_id to cross-check here. Security relies on the
bearer-key auth layer at the route plus AEAD-binding on state
under applicant_key.
        "#))
        .trust_unchecked::<Replay, _>(reason!(r#"
Applicant flow uses metadata only for engine-resource fields
(client_disclosure_pubkey, policy_digest, input). Their
staleness has no security impact — these fields are stable
across the session lifetime.
        "#))
        .into_inner()
        .ok_or(StatusCode::NOT_FOUND)
}

pub(super) fn parse_args(
    metadata: &SessionMetadata,
) -> Result<Vec<(String, EvalArgs)>, StatusCode> {
    parse_input(&metadata.input).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Build per-run resources for the engine. The listener is the only
/// side-effect channel — it fires after every committed CallEvent and
/// is responsible for sealing + persisting state and disclosures
/// atomically. Engine itself holds no keys; encryption lives on the
/// listener side, symmetric with how state/metadata are sealed inside
/// host-bridge.
pub(super) fn build_resources(listener: Arc<dyn SessionListener>) -> RunResources {
    RunResources { listener }
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
