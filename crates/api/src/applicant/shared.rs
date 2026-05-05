//! Shared helpers and ambient TEE-side secrets used by the applicant
//! handlers. Keep tightly scoped — anything reused by multiple handlers
//! belongs here, anything used by exactly one belongs in that handler's
//! own file.

use std::str::FromStr;
use std::sync::Arc;

use age::x25519::Identity;
use axum::http::StatusCode;

use enclavid_engine::policy::RunResources;
use enclavid_engine::{Component, EvalArgs, SessionListener};
use enclavid_host_bridge::{AuthZ, Metadata, Replay, SessionMetadata, reason};

use crate::input::parse_input;
use crate::policy_pull;
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

/// Look up the compiled policy for a session, compiling lazily on
/// cache miss. The first /connect for a session pays the
/// pull+decrypt+compile cost; subsequent calls and /input rounds
/// hit the cache.
///
/// On cache miss the metadata's `k_client` field is parsed as an
/// age identity, used to decrypt the policy artifact pulled from
/// the registry, and the resulting wasm is compiled into a
/// `Component`. K_client lives in TEE memory only for the duration
/// of this function — once the `Component` is in the cache, K_client
/// is dropped.
///
/// Errors map to HTTP statuses the handler can pass through directly:
///   * 410 Gone — registry pull / decrypt / compile failed (the
///     session was created with the wrong K_client, or the policy
///     artifact has been removed)
///   * 5xx — transport / infra problems
pub(super) async fn lookup_policy(
    state: &AppState,
    session_id: &str,
    metadata: &SessionMetadata,
) -> Result<Arc<Component>, StatusCode> {
    if let Some(c) = state.policies.get(session_id).await {
        return Ok(c);
    }
    let k_client_str = std::str::from_utf8(&metadata.k_client)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let k_client = Identity::from_str(k_client_str)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let decrypted = policy_pull::pull_and_decrypt(
        &state.registry,
        &metadata.workspace_id,
        &metadata.policy_name,
        &metadata.policy_digest,
        &k_client,
    )
    .await
    .map_err(|_| StatusCode::GONE)?;
    let component = Arc::new(
        state
            .runner
            .compile(&decrypted.wasm_bytes)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );
    state
        .policies
        .insert(session_id.to_string(), component.clone())
        .await;
    Ok(component)
}
