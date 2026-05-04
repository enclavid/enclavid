use std::sync::Arc;

use age::x25519::Identity;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, post};
use base64ct::{Base64, Encoding};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize};

use enclavid_attestation::ReportData;
use enclavid_host_bridge::{
    SessionMetadata, SessionStatus, SetMetadata, SetStatus, WriteField,
};

use crate::client_state::ClientState;

use super::auth::Workspace;

/// Length of session_id random bytes (≥ 16 = 128 bits entropy per arch doc).
const SESSION_ID_RANDOM_BYTES: usize = 32;

/// Maximum length of `external_ref`. Bounds host storage growth and
/// keeps wire frames small. UUIDs and typical client identifiers fit
/// comfortably.
const MAX_EXTERNAL_REF_LEN: usize = 128;

#[derive(Deserialize)]
pub struct CreateSessionRequest {
    /// Policy reference: `name:tag` (mutable) or `name@sha256:...` (pinned).
    pub policy: String,
    /// Disclosure recipient pubkey: applicant-consented data is encrypted
    /// to this. Provided as age recipient string `age1...`.
    pub client_disclosure_pubkey: String,
    /// Opaque client-side identifier for this verification — proxied
    /// back in webhook payloads and `GET /sessions/:id/status`. NOT
    /// indexed: clients reconcile `external_ref → session_id` on their
    /// own side. Optional. Validated at deserialization (length and
    /// charset) so a malformed value surfaces as a serde error → 400
    /// before the handler even runs.
    #[serde(default, deserialize_with = "deserialize_external_ref")]
    pub external_ref: Option<String>,
}

/// Length-bound + printable-ASCII gate on `external_ref`. Empty
/// strings collapse to `None` (treated identically to "missing").
/// The restricted charset avoids host-side key parsing surprises
/// and disallows zero-width / RTL-override confusables that could
/// spoof reconciliation on the consumer's dashboard.
fn deserialize_external_ref<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<String>, D::Error> {
    let opt = <Option<String>>::deserialize(d)?;
    let Some(s) = opt else { return Ok(None) };
    if s.is_empty() {
        return Ok(None);
    }
    if s.len() > MAX_EXTERNAL_REF_LEN {
        return Err(serde::de::Error::custom(format!(
            "must not exceed {MAX_EXTERNAL_REF_LEN} bytes"
        )));
    }
    if s.chars().any(|c| !c.is_ascii_graphic()) {
        return Err(serde::de::Error::custom(
            "must consist of printable ASCII only (no whitespace, no control chars)",
        ));
    }
    Ok(Some(s))
}

#[derive(Serialize)]
pub struct AttestationView {
    pub format: String,
    /// Base64-standard encoding of `Quote::quote_blob`.
    pub quote: String,
    /// Hex-encoded TEE measurement.
    pub measurement: String,
}

#[derive(Serialize)]
pub struct ResolvedPolicyView {
    pub name: String,
    pub digest: String,
}

#[derive(Serialize)]
pub struct CreateSessionResponse {
    pub session_id: String,
    /// age recipient string (`age1...`) — clients use this directly with
    /// stock age to wrap K_client.
    pub ephemeral_pubkey: String,
    pub resolved_policy: ResolvedPolicyView,
    pub attestation: AttestationView,
}

/// Route factory: bare `post(handler)` MethodRouter. Auth is attached
/// at the router level via `.layer(auth(op))` — see `client::router`.
pub(super) fn post_create() -> MethodRouter<Arc<ClientState>> {
    post(create)
}

/// POST /api/v1/sessions — creates a PendingInit session, returns
/// `session_id`, `ephemeral_pubkey`, and an attestation quote binding
/// the three. The client unwraps and verifies, then proceeds to /init
/// with the wrapped K_client.
async fn create(
    State(state): State<Arc<ClientState>>,
    Workspace(workspace_id): Workspace,
    Json(body): Json<CreateSessionRequest>,
) -> Result<Json<CreateSessionResponse>, StatusCode> {
    // For MVP we accept name@digest only — tag → digest resolution via
    // registry will land alongside the Pull integration. `name:tag` form
    // is rejected at parse_pinned_reference with 400.
    let (policy_name, policy_digest) =
        parse_pinned_reference(&body.policy).ok_or(StatusCode::BAD_REQUEST)?;

    // Per-session ephemeral X25519 keypair. Private half lives only in
    // the in-memory cache — never persisted, dropped on transition out
    // of PendingInit.
    let identity = Identity::generate();
    let ephemeral_pubkey_str = identity.to_public().to_string();

    let session_id = generate_session_id();

    // Mint attestation quote binding (session_id, ephemeral_pubkey,
    // policy_digest). Backend is whatever is plugged into ClientState
    // (mock for dev, sev-snp for production).
    let report_data = ReportData {
        session_id: session_id.clone(),
        ephemeral_pubkey: ephemeral_pubkey_str.clone().into_bytes(),
        policy_digest: policy_digest.clone(),
    };
    let quote = state
        .attestor
        .mint(&report_data)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let metadata = SessionMetadata {
        workspace_id,
        policy_name: policy_name.clone(),
        policy_digest: policy_digest.clone(),
        ephemeral_pubkey: ephemeral_pubkey_str.clone().into_bytes(),
        d_enc: String::new(),
        d_plain: String::new(),
        client_disclosure_pubkey: body.client_disclosure_pubkey,
        input: Vec::new(),
        external_ref: body.external_ref.unwrap_or_default(),
    };
    // Atomic write of the encrypted metadata blob + plaintext status
    // sidecar through the SessionStore service. Host's "Ok" is a claim
    // that PendingInit was persisted. If it lied: subsequent /init
    // returns 404, the client retries, no data exposure. K_client
    // backstop ensures a host that retains stale metadata can't drive
    // applicant flow.
    let ops: &[&dyn WriteField] = &[
        &SetMetadata(&metadata),
        &SetStatus(SessionStatus::PendingInit),
    ];
    // /create writes with `None` — host accepts only if the
    // session does not exist yet. With 32-byte random session_ids
    // a collision is astronomically unlikely; the primary effect
    // is rejecting accidental double-/create on the same id.
    // Returned version is wrapped (Untrusted<u64, (AuthN, Replay)>);
    // we don't use it here, so it's dropped without peeling. Race
    // safety is provided by the host-side existence-must-not-exist
    // check on this write.
    state
        .session_store
        .write(&session_id, None, ops)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state
        .ephemeral_identities
        .insert(session_id.clone(), Arc::new(identity))
        .await;

    Ok(Json(CreateSessionResponse {
        session_id,
        ephemeral_pubkey: ephemeral_pubkey_str,
        resolved_policy: ResolvedPolicyView {
            name: policy_name,
            digest: policy_digest,
        },
        attestation: AttestationView {
            format: quote.format,
            quote: Base64::encode_string(&quote.quote_blob),
            measurement: quote.measurement,
        },
    }))
}

fn generate_session_id() -> String {
    let mut bytes = [0u8; SESSION_ID_RANDOM_BYTES];
    OsRng.fill_bytes(&mut bytes);
    format!("ses_{}", hex::encode(bytes))
}

/// Split a pinned reference `<name>@sha256:<hex>` into (name, digest).
/// Returns None for any other shape (e.g. `name:tag` form) — tag → digest
/// resolution is a separate concern that lives in the create handler if
/// we ever support it.
fn parse_pinned_reference(reference: &str) -> Option<(String, String)> {
    let (name, digest) = reference.split_once('@')?;
    if !digest.starts_with("sha256:") {
        return None;
    }
    Some((name.to_string(), digest.to_string()))
}
