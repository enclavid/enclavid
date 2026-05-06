use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use age::x25519::Identity;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, post};
use base64ct::{Base64, Encoding};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize};
use secrecy::{ExposeSecret, SecretBox};

use enclavid_attestation::ReportData;
use enclavid_host_bridge::{
    SessionMetadata, SessionStatus, SetMetadata, SetStatus, WriteField,
};

use crate::client_state::ClientState;
use crate::policy_pull;

use super::auth::Workspace;

/// Length of session_id random bytes (≥ 16 = 128 bits entropy per arch doc).
const SESSION_ID_RANDOM_BYTES: usize = 32;

/// Maximum length of `external_ref`. Bounds host storage growth and
/// keeps wire frames small. UUIDs and typical client identifiers fit
/// comfortably.
const MAX_EXTERNAL_REF_LEN: usize = 128;

#[derive(Deserialize)]
pub struct CreateSessionRequest {
    /// Policy reference: `name@sha256:...` (pinned). Tag-form rejected
    /// at parse — TEE only ever asks the registry by digest.
    pub policy: String,
    /// Disclosure recipient pubkey: applicant-consented data is
    /// encrypted to this. Provided as age recipient string `age1...`.
    pub client_disclosure_pubkey: String,
    /// Client's age secret-key (the policy-decryption key) as the
    /// canonical `AGE-SECRET-KEY-1...` string. Validated at session
    /// create against the manifest's validator annotation; stored
    /// encrypted under TEE_key in metadata for lazy use at /connect.
    pub k_client: String,
    /// Opaque client-side identifier for this verification — proxied
    /// back in webhook payloads and `GET /sessions/:id`. NOT
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
    pub resolved_policy: ResolvedPolicyView,
    pub attestation: AttestationView,
}

/// Route factory: bare `post(handler)` MethodRouter. Auth is attached
/// at the router level via `.layer(auth(op))` — see `client::router`.
pub(super) fn post_create() -> MethodRouter<Arc<ClientState>> {
    post(create)
}

/// POST /api/v1/sessions — full session-creation flow in one shot.
///
/// 1. Parse + validate `policy` reference, `external_ref`, parse
///    `k_client` as an age identity.
/// 2. Validate K_client cheaply: pull only the manifest, decrypt the
///    `validator` annotation token. Wrong key → 422.
/// 3. Mint attestation quote binding (session_id, policy_digest) to
///    this TEE measurement. Per-instance TLS-cert-to-attestation
///    binding handles "is this the right TEE?" out of band.
/// 4. Atomically write metadata (with K_client encrypted under
///    TEE_key) + Status:Running to the host store.
///
/// K_client itself stays in TEE memory only for the duration of this
/// handler — once written, the local copy is dropped. The persisted
/// metadata blob is AEAD'd with the TEE-side key, AAD=session_id, so
/// the host sees opaque bytes only.
async fn create(
    State(state): State<Arc<ClientState>>,
    Workspace(workspace_id): Workspace,
    Json(body): Json<CreateSessionRequest>,
) -> Result<Json<CreateSessionResponse>, StatusCode> {
    let (policy_name, policy_digest) =
        parse_pinned_reference(&body.policy).ok_or(StatusCode::BAD_REQUEST)?;

    // Parse K_client as age identity. SecretBox to ensure the
    // plaintext string gets zeroed on drop instead of lingering in
    // request-body buffers.
    let k_client_secret: SecretBox<String> = SecretBox::new(Box::new(body.k_client));
    let k_client = Identity::from_str(k_client_secret.expose_secret())
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Validate K_client matches the policy's validator annotation —
    // single small RPC to the host registry, no full policy pull.
    policy_pull::validate_k_client(
        &state.registry,
        &workspace_id,
        &policy_name,
        &policy_digest,
        &k_client,
    )
    .await
    .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;

    let session_id = generate_session_id();

    let report_data = ReportData {
        session_id: session_id.clone(),
        policy_digest: policy_digest.clone(),
    };
    let quote = state
        .attestor
        .mint(&report_data)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let metadata = SessionMetadata {
        workspace_id,
        policy_name: policy_name.clone(),
        policy_digest: policy_digest.clone(),
        // K_client lives encrypted inside the metadata blob (under
        // TEE_key, AAD=session_id). Stored as the raw secret-key
        // string — `/connect` re-parses it as an Identity when it's
        // time to decrypt the policy artifact.
        k_client: k_client_secret.expose_secret().as_bytes().to_vec(),
        client_disclosure_pubkey: body.client_disclosure_pubkey,
        input: Vec::new(),
        external_ref: body.external_ref.unwrap_or_default(),
        // Encrypted-status copy: TEE truth (vs the plaintext one in
        // BlobField::Status which is only a host-facing TTL hint).
        status: SessionStatus::Running as i32,
        created_at,
        // Persister increments this atomically with each
        // AppendDisclosure write — see SessionPersister.
        disclosure_count: 0,
        // Seed the running hash with the session-bound h_0 so the
        // chain is always defined (no special "empty" state). The
        // persister extends it on each AppendDisclosure; the
        // disclosures handler folds the host-served list and
        // compares against this field to detect host tampering.
        disclosure_hash: crate::disclosure_hash::init(&session_id),
        // d_enc / d_plain were pre-merge fields populated at /init
        // (see proto comment). Reserved on the wire; nothing to set.
    };
    let ops: &[&dyn WriteField] = &[
        &SetMetadata(&metadata),
        &SetStatus(SessionStatus::Running),
    ];
    state
        .session_store
        .write(&session_id, None, ops)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(CreateSessionResponse {
        session_id,
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
