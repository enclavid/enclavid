use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Json;
use axum::routing::{MethodRouter, post};
use base64ct::{Base64, Encoding};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize};
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};

use enclavid_attestation::ReportData;
use broker_client::{
    AuthN, AuthZ, Client, ClientAccess, Covert, PluginPin, SessionMetadata, SessionStatus,
    SetMetadata, SetPrincipal, SetStatus, WriteField, boundary, reason,
};

use crate::client_state::ClientState;
use crate::limits::{
    CLIENT_SESSION_TOKEN_BYTES, MAX_CLIENT_REF_LEN, MAX_REGISTRY_AUTH_LEN,
    SESSION_ID_RANDOM_BYTES,
};
use crate::policy_pull;

use super::auth::Principal;

#[derive(Deserialize)]
pub struct CreateSessionRequest {
    /// Full pinned OCI reference for the policy artifact:
    /// `<registry>/<repository>@sha256:<hex>`. Tag-form rejected at
    /// parse — TEE only ever asks the registry by digest. The
    /// registry hostname is part of the ref, so any OCI-compliant
    /// registry works (our Angos by default; ghcr, ECR, etc. via
    /// PR4 once `registry_auth` is wired up).
    pub policy: String,
    /// Disclosure recipient pubkey: applicant-consented data is
    /// encrypted to this. Provided as age recipient string `age1...`.
    pub client_disclosure_pubkey: String,
    /// Opaque client-side identifier for this verification — proxied
    /// back in webhook payloads and `GET /sessions/:id`. NOT
    /// indexed: clients reconcile `client_ref → session_id` on their
    /// own side. Optional. Validated at deserialization (length and
    /// charset) so a malformed value surfaces as a serde error → 400
    /// before the handler even runs.
    #[serde(default, deserialize_with = "deserialize_external_ref")]
    pub client_ref: Option<String>,
    /// Per-hostname registry bearer map. Key = registry hostname
    /// (authority portion of an OCI ref, e.g. `closed.vendor.com`);
    /// value = the full `Authorization` header value the host should
    /// attach when pulling from that registry (e.g. `"Bearer <token>"`).
    /// Applies uniformly to the policy ref AND every plugin's
    /// `impl_ref`.
    ///
    /// Missing hostname / empty value ⇒ anonymous pull. When the
    /// whole map is absent / empty AND an inbound `Authorization`
    /// header is present on this request, the inbound header is
    /// applied to the policy registry's hostname as a back-compat
    /// convenience for the common "same credential everywhere" case.
    ///
    /// Total serialized size bounded by [`MAX_REGISTRY_AUTH_LEN`]
    /// (sum of all values) to keep session metadata blobs cheap.
    #[serde(default)]
    pub registry_auth: BTreeMap<String, String>,

    /// Plugin pins declared by the client at session creation. One
    /// entry per non-host-provided WIT package the policy imports.
    /// Each `impl_ref` MUST be digest-pinned (`@sha256:<hex>`).
    /// Hostname portion of `impl_ref` drives the
    /// [`Self::registry_auth`] lookup at pull time.
    ///
    /// Empty when the policy has no plugin imports.
    #[serde(default)]
    pub plugins: Vec<PluginRequest>,
}

/// One plugin pin in the create-session request. Mirrors the on-wire
/// proto `enclavid.state.PluginPin` with serde-friendly field types;
/// converted to the proto form before persistence.
#[derive(Deserialize)]
pub struct PluginRequest {
    /// WIT package id this pin satisfies, e.g. `vendor:plugin@0.1.0`.
    pub package: String,
    /// Full pinned OCI reference, e.g.
    /// `closed.vendor.com/plugin@sha256:<hex>`. Tag-form rejected at
    /// the handler.
    pub impl_ref: String,
}

/// Length-bound + printable-ASCII gate on `client_ref`. Empty
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
    if s.len() > MAX_CLIENT_REF_LEN {
        return Err(serde::de::Error::custom(format!(
            "must not exceed {MAX_CLIENT_REF_LEN} bytes"
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
    /// Full pinned OCI reference echoed back from the request.
    pub reference: String,
    /// Convenience: just the `sha256:<hex>` digest, extracted from
    /// `reference`. Same value the attestation quote binds in
    /// `ReportData.policy_digest`.
    pub digest: String,
}

#[derive(Serialize)]
pub struct CreateSessionResponse {
    pub session_id: String,
    /// Per-session bearer the client MUST present in the `X-Session-Token`
    /// header on every subsequent `GET /sessions/:id*` call. Base64-
    /// standard encoded 32 random bytes. Generated by the TEE here,
    /// returned **only** in this TLS-encrypted response (host doesn't
    /// see it). Client should persist it alongside `session_id` —
    /// losing it means losing read access to that session (TTL bounded
    /// to session lifetime).
    pub client_session_token: String,
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
/// 1. Parse + validate `policy` reference, `client_ref`, plugin pins.
/// 2. Mint attestation quote binding (session_id, policy_digest) to
///    this TEE measurement. Per-instance TLS-cert-to-attestation
///    binding handles "is this the right TEE?" out of band.
/// 3. Atomically write metadata + Status:Running to the host store.
///
/// The persisted metadata blob is AEAD'd with the TEE-side key,
/// AAD=session_id, so the host sees opaque bytes only.
async fn create(
    State(state): State<Arc<ClientState>>,
    Principal(principal): Principal,
    headers: HeaderMap,
    Json(body): Json<CreateSessionRequest>,
) -> Result<Json<CreateSessionResponse>, StatusCode> {
    // Validate the ref shape up-front — tag-form (no `@sha256:`) or
    // bad-algo refs trap here with a clean 400, instead of failing
    // later inside policy_pull with an opaque error.
    let policy_digest = policy_pull::split_pinned_ref(&body.policy)
        .map(|(_, d)| d.to_string())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let policy_ref = body.policy.clone();

    // Build the hostname-keyed bearer map. Body-supplied `registry_auth`
    // is the authoritative source — caller specifies which hostname
    // gets which bearer (covers heterogeneous "policy in our Angos,
    // plugin in ghcr" deployments). When the body map is empty AND an
    // inbound `Authorization` header is present, fall back to using
    // that header as the bearer for the policy registry only — common
    // case where the same credential serves both the API call and the
    // policy pull. Length-bound the SUM of values so a malicious
    // consumer can't bloat session metadata.
    let mut registry_auth: HashMap<String, Vec<u8>> = HashMap::new();
    if !body.registry_auth.is_empty() {
        for (host, bearer) in body.registry_auth {
            registry_auth.insert(host, bearer.into_bytes());
        }
    } else if let Some(hv) = headers.get(header::AUTHORIZATION) {
        let policy_host = policy_pull::registry_hostname(&body.policy)
            .ok_or(StatusCode::BAD_REQUEST)?;
        registry_auth.insert(policy_host.to_string(), hv.as_bytes().to_vec());
    }
    let total_bearer_bytes: usize = registry_auth.values().map(Vec::len).sum();
    if total_bearer_bytes > MAX_REGISTRY_AUTH_LEN {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate every plugin ref is digest-pinned (`@sha256:<hex>`)
    // before persistence — surfaces typos as a clean 400 instead of
    // an opaque pull error at /connect. Also dedupe-checks on
    // package id — two pins for the same WIT package would create
    // ambiguity at link time and is almost certainly a caller bug.
    let mut seen_packages: std::collections::HashSet<&str> = Default::default();
    for pr in &body.plugins {
        if pr.package.is_empty() || pr.impl_ref.is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
        if policy_pull::split_pinned_ref(&pr.impl_ref).is_none() {
            return Err(StatusCode::BAD_REQUEST);
        }
        if !seen_packages.insert(pr.package.as_str()) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    let plugins: Vec<PluginPin> = body
        .plugins
        .into_iter()
        .map(|pr| PluginPin {
            package: pr.package,
            impl_ref: pr.impl_ref,
        })
        .collect();

    let session_id = generate_session_id();

    // Per-session capability bearer. Returned to the client below
    // (TLS-encrypted, host doesn't see); stored only as SHA-256 hash
    // in the sealed metadata so tee_seal_key compromise alone doesn't
    // leak the token (pre-image resistance on 256-bit input). Client
    // presents the raw bytes in `X-Session-Token` on read endpoints;
    // TEE recomputes the hash, constant-time compares with stored.
    // SecretBox so plaintext zeroizes on drop and is redacted from
    // Debug output.
    let client_session_token = generate_client_session_token();
    let client_session_token_hash =
        Sha256::digest(client_session_token.expose_secret()).to_vec();

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
    let client_block = Client {
        // Per-session access gate (defense-in-depth) — see
        // ClientAccess proto doc.
        access: Some(ClientAccess {
            // Principal lives both here (crypto-pinned for the
            // TEE-side cross-tenant check on reads) and as a separate
            // plaintext `SetPrincipal` op below (host-visible for
            // billing/revocation indexing). Same value, different
            // consumers, different protection properties.
            principal: principal.clone(),
            // SHA-256 of the bearer we returned to the client in the
            // POST /sessions response.
            session_token_hash: client_session_token_hash,
        }),
        disclosure_pubkey: body.client_disclosure_pubkey,
        r#ref: body.client_ref.unwrap_or_default(),
        registry_auth,
        plugins,
    };
    let metadata = SessionMetadata {
        policy_ref: policy_ref.clone(),
        input: Vec::new(),
        client: Some(client_block),
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
    };
    // Always write metadata + status. Principal is optional: skip the
    // op entirely when the auth scheme didn't produce one (host stores
    // nothing under `principal` in that case — fine, host-side
    // attribution features just won't have this session indexed).
    let set_metadata = SetMetadata(
        boundary::outbound::to_host(&metadata, reason!(r#"
SessionMetadata initial write at POST /sessions. Wire crossing for
the per-session config blob (principal, policy_ref, client
disclosure pubkey, input claims, disclosure-chain bookkeeping).
AuthN closed inside broker-client by AEAD-seal under tee_seal_key;
AuthZ + Covert vouched below.
            "#))
        .vouch_unchecked::<AuthZ, _>(reason!(r#"
Only the attested CVM holds tee_seal_key, so retrieval at /connect
is gated on the same enclave that wrote it. The metadata is
written here under POST /sessions (client AuthN'd by the host-side
Auth service) and read by the applicant API as opaque ciphertext —
release is implicit in key-possession.
            "#))
        .vouch_unchecked::<Covert, _>(reason!(r#"
Metadata sealed under tee_seal_key — plaintext invisible to both
host and consumer. Audit-honest caveat: ciphertext size is host-
observable. This is the initial /create write before any policy
has run; fields are derived from the client's /create request
(principal, policy_ref, client.access, client_disclosure_pubkey,
input claims), all client-controlled, not policy-controlled. Zero
covert bandwidth from policy at this write — the channel only
opens later via persister rewrites (see SetMetadata Covert peel
in applicant/persister.rs).
            "#))
    );
    let set_status = SetStatus(
        boundary::outbound::to_host(SessionStatus::Running, reason!(r#"
SessionStatus initial write at POST /sessions (Running). By-design
plaintext for host TTL / cleanup orchestration.
            "#))
        .vouch_unchecked::<AuthN, _>(reason!(r#"
By-design plaintext. Host needs the byte to manage TTL / cleanup
without holding a TEE-side key. No applicant- or policy-specific
data lands in the byte — only the lifecycle marker is observable.
            "#))
        .vouch_unchecked::<AuthZ, _>(reason!(r#"
Lifecycle marker observable to host for orchestration is the
explicit contract — host needs to know when to expire sessions or
release storage. Not access-controlled at this layer.
            "#))
        .vouch_unchecked::<Covert, _>(reason!(r#"
Enum cardinality = 5; ~1 status write per session lifecycle
transition. Bounded by session-lifecycle schema.
            "#))
    );
    let set_principal = principal.as_deref().map(|p| {
        SetPrincipal(
            boundary::outbound::to_host(p, reason!(r#"
Tenant principal UTF-8 identifier write at POST /sessions. By-
design plaintext: host indexes sessions per tenant for revocation
/ rate-limit / billing.
                "#))
            .vouch_unchecked::<AuthN, _>(reason!(r#"
By-design plaintext: host needs the value queryable. TEE never
reads it back, so authenticity gate isn't needed on this side
either. Equivalent shape to SetStatus.
                "#))
            .vouch_unchecked::<AuthZ, _>(reason!(r#"
Tenant identifier is the host's own operational data (host runs
the rate limiter and billing index); not access-controlled at
this layer.
                "#))
            .vouch_unchecked::<Covert, _>(reason!(r#"
Value is a fixed-shape tenant id chosen at /create from the
authenticated client identity, not produced by policy at evaluate
time. No policy-controlled bandwidth.
                "#))
        )
    });
    let mut ops: Vec<&dyn WriteField> = vec![&set_metadata, &set_status];
    if let Some(op) = set_principal.as_ref() {
        ops.push(op);
    }
    state
        .session_store
        .write(&session_id, None, &ops)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(CreateSessionResponse {
        session_id,
        client_session_token: Base64::encode_string(client_session_token.expose_secret()),
        resolved_policy: ResolvedPolicyView {
            reference: policy_ref,
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

/// Mint a fresh 32-byte per-session bearer for client reads. Wrapped
/// in `SecretBox` so the plaintext zeroizes on drop and never lands in
/// debug logs.
fn generate_client_session_token() -> SecretBox<Vec<u8>> {
    let mut bytes = vec![0u8; CLIENT_SESSION_TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    SecretBox::new(Box::new(bytes))
}

