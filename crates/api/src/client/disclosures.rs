use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, get};
use base64ct::{Base64, Encoding};
use serde::Serialize;

use hatch_client::{AuthN, AuthZ, Disclosure, Metadata, Replay, outbound_session_id, reason};

use crate::client_state::ClientState;
use crate::disclosure_commit;

use super::auth::{Principal, SessionToken, trust_metadata};

#[derive(Serialize)]
pub struct DisclosuresResponse {
    /// Each entry is one age-encrypted record sealed to the
    /// consumer-supplied `client_disclosure_pubkey` (provided at
    /// session create). Base64-standard for JSON wire safety; client
    /// decodes then opens with the matching age identity. **Order is
    /// UNSPECIFIED** — consumers MUST NOT rely on position. Attribute
    /// by session_id (KYC is per-natural-person, so distinct subjects
    /// are distinct sessions) and each envelope's `fields[].key`
    /// (content self-identifies), never by index.
    pub items: Vec<String>,
    /// Hex SHA-256 of the order-independent set commitment over `items`,
    /// recomputed and verified INSIDE the attested TEE before this response
    /// is emitted. A receipt the consumer can record: the same session always
    /// yields the same commitment, so a host serving divergent/forked views
    /// across pulls is detectable. NOTE: a bare echoed hash over this same
    /// response is co-forgeable by a host controlling the response — real
    /// independent (non-repudiable) verification requires binding the
    /// commitment into a fresh attestation quote, which is deferred (real
    /// SNP not yet wired). Do not treat this as standalone proof today.
    pub commitment: String,
}

/// Route factory: bare `get(handler)` MethodRouter. Auth attached at
/// router level via `.layer(auth(op))` — see `client::router`.
pub(super) fn get_disclosures() -> MethodRouter<Arc<ClientState>> {
    get(read)
}

async fn read(
    State(state): State<Arc<ClientState>>,
    Principal(presented_principal): Principal,
    SessionToken(presented_token): SessionToken,
    Path(session_id): Path<String>,
) -> Result<Json<DisclosuresResponse>, StatusCode> {
    // Pull metadata + disclosure list in a single Read RPC. Metadata
    // gates access via two orthogonal checks (token + principal)
    // AND is the source of truth for the order-INDEPENDENT set
    // commitment — we recompute the commitment over the host-served
    // list and compare, so any host fabrication / truncation / inject /
    // swap-with-other-list shows up as a commitment mismatch. Reorder is
    // deliberately NOT detected (list order is meaningless now).
    let ((metadata_untrusted, disclosures), _version) = state
        .session_store
        .read(outbound_session_id(&session_id), (Metadata, Disclosure))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Discharge AuthZ (token + principal) and Replay scopes on
    // metadata via the shared helper. Disclosures list AuthN is
    // checked separately below against the metadata set commitment.
    let metadata = trust_metadata(metadata_untrusted, &presented_token, &presented_principal)?;

    // The TEE-truth commitment, derived from the AEAD-sealed leaf list.
    // Computed once (independent of the host-served items) and reused as the
    // returned receipt.
    let expected = disclosure_commit::commit(&session_id, &metadata.disclosure_entry_hashes);

    // AuthN on the list is discharged by recomputing the set commitment over
    // the host-served ciphertexts and comparing to `expected`, plus a count
    // check. Any host forge / truncate / inject / swap-with-other-list changes
    // the set → mismatch → refuse (500). Reorder is intentionally accepted
    // (order is meaningless). 500 keeps the failure path consistent with other
    // host misbehaviours here.
    let items = disclosures
        .trust::<AuthN, _, _, _, _>(|items| {
            let served = disclosure_commit::commit_from_ciphertexts(&session_id, &items);
            if served == expected && items.len() as u64 == metadata.disclosure_count {
                Ok(items)
            } else {
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        })?
        .trust_unchecked::<AuthZ, _>(reason!(
            r#"
TEE forwards opaque sealed bytes; only the holder of the consumer's
disclosure private key can open them. This endpoint requires the
client AuthN'd via the bearer middleware to match the
metadata.client predicate (closed upstream), so the recipient is
both authenticated and the correct decryption target.
        "#
        ))
        .trust_unchecked::<Replay, _>(reason!(
            r#"
Two replay angles to consider:
  * Stale list against current metadata's set commitment —
    caught by the commitment + count check above (mismatch → 500).
  * Full-snapshot rollback (host serves a coherent older
    metadata + list pair) — commitment still validates; consumer
    sees older state. Stateless-TEE limitation; requires an
    external freshness oracle (TPM monotonic counter /
    append-only log) to close.
        "#
        ))
        .into_inner();

    Ok(Json(DisclosuresResponse {
        items: items.iter().map(|b| Base64::encode_string(b)).collect(),
        commitment: hex::encode(expected),
    }))
}
