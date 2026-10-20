use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{MethodRouter, delete};

use enclavid_boundary::{AuthN, AuthZ, Covert, Replay, reason};
use session_types::SessionStatus;
use storage_client::{
    DropApplicantData, Metadata, SetMetadata, StoreError, WriteField, boundary, outbound_fields,
};

use crate::state::AppState;

/// Route factory. Public (no auth layer) — see `applicant::router`.
pub(super) fn delete_state() -> MethodRouter<Arc<AppState>> {
    delete(reset)
}

/// DELETE /api/v1/sessions/{id}/state — hand the session back to whoever asks next.
///
/// The state IS the claim (it's sealed under the applicant key), so dropping it
/// puts the session back to "unclaimed" and the next /connect can take it with
/// any key — there is no separate in-memory claim to clear. Media and the
/// disclosure chain go with it, and the disclosure bookkeeping in metadata is
/// wound back to match — all in one write, under the version this read the
/// session at. 409 when the session is completed, or moved under the reset.
///
/// No auth: the legitimate applicant who lost their key cannot prove ownership
/// cryptographically (state is encrypted with the lost key). Knowledge of
/// `session_id` (≥128 bits entropy, distributed only to the applicant + bank)
/// is the trust gate, and it is all that stands in the way: whoever holds the id
/// can reset a session its applicant has already claimed, then `/connect` with a
/// key of their own and run it as themselves. Front-running cannot do that once
/// the session is claimed — a wrong key is refused at `/connect` — so this is the
/// price of giving an applicant who lost their key a way back, and an accepted
/// risk at the peel below.
///
/// What it would add, left alone, is worse than takeover. Front-running yields
/// a chain holding only the attacker's entries; resetting a session that has
/// already disclosed would leave the first applicant's entries in place for the
/// second applicant's to be appended to — and the consumer reads a session's
/// disclosures as one natural person's, because that is what a session is. One
/// record, two people, a set commitment that still verifies. So everything the
/// first applicant left goes, and the one state where an entry could already
/// have been read is refused outright.
async fn reset(
    Path(session_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<StatusCode, StatusCode> {
    let ((metadata_untrusted,), version) = state
        .session_store
        .read(&session_id, (Metadata,))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let metadata = metadata_untrusted
        .trust_accept_risk(reason!(
            AuthZ::AcceptedRisk,
            "anyone holding the session's link may drop what its applicant brought and \
             claim it anew — the one way back for an applicant who lost their key"
        ))
        .trust(reason!(
            Replay::Fresh,
            "a stale copy is caught by the version this read returned: the write below \
             names it, so a session that moved under us refuses the whole reset"
        ))
        .into_inner();

    // The version this read returned, fed straight back as the write's CAS
    // token below. Host-supplied, and there is no direction in which a wrong
    // one grants anything: it can only make the write refuse.
    let version = version
        .trust(reason!(
            AuthN::Indifferent,
            "the host's own counter, and any value only makes the write refuse"
        ))
        .trust(reason!(
            AuthZ::NoPrincipal,
            "a CAS token, not an access decision"
        ))
        .trust(reason!(
            Replay::Harmless,
            "a stale value can only make the write refuse"
        ))
        .into_inner();

    // No session, nothing to hand back. Same answer as a successful reset —
    // this route has never distinguished the two, and /status is where session
    // existence is answered.
    let Some(mut metadata) = metadata else {
        return Ok(StatusCode::NO_CONTENT);
    };

    // The one state whose disclosures are readable is the one state a reset may
    // not touch (`client::disclosures` serves `Completed` and nothing else).
    // Every other state has served nobody, which is what makes deleting the
    // chain below a deletion of data rather than a retraction of data someone
    // already holds.
    if metadata.status == SessionStatus::Completed {
        return Err(StatusCode::CONFLICT);
    }

    metadata.disclosure_count = 0;
    metadata.disclosure_entry_hashes.clear();
    // The gate set names blobs that are about to stop existing. Left behind, a
    // policy naming an old ref would pass the gate and get `Ok(None)` from the
    // store — a trap in the worker rather than a clean refusal.
    metadata.captured_media.clear();

    let set_metadata = SetMetadata(
        boundary::outbound::to_untrusted(&metadata)
            .vouch(reason!(
                AuthZ::NoSecret,
                "sealed under tee_seal_key, which only the attested CVM holds: the volume \
                 receives ciphertext it cannot read"
            ))
            .vouch(reason!(
                Covert::AlreadyHeld,
                "sealed under tee_seal_key; this write SHRINKS the metadata to its \
                 disclosure-free size, which tells the host a reset happened — something \
                 it already watched arrive as this very request"
            )),
    );

    // The metadata and everything the applicant brought go in ONE write, under
    // the version the read above returned — which is what makes the status
    // check above sound rather than advisory. A round that committed since,
    // completing the session or not, has moved the version: this refuses
    // whole, and what the round committed stays. There is no moment at which
    // the metadata is reset and the data is not, or the other way round.
    let fields: [&dyn WriteField; 2] = [&set_metadata, &DropApplicantData];
    let fields = outbound_fields(&fields).vouch(reason!(
        Covert::Bounded,
        "a fixed pair, so the count says only that a reset happened"
    ));
    match state
        .session_store
        .write(&session_id, Some(version), fields)
        .await
    {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        // The session moved since the read: a round committed, maybe the one
        // that completed it. Nothing was reset; asking again reads it afresh.
        Err(StoreError::VersionMismatch) => Err(StatusCode::CONFLICT),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
