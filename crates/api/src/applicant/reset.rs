use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{MethodRouter, delete};

use hatch_client::{
    AuthN, AuthZ, Covert, Metadata, Replay, SessionStatus, SetMetadata, WriteField, boundary,
    outbound_session_id, reason,
};

use crate::state::AppState;

/// Route factory. Public (no auth layer) — see `applicant::router`.
pub(super) fn delete_state() -> MethodRouter<Arc<AppState>> {
    delete(reset)
}

/// DELETE /session/:id/state — hand the session back to whoever asks next.
///
/// The state IS the claim (it's sealed under the applicant key), so dropping it
/// puts the session back to "unclaimed" and the next /connect can take it with
/// any key — there is no separate in-memory claim to clear. Media and the
/// disclosure chain go with it, and the disclosure bookkeeping in metadata is
/// wound back to match.
///
/// No auth: the legitimate applicant who lost their key cannot prove ownership
/// cryptographically (state is encrypted with the lost key). Knowledge of
/// `session_id` (≥128 bits entropy, distributed only to the applicant + bank)
/// is the trust gate. An attacker with `session_id` can already grief the
/// session via /connect front-running, so as a *takeover* this adds nothing.
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
        .read(outbound_session_id(&session_id), (Metadata,))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let metadata = metadata_untrusted
        .trust_unchecked::<AuthZ, _>(reason!(
            "the applicant flow authenticates no tenant and this route none at all — \
             knowing the id is the gate, and the id's existence is already public at /status"
        ))
        .trust_unchecked::<Replay, _>(reason!(
            "a stale copy is caught by the version this read returned: the write below \
             names it, so a session that moved under us refuses the whole reset"
        ))
        .into_inner();

    // The version this read returned, fed straight back as the write's CAS
    // token below. Host-supplied, and there is no direction in which a wrong
    // one grants anything: it can only make the write refuse.
    let version = version
        .trust_unchecked::<AuthN, _>(reason!("the host's own counter"))
        .trust_unchecked::<AuthZ, _>(reason!("a CAS token, not an access decision"))
        .trust_unchecked::<Replay, _>(reason!("a stale value can only make the write refuse"))
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
            .vouch_unchecked::<AuthZ, _>(reason!(
                "only the attested CVM holds tee_seal_key; read as opaque ciphertext on \
                 /connect — release implicit in key-possession"
            ))
            .vouch_unchecked::<Covert, _>(reason!(
                "sealed under tee_seal_key; this write SHRINKS the metadata to its \
                 disclosure-free size, which tells the host a reset happened — something \
                 it already watched arrive as this very request"
            )),
    );

    // Before the delete, and version-gated, which is what makes the status check
    // above sound rather than advisory. A session that completed between the
    // read and here has moved the version, so this refuses and no chain is
    // touched. And from the moment it lands, `disclosure_entry_hashes` is empty
    // while the entries are not, so the set commitment cannot agree with the
    // served list — a consumer pull in the window between this and the delete
    // refuses rather than seeing a half-reset session.
    let fields: [&dyn WriteField; 1] = [&set_metadata];
    let expected_version = boundary::outbound::to_untrusted(Some(version))
        .vouch_unchecked::<AuthN, _>(reason!("the host's own counter, handed back to it"))
        .vouch_unchecked::<AuthZ, _>(reason!("a CAS token; no release decision hangs on it"))
        .vouch_unchecked::<Covert, _>(reason!(
            "a host-minted integer this process only echoes — no policy bandwidth"
        ));
    let fields = boundary::outbound::to_untrusted(&fields[..])
        .vouch_unchecked::<AuthN, _>(reason!(
            "one field, whose content is sealed in its own build_op"
        ))
        .vouch_unchecked::<AuthZ, _>(reason!("it writes this session's own key"))
        .vouch_unchecked::<Covert, _>(reason!("per-field covert closed in build_op"));
    state
        .session_store
        .write(outbound_session_id(&session_id), expected_version, fields)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // The `u64` we discard is the host's claim of how many state entries were
    // removed (0 = was already absent, 1 = wiped). Trust-wise a lying host can
    // fake either direction; the value is informational, not a security signal.
    state
        .session_store
        .delete(outbound_session_id(&session_id))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}
