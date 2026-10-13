//! A session that cannot be prepared to run.
//!
//! Preparing a session — pulling what it pins with its bearers, decrypting it
//! with its keys, compiling it — happens before any of the policy's code runs.
//! When it fails for a reason that is the consumer's setup and asking again will
//! not change, the session is marked [`SessionStatus::InitFailed`] with the
//! [`InitError`] that says why, which the consumer reads in its view of the
//! session. Any other failure is the request's alone, and the session may run on
//! the next.
//!
//! A round, where the policy's code runs, never marks a session: what it could
//! report would be the policy's to choose.

use axum::http::StatusCode;

use enclavid_boundary::{AuthN, AuthZ, Covert, reason};
use hatch_client::{
    InitError, SessionMetadata, SessionStatus, SessionStore, SetMetadata, WriteField, boundary,
    outbound_session_id,
};

/// Why a session's composition could not be had for this request.
pub enum Unavailable {
    /// What the consumer set up does not work, and asking again will not
    /// change that.
    Init(InitError),
    /// Anything else: this request's answer, the session left as it was.
    Request(StatusCode),
}

impl Unavailable {
    /// The applicant's answer — for an init error, once the session is marked
    /// with it ([`record`]): `metadata` is the session's as read at `version`.
    pub async fn settle(
        self,
        store: &SessionStore,
        session_id: &str,
        version: u64,
        metadata: &SessionMetadata,
    ) -> StatusCode {
        match self {
            Self::Init(error) => {
                let answer = answer(&error);
                record(store, session_id, version, metadata, error).await;
                answer
            }
            Self::Request(status) => status,
        }
    }
}

impl From<StatusCode> for Unavailable {
    fn from(status: StatusCode) -> Self {
        Self::Request(status)
    }
}

/// What the applicant is answered by a session that could not be prepared to
/// run: a status per kind of error, and nothing of what the error holds — which
/// part of the consumer's setup failed is the consumer's to read.
pub fn answer(error: &InitError) -> StatusCode {
    match error {
        InitError::Pull { .. } => StatusCode::GONE,
        InitError::Compile(_) => StatusCode::UNPROCESSABLE_ENTITY,
    }
}

/// Mark `session_id` as one that could not be prepared to run, with `error`:
/// its `metadata`, as read at `version`, written back in one write under that
/// version. A session that moved since — a round committed, or another request
/// marked it first — is left as it is, and what moved it stands.
pub async fn record(
    store: &SessionStore,
    session_id: &str,
    version: u64,
    metadata: &SessionMetadata,
    error: InitError,
) {
    let mut metadata = metadata.clone();
    metadata.status = SessionStatus::InitFailed;
    metadata.init_error = Some(error);
    let set_metadata = SetMetadata(
        boundary::outbound::to_untrusted(&metadata)
            .vouch_unchecked::<AuthZ, _>(reason!(
                "only the attested CVM holds tee_seal_key; read as opaque ciphertext — \
                 release implicit in key-possession"
            ))
            .vouch_unchecked::<Covert, _>(reason!(
                "the error rides in a fixed frame, so the write says only that the session \
                 could not be prepared — which api decided before any policy code ran"
            )),
    );
    let fields: [&dyn WriteField; 1] = [&set_metadata];
    let expected_version = boundary::outbound::to_untrusted(Some(version))
        .vouch_unchecked::<AuthN, _>(reason!("the host's own counter, handed back to it"))
        .vouch_unchecked::<AuthZ, _>(reason!("a CAS token; no release decision hangs on it"))
        .vouch_unchecked::<Covert, _>(reason!(
            "a host-minted integer this process only echoes — no policy bandwidth"
        ));
    let fields = boundary::outbound::to_untrusted(&fields[..])
        .vouch_unchecked::<AuthN, _>(reason!("one field, closed in its own build_op"))
        .vouch_unchecked::<AuthZ, _>(reason!("it writes this session's own key"))
        .vouch_unchecked::<Covert, _>(reason!("a single fixed field"));
    if let Err(e) = store
        .write(outbound_session_id(session_id), expected_version, fields)
        .await
    {
        safe_logger::debug!("init: {session_id} was not marked as failed: {e}");
    }
}
