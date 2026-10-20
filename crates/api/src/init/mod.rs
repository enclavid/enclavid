//! Preparing a session to run, and a session that cannot be.
//!
//! Preparing a session ([`prepare`]) — asking the registry whether its bearers
//! may pull what it pins, having its composition pulled, decrypted with its keys
//! and compiled, held by the execution-worker, and its props read there against
//! the type the composition declares — happens before any of the policy's code
//! runs: ahead of the first round when the consumer or the applicant asks for a
//! warmup ([`warm`]), and before each round until one round's write records it
//! done. When it fails for a reason that is the consumer's setup and asking
//! again will not change, the session is marked [`SessionStatus::InitFailed`]
//! with the [`InitError`] that says why, which the consumer reads in its view
//! of the session. Any other failure is the request's alone, and the session
//! may run on the next.
//!
//! A round, where the policy's code runs, never marks a session: what it could
//! report would be the policy's to choose.

mod pull_check;

use std::sync::Arc;

use axum::http::StatusCode;

use enclavid_boundary::{Asserted, AuthN, AuthZ, Covert, Replay, Untrusted, reason};
use engine_rpc::{ExecError, Preparation, Preparing, PropsRead};
use engine_types::limits::MAX_PROPS_BYTES;
use engine_types::props::PropsRefusal;
use session_types::{InitError, Prepared, SessionMetadata, SessionStatus};
use storage_client::{SessionStore, SetMetadata, WriteField, boundary, outbound_fields};

use crate::boundary::ExecutionWorker;
use crate::compositions::{Composition, Compositions, max_cwasm_bytes};
use crate::executor::outbound_preparation;

use pull_check::check_pull;

/// Prepare `metadata`'s session to run. What has to hold before any of its
/// policy's code does, in order: the registry lets the session's bearers pull
/// every artifact it pins ([`check_pull`]); the execution-worker holds its
/// composition — from its own cache, from L2, or compiled — and reads its props
/// as the type the composition declares, into the WAVE every round of it is
/// handed ([`settled`]).
///
/// A session prepared already only has its composition held again: what a
/// warmup asks of one whose rounds have begun.
///
/// A compile another session or a warmup left in L2 spares this the pulls and
/// the compile, never the manifests or the props.
pub async fn prepare(
    compositions: &Compositions,
    session_id: &str,
    metadata: &SessionMetadata,
) -> Result<Prepared, Unavailable> {
    let composition = Composition::of(metadata).ok_or_else(|| {
        safe_logger::debug!("init: metadata.client missing for {session_id}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if let Some(prepared) = &metadata.prepared {
        hold(compositions, &composition, session_id, Preparing::Hold).await?;
        return Ok(prepared.clone());
    }
    check_pull(compositions, session_id, metadata).await?;
    let preparing = Preparing::Read(metadata.props.clone());
    let read = hold(compositions, &composition, session_id, preparing).await?;
    judged(read, metadata)
}

/// What the worker read of the props, judged. Each answer it can give is judged
/// on its own grounds, so it is taken apart before either is acted on: see
/// [`settled`] and [`refused`].
fn judged(
    read: Untrusted<PropsRead, (Asserted,), ExecutionWorker>,
    metadata: &SessionMetadata,
) -> Result<Prepared, Unavailable> {
    match read.split(|read| match read {
        PropsRead::Refused(refusal) => Err(refusal),
        other => Ok(other),
    }) {
        Ok(read) => read.trust_with(Asserted::Contained, settled)?.into_inner(),
        Err(refusal) => refused(
            refusal
                .trust_accept_risk(reason!(
                    Asserted::AcceptedRisk,
                    "the session has not started, so nothing of an applicant's was ever \
                     handed to a worker for it, and the props bear the refusal out; what \
                     remains is which problem of a fixed set, once per session, read by the \
                     consumer"
                ))
                .into_inner(),
            metadata,
        ),
    }
}

/// Have the execution-worker hold `composition` and do what `preparing` asks
/// of it: from its own cache, or from the bundle resolved as a round's miss is
/// ([`Compositions::with_bundle`]). What it read comes back its word.
async fn hold(
    compositions: &Compositions,
    composition: &Composition,
    session_id: &str,
    preparing: Preparing,
) -> Result<Untrusted<PropsRead, (Asserted,), ExecutionWorker>, Unavailable> {
    let key = composition.key();
    let max_cwasm_bytes = max_cwasm_bytes(&composition.terms);
    let executor = &compositions.executor;
    let compat_token = match executor
        .prepare(outbound_preparation(
            &key,
            max_cwasm_bytes,
            preparing.clone(),
        ))
        .await
        .map_err(|e| unprepared(session_id, &e))?
    {
        Preparation::Read(read) => return Ok(read),
        Preparation::CacheMiss(compat_token) => compat_token
            .trust(reason!(
                Asserted::Contained,
                "a miss names only a slot inside the composition namespace api itself \
                 computed, so a fabricated token costs a recompile and never yields \
                 another composition's code"
            ))
            .into_inner(),
    };
    compositions
        .with_bundle(composition, &key, &compat_token, session_id, |source| {
            executor.prepare_with_bundle(
                outbound_preparation(&key, max_cwasm_bytes, preparing),
                source,
            )
        })
        .await?
        .map_err(|e| unprepared(session_id, &e).into())
}

/// What a worker's failure to prepare makes of the request: the status a round
/// failing the same way is answered with — nothing of it is the session's to
/// keep, since the worker's word is all it is.
fn unprepared(session_id: &str, e: &ExecError) -> StatusCode {
    safe_logger::debug!("init: preparing {session_id} failed: {e}");
    match e {
        ExecError::Policy => StatusCode::UNPROCESSABLE_ENTITY,
        ExecError::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
        ExecError::Busy => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// What the worker read of the props, judged — the work that closes `Asserted` on
/// it as CONTAINED: the props as WAVE are kept for the session and handed back to
/// the worker every round, to the policy whose type they are, and shown to no
/// one; held to what a round carries, and framed wherever they cross or rest, so
/// their length tells the host nothing either.
///
/// Nothing read, when reading was asked, is not an answer: 500. A refusal is not
/// judged here — see [`refused`].
fn settled(read: PropsRead) -> Result<Result<Prepared, Unavailable>, StatusCode> {
    match read {
        PropsRead::Read(props) => {
            if props
                .as_ref()
                .is_some_and(|wave| wave.len() > MAX_PROPS_BYTES)
            {
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
            Ok(Ok(Prepared { props }))
        }
        PropsRead::Refused(_) | PropsRead::NotRead => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// A refusal of the props, once its concern is taken off as an accepted risk —
/// no kind fits, and two checks narrow it. The session has not started: nothing
/// of an applicant's was ever handed to a worker for it, since a session takes
/// input only on a prompt a round committed, and that write records it prepared —
/// so no round can have, and the refusal is read only while none has; the write
/// that marks it is refused if one commits meanwhile. And the props bear it out
/// ([`crate::props::fault`]): a problem of a fixed set, at a place the props hold.
/// What remains is which of those, once per session, read by the consumer — and a
/// worker that broke out of its child could put a neighbouring session's bits into
/// that choice.
fn refused(refusal: PropsRefusal, metadata: &SessionMetadata) -> Result<Prepared, Unavailable> {
    if metadata.prepared.is_some() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR.into());
    }
    let fault = crate::props::fault(&refusal, &metadata.props).ok_or_else(|| {
        safe_logger::debug!("init: a props refusal the props do not bear out");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Err(Unavailable::Init(InitError::Props(fault)))
}

/// Prepare a session ahead of its rounds — what a warmup asks — and mark it
/// ([`record`]) when that fails for good; `metadata` is the session's as read
/// at `version`. Nothing is answered, and nothing is marked otherwise: the
/// first round prepares the session again, from what this left in the
/// worker's cache and in L2, and that round's write is what records it
/// prepared. A warmup asked for while the session's last is under way is that
/// one.
pub async fn warm(
    compositions: &Compositions,
    store: &SessionStore,
    session_id: &str,
    version: u64,
    metadata: &SessionMetadata,
) {
    let Ok(_warming) = compositions.warming.of(session_id).try_acquire_owned() else {
        return;
    };
    match prepare(compositions, session_id, metadata).await {
        Ok(_) => {}
        Err(Unavailable::Init(error)) => record(store, session_id, version, metadata, error).await,
        Err(Unavailable::Request(status)) => {
            safe_logger::debug!("init: warming {session_id} was answered {status}");
        }
    }
}

/// [`warm`] a session after the request that asked for it has been answered:
/// `metadata` as read at `version`, the version as the store returned it.
pub fn warm_in_background(
    compositions: Arc<Compositions>,
    store: Arc<SessionStore>,
    session_id: String,
    version: Untrusted<u64, (AuthN, AuthZ, Replay)>,
    metadata: SessionMetadata,
) {
    // Fed back only as the CAS token of the write that marks the session, if
    // preparing it fails for good.
    let version = version
        .trust(reason!(
            AuthN::Indifferent,
            "any value only makes the write that marks the session land or refuse"
        ))
        .trust(reason!(
            AuthZ::NoPrincipal,
            "the return value of a read this side made"
        ))
        .trust(reason!(
            Replay::Harmless,
            "a stale one makes the write refuse, which costs only the mark — a round that \
             moved the session on stands"
        ))
        .into_inner();
    tokio::spawn(async move {
        warm(&compositions, &store, &session_id, version, &metadata).await;
    });
}

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
        InitError::Compile(_) | InitError::Props(_) => StatusCode::UNPROCESSABLE_ENTITY,
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
            .vouch(reason!(
                AuthZ::NoSecret,
                "sealed under tee_seal_key, which only the attested CVM holds: the volume \
                 receives ciphertext it cannot read"
            ))
            .vouch(reason!(
                Covert::NotChosen,
                "the error rides in a fixed frame, so the write says only that the session \
                 could not be prepared — which api decided before any policy code ran"
            )),
    );
    let fields: [&dyn WriteField; 1] = [&set_metadata];
    let fields = outbound_fields(&fields).vouch(reason!(Covert::Bounded, "a single fixed field"));
    if let Err(e) = store.write(session_id, Some(version), fields).await {
        safe_logger::debug!("init: {session_id} was not marked as failed: {e}");
    }
}

#[cfg(test)]
mod tests;
