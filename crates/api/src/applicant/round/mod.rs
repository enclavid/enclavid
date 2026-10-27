//! One reducer round of an applicant's session, as `/connect` and `/input`
//! drive it.
//!
//! ```text
//! mod.rs         ← SessionRunCtx and `run`: the round, its reply checked against
//!                  what it committed
//! extract.rs     ← loading the session for a round; one that has ended is
//!                  answered there and runs nothing
//! resolve.rs     ← a worker's cache miss: the composition from L2, or compiled
//! ```

mod extract;
mod resolve;

use std::sync::Arc;

use axum::http::StatusCode;

use engine_rpc::{CompositionKey, ExecError, RunOutcome, RunStatus};
use session_types::{Decision, Event, Prompt, SessionMetadata, SessionState};
use storage_client::DataKeys;

use crate::init::{self, Unavailable};
use crate::locale::Locale;
use crate::state::AppState;

use super::callbacks::CallbackServer;
use super::media_store::HatchMediaStore;
use super::persister::{self, RoundAwaiting, SessionPersister};
use super::views::{SessionProgress, progress_from};

use resolve::run_resolved;

/// Pre-flight context shared by `/connect` and `/input`. The extractor
/// fetches metadata, reads + integrity-trusts the previously-persisted
/// session state under the caller's bearer key, looks up the compiled
/// policy, and prepares the per-run persister + engine resources.
///
/// Handlers receive a fully-loaded ctx, decide on the inbound
/// [`Event`] (connect: `Event::Start` on a fresh `SessionState`;
/// input: the event matched against the loaded state's
/// `current_prompt`), and dispatch both back via
/// [`SessionRunCtx::run`]. That's where the connect / input flows
/// diverge: connect tolerates a missing state (default-init), input
/// requires it (409) and validates the submitted input against the
/// prompt the session is awaiting.
pub(super) struct SessionRunCtx {
    state: Arc<AppState>,
    pub(super) session_id: String,
    /// State previously persisted under this session's data key. `None`
    /// for a session whose `/connect` has never reached this far —
    /// connect treats that as "fresh start", input as 409.
    pub(super) session_state: Option<SessionState>,
    /// Applicant's preferred locale (from `Accept-Language` header).
    /// Text-ref resolution happens server-side so the wire payload is
    /// a plain string per ref — frontend doesn't carry i18n logic.
    pub(super) locale: Locale,
    /// SOLE strong owner of the session's data keys for this round, unlocked
    /// with the caller's key. The persister and media store hold only `Weak`s to
    /// them, so the plaintext keys' lifetime is exactly this context: they drop
    /// (and zeroize) when the run ends. MUST outlive `executor.run().await` —
    /// see [`SessionRunCtx::run`].
    data_keys: Arc<DataKeys>,
    /// The data keys locked under the caller's key, on a session no applicant
    /// held before this request: the round's first write records the lock, and
    /// with it the claim. `None` on a claimed session, whose lock stays as it is.
    new_lock: Option<Vec<u8>>,
    /// Age recipient the round's disclosure seals to, lifted out of metadata on
    /// the extractor path so `run` can build the persister once it knows what
    /// the round consented to.
    disclosure_pubkey: String,
    /// Session version the state read returned — the persister's opening CAS
    /// token.
    version: u64,
    /// The per-round media store — becomes the `media_load` half of the
    /// [`CallbackServer`] the keyless worker calls back into. Holds the seal key
    /// + a `Weak` to the data keys.
    media_store: Arc<HatchMediaStore>,
    /// Composition cache key — names the fused component in the execution-worker's
    /// L1 cache, and (with the worker's `compat_token`) keys the orchestrator's
    /// L2. Passed to the worker on the run; named back in its cache-miss reply.
    composition_key: CompositionKey,
    /// This session's metadata — kept for the round so `run_resolved` can
    /// cold-compile (OCI pull + fuse) on an L2 miss.
    metadata: SessionMetadata,
}

impl SessionRunCtx {
    /// Drive one reducer round: feed `event` against `session_state`
    /// into the policy, persist the returned state — and, on a terminal
    /// decision, the session's completion with it, in the same write (done
    /// by the persister via the engine's `on_session_change` hook) — check
    /// the reply against what was committed, or answer from what was
    /// committed when no reply came, and project the result into the JSON
    /// view returned to the applicant. Consumes self — handlers call it once
    /// per request.
    pub(super) async fn run(
        self,
        session_state: SessionState,
        event: Event,
    ) -> Result<SessionProgress, StatusCode> {
        let SessionRunCtx {
            state,
            session_id,
            locale,
            // Bound (not dropped into `..`) ON PURPOSE: this is the sole strong
            // ref to the data keys, and the persister / media store hold only
            // `Weak`s. It MUST stay alive across `executor.run().await` below so
            // their `upgrade()`s succeed while the worker calls back to seal
            // state / open media. Dropping it early makes those upgrades return
            // `None` and the round fails. It drops (and zeroizes) at the end of
            // this fn.
            data_keys: key_owner,
            new_lock,
            disclosure_pubkey,
            version,
            media_store,
            composition_key,
            metadata,
            ..
        } = self;
        // Before anything runs: the worker may serve this composition from a
        // cache, with no pull behind it, and the props the round is given must
        // be ones it can be. Until a round's write records the session prepared
        // ([`SessionPersister::persist`]), every round prepares it.
        let prepared = match &metadata.prepared {
            Some(prepared) => prepared.clone(),
            None => match init::prepare(&state.compositions, &session_id, &metadata).await {
                Ok(prepared) => prepared,
                Err(e) => {
                    return Err(e
                        .settle(&state.session_store, &session_id, version, &metadata)
                        .await);
                }
            },
        };
        // The persister derives what this round may seal from the event and the
        // pre-round prompt, both of which are ours — see
        // [`SessionPersister::for_round`]. So the round's one seal is settled
        // before the request leaves this process, and the binding that makes it
        // evidence was already checked in `input`, whose digest gate is what
        // authorizes a seal at all.
        // Sole strong hold on what this round may disclose. The persister borrows
        // it as a `Weak`, exactly as it does the data keys, so the
        // applicant's plaintext fields live exactly as long as this frame —
        // however the frame ends.
        let consent = persister::round_consent(&event, &session_state.current_prompt);
        // The applicant's own frames, content-addressed here. Sent to the worker
        // in the event below and never taken back from it.
        let captures = persister::round_captures(&event);
        // The round's request, framed ONCE for both phases: the peel that closes
        // `Covert` produces the wire value, so the retry below re-sends the same
        // constant-size frames rather than re-encoding identical ones. The props
        // are the ones every round is handed, as the policy reads them.
        let req = crate::executor::outbound_round(
            &composition_key,
            crate::compositions::max_cwasm_bytes(&metadata.terms),
            &session_state,
            prepared.props.as_deref(),
            event,
        )
        .map_err(|e| classify_run_error(&session_id, &e))?;
        // Where this round's write leaves the session, once it lands. Held here
        // on the terms the consent is.
        let awaiting = RoundAwaiting::default();
        // The wait this round ends in, if it ends in one: the next after the
        // session's as the round began.
        let awaiting_seq = session_state.awaiting_seq + 1;
        let persister = SessionPersister::for_round(
            state.session_store.clone(),
            session_id.clone(),
            // Weak: `key_owner` below is the sole strong ref, and it must
            // outlive the worker's callbacks.
            Arc::downgrade(&key_owner),
            new_lock,
            disclosure_pubkey,
            version,
            awaiting_seq,
            metadata.clone(),
            prepared,
            &consent,
            &captures,
            &awaiting,
            state.shuffle_key.clone(),
        );
        // Bound, like `key_owner` above and for the same reason: it is the sole
        // strong hold on the applicant's consented fields, the persister has only
        // a `Weak`, and it must outlive `executor.run().await` so a callback can
        // still seal. It drops at the end of this fn, whichever way the fn ends.

        // Callbacks the keyless worker calls DURING a run: blob rehydration
        // (`media_load`) + state persistence (`session_change`). Bundle resolution
        // is NOT here — the orchestrator drives it itself on a cache miss (below),
        // under the `composition_key` IT computed, so the worker never names which
        // L2 slot a compile lands in.
        // Handed over as the contract served at api's end of the leg
        // (`RemoteCallbacksAt<ExecutionWorker>`) — there is no other kind to
        // hand over. The raw callback server is not engine-rpc's to export, so this
        // side has no unwrapped contract available to implement by accident.
        let callbacks = CallbackServer {
            persister: persister.clone(),
            media_store,
        };

        let reply = async {
            // Phase 1: cache-only run. The worker serves the composition from its
            // own L1, or reports a miss — no bundle crosses on this call.
            //
            // The reply is the worker's word as much as anything it pushes back,
            // so it arrives under the same scope and has to be judged before it
            // is used.
            let status = match state
                .executor
                .run(req.clone(), callbacks.clone())
                .await
                .map_err(|e| classify_run_error(&session_id, &e))?
                // Answered by api's end (`crate::boundary::ExecutionWorker`), and
                // the answer covers BOTH arms: a cache miss and a cache hit differ
                // in whether the worker's L1 happened to hold the composition,
                // which is no reason for two different judgements.
                .into_inner()
            {
                RunOutcome::Ran(status) => status
                    .open()
                    .map_err(|e| classify_run_error(&session_id, &e.into()))?,
                RunOutcome::CacheMiss { compat_token } => {
                    // L1 miss: resolve the bundle OURSELVES, keyed by the
                    // `composition_key` WE computed — never one echoed by the
                    // worker — which is what closes the L2 cache-poisoning vector.
                    // A resolution failure that is the pins' marks the session as
                    // one that could not be prepared ([`crate::init`]). Phase 2:
                    // re-drive WITH the bundle via `run_with_bundle`, which
                    // always runs (no second miss).
                    run_resolved(
                        &state,
                        &composition_key,
                        &compat_token,
                        &session_id,
                        &metadata,
                        req,
                        callbacks,
                    )
                    .await?
                    .map_err(|e| classify_run_error(&session_id, &e))?
                    .into_inner()
                }
            };
            Ok::<_, Unavailable>(status)
        }
        .await;

        let status = match reply {
            // The decision, if the round reached one, was committed with its
            // state in the one write `persist` made. The reply has to say the
            // same, or the worker contradicted itself and neither word answers
            // the applicant.
            Ok(status) => {
                if !agrees(&status, persister.decided().await) {
                    safe_logger::debug!(
                        "session_run_ctx: the reply for {session_id} contradicts what its \
                         round committed"
                    );
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
                status
            }
            // Found before the round ran, so no write of its can have landed.
            Err(e @ Unavailable::Init(_)) => {
                return Err(e
                    .settle(&state.session_store, &session_id, version, &metadata)
                    .await);
            }
            // A failure, but the round's write may have landed first — the child
            // killed after its commit, a leg gone before its reply. If it did,
            // the session moved on all the same, and the applicant is answered
            // with where it now stands, which is what a reload would show them:
            // not an error inviting them to send this round's input again, to a
            // prompt it was never for. If nothing was written, the error stands.
            Err(Unavailable::Request(e)) => {
                committed(persister.decided().await, awaiting.lock().await.take()).ok_or(e)?
            }
        };
        Ok(progress_from(status, &locale, awaiting_seq))
    }
}

/// Whether a round's reply says what the round committed: a finished round
/// committed exactly the decision it reports, and any other round none.
fn agrees(status: &RunStatus, committed: Option<Decision>) -> bool {
    match status {
        RunStatus::Completed(decision) => committed == Some(*decision),
        RunStatus::AwaitingInput(_) => committed.is_none(),
    }
}

/// What the round's own write committed, as its reply would have said it: the
/// decision on the round that finished, the prompt the committed state awaits
/// on any other. `None` when no write landed.
fn committed(decided: Option<Decision>, awaiting: Option<Prompt>) -> Option<RunStatus> {
    decided
        .map(RunStatus::Completed)
        .or_else(|| awaiting.map(RunStatus::AwaitingInput))
}

/// Map a worker's [`ExecError`] to the applicant's answer — a status per value
/// of a fixed enum, and nothing besides.
///
/// A 4xx says the fault is not theirs — they can stop retrying and report it —
/// and that is the whole of what this side is willing to attribute. WHAT the
/// policy did is authored by the consumer's own wasm, so anything carrying it
/// would be the policy choosing bytes on a wire, possibly as a function of the
/// applicant's data. A 503 says nothing ran, so the same request may be sent
/// again.
///
/// The consumer, who could act on a diagnosis, deliberately gets none of this:
/// a failure reason routed to them from a round is a value the policy chose
/// while holding the applicant's data.
fn classify_run_error(session_id: &str, e: &ExecError) -> StatusCode {
    safe_logger::debug!("session_run_ctx: executor.run failed for {session_id}: {e}");
    match e {
        ExecError::Policy => StatusCode::UNPROCESSABLE_ENTITY,
        ExecError::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
        // Nothing ran and nothing changed: the worker had no room for the round.
        // The one answer that means "the same request, later".
        ExecError::Busy => StatusCode::SERVICE_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use session_types::MediaSpec;

    /// A worker with no room is the one failure that says "the same request,
    /// later" — an empty 503, nothing for a policy to have chosen.
    #[test]
    fn a_busy_worker_is_a_503() {
        assert_eq!(
            classify_run_error("ses_test", &ExecError::Busy),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    /// A reply answers the applicant only when it says what the round's own
    /// write committed: the same decision, or none on a round still waiting.
    #[test]
    fn a_reply_must_say_what_the_round_committed() {
        let finished = RunStatus::Completed(Decision::Approved);
        let waiting = RunStatus::AwaitingInput(Prompt::Media(MediaSpec::default()));
        assert!(agrees(&finished, Some(Decision::Approved)));
        assert!(!agrees(&finished, Some(Decision::Rejected)));
        assert!(!agrees(&finished, None));
        assert!(agrees(&waiting, None));
        assert!(!agrees(&waiting, Some(Decision::Approved)));
    }

    /// A round whose reply never came answers with what its write committed,
    /// and with nothing — the error stands — when no write landed.
    #[test]
    fn a_lost_reply_is_answered_from_the_write() {
        assert!(matches!(
            committed(Some(Decision::Rejected), None),
            Some(RunStatus::Completed(Decision::Rejected))
        ));
        assert!(matches!(
            committed(None, Some(Prompt::Media(MediaSpec::default()))),
            Some(RunStatus::AwaitingInput(Prompt::Media(_)))
        ));
        assert!(committed(None, None).is_none());
    }
}
