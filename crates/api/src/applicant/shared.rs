//! Shared helpers and ambient TEE-side secrets used by the applicant
//! handlers. Keep tightly scoped — anything reused by multiple handlers
//! belongs here, anything used by exactly one belongs in that handler's
//! own file.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::extract::{FromRequestParts, Path};
use axum::http::StatusCode;
use axum::http::request::Parts;
use futures::{StreamExt, TryStreamExt};
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};

use enclavid_boundary::Asserted;
use enclavid_boundary::{AuthN, AuthZ, Exposed, Replay, Untrusted, reason};
use hatch_client::{
    Client, Decision, DisplayField, Event, Key, Metadata, PluginPin, Prompt, SessionMetadata,
    SessionState, SessionStatus, State as StateField, outbound_session_id,
};
// The run wire mirrors: props api builds + ships, the outcome + error it gets
// back from the execution-worker.
use engine_rpc::{
    BundleSource, CallbackServiceUntrusted, CompatToken, CompileError, CompileSource,
    CompositionKey, ExecError, Prop, RunOutcome, RunRequest, RunStatus,
};

use crate::cwasm_cache;
use crate::error::ApiError;
use crate::input::parse_input;
use crate::locale::Locale;
use crate::policy_pull;

use crate::state::AppState;

use super::auth::CallerKey;
use super::callbacks::CallbackServer;
use super::media_store::HatchMediaStore;
use super::persister::{self, RoundAwaiting, SessionPersister};
use super::views::{SessionProgress, progress_from, prompt_view};

/// Build the static `props` list the policy reads via
/// `context.props`, from the consumer's config bytes in metadata.
pub(super) fn parse_props(metadata: &SessionMetadata) -> Result<Vec<(String, Prop)>, StatusCode> {
    parse_input(&metadata.input).map_err(|e| {
        safe_logger::debug!("parse_props: parse_input failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

/// What this round is allowed to disclose to the consumer, if anything.
///
/// The whole consent decision, in one expression: a round seals exactly when the
/// applicant accepted, the screen they were answering was a consent screen, and
/// the fields sealed are the ones that screen carried. "show == seal" is this
/// function.
///
/// It runs on THIS side and only here. The execution-worker sees the same event
/// and the same prompt, but it is the process that executes adversary-supplied
/// code, so a disclosure computed there would be worth exactly as much as that
/// process is — and the callback it drives no longer carries one to be tempted
/// by. Both inputs are ours and both are already bound to the applicant:
/// `/input` built the event from their request, and refused the accept unless
/// the digest they echoed matched this same `current_prompt`.
///
/// A free function rather than a method because the rule is worth testing and
/// the round it belongs to needs a live worker, a store and a token to exist.
pub(super) fn consent_for_round(
    event: &Event,
    current_prompt: &Option<Prompt>,
) -> Option<Vec<DisplayField>> {
    match (event, current_prompt) {
        (Event::ConsentDisclosure(true), Some(Prompt::ConsentDisclosure(d))) => {
            Some(d.fields.clone())
        }
        _ => None,
    }
}

/// Where a session already stands, when saying so takes no round.
///
/// A completed session answers with the decision it was given and never runs
/// again: a second run could reach `finish` a second time — another disclosure
/// sealed, the decision the consumer already read rewritten. A started one
/// answers with the prompt it is waiting on, so reopening the link carries on
/// where the applicant was instead of starting over. `None` is a session no
/// round has reached yet, the one case `/connect` still runs.
///
/// A free function for the same reason [`consent_for_round`] is one.
pub(super) fn standing(
    metadata: &SessionMetadata,
    session_state: Option<&SessionState>,
    locale: &Locale,
) -> Result<Option<SessionProgress>, StatusCode> {
    if metadata.status == SessionStatus::Completed {
        // The round that finishes commits the two together, with its state; a
        // completed session without its decision is not a state this code
        // produces.
        let decision = metadata.decision.ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        return Ok(Some(SessionProgress::Completed {
            decision: decision.into(),
        }));
    }
    Ok(session_state
        .and_then(|s| s.current_prompt.as_ref())
        .map(|prompt| SessionProgress::AwaitingInput {
            request: prompt_view(prompt, locale),
        }))
}

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
    /// State previously persisted under this `applicant_session_token`. `None`
    /// for a session whose `/connect` has never reached this far —
    /// connect treats that as "fresh start", input as 409.
    pub(super) session_state: Option<SessionState>,
    /// Applicant's preferred locale (from `Accept-Language` header).
    /// Text-ref resolution happens server-side so the wire payload is
    /// a plain string per ref — frontend doesn't carry i18n logic.
    locale: Locale,
    /// SOLE strong owner of the applicant token for this round. The persister
    /// and media store hold only `Weak`s to it, so the plaintext token's
    /// lifetime is exactly this context: it drops (and zeroizes) when the run
    /// ends. MUST outlive `executor.run().await` — see [`SessionRunCtx::run`].
    applicant_session_token: Arc<SecretBox<Vec<u8>>>,
    /// Age recipient the round's disclosure seals to, lifted out of metadata on
    /// the extractor path so `run` can build the persister once it knows what
    /// the round consented to.
    disclosure_pubkey: String,
    /// Session version the state read returned — the persister's opening CAS
    /// token.
    version: u64,
    /// The per-round media store — becomes the `media_load` half of the
    /// [`CallbackServer`] the keyless worker calls back into. Holds the seal key
    /// + a `Weak` to the applicant token.
    media_store: Arc<HatchMediaStore>,
    props: Vec<(String, Prop)>,
    /// Composition cache key — names the fused component in the execution-worker's
    /// L1 cache, and (with the worker's `compat_token`) keys the orchestrator's
    /// L2. Passed to the worker on the run; named back in its cache-miss reply.
    composition_key: CompositionKey,
    /// This session's metadata — kept for the round so `run_resolved` can
    /// cold-compile (OCI pull + fuse) on an L2 miss.
    metadata: SessionMetadata,
}

impl SessionRunCtx {
    /// See [`standing`].
    pub(super) fn standing(&self) -> Result<Option<SessionProgress>, StatusCode> {
        standing(&self.metadata, self.session_state.as_ref(), &self.locale)
    }

    /// Whether the session has its decision. No round runs on one that has.
    pub(super) fn completed(&self) -> bool {
        self.metadata.status == SessionStatus::Completed
    }

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
    ) -> Result<SessionProgress, ApiError> {
        let SessionRunCtx {
            state,
            session_id,
            locale,
            // Bound (not dropped into `..`) ON PURPOSE: this is the sole strong
            // ref to the applicant token, and the persister / media store hold
            // only `Weak`s. It MUST stay alive across `executor.run().await`
            // below so their `upgrade()`s succeed while the worker calls back to
            // seal state / open media. Dropping it early makes those upgrades
            // return `None` and the round fails. It drops (and zeroizes) at the
            // end of this fn.
            applicant_session_token: token_owner,
            disclosure_pubkey,
            version,
            media_store,
            props,
            composition_key,
            metadata,
            ..
        } = self;
        // The persister derives what this round may seal from the event and the
        // pre-round prompt, both of which are ours — see
        // [`SessionPersister::for_round`]. So the round's one seal is settled
        // before the request leaves this process, and the binding that makes it
        // evidence was already checked in `input`, whose digest gate is what
        // authorizes a seal at all.
        // Sole strong hold on what this round may disclose. The persister borrows
        // it as a `Weak`, exactly as it does the applicant token, so the
        // applicant's plaintext fields live exactly as long as this frame —
        // however the frame ends.
        let consent = persister::round_consent(&event, &session_state.current_prompt);
        // The applicant's own frames, content-addressed here. Sent to the worker
        // in the event below and never taken back from it.
        let captures = persister::round_captures(&event);
        // Where this round's write leaves the session, once it lands. Held here
        // on the terms the consent is.
        let awaiting = RoundAwaiting::default();
        let persister = SessionPersister::for_round(
            state.session_store.clone(),
            session_id.clone(),
            // Weak: `token_owner` below is the sole strong ref, and it must
            // outlive the worker's callbacks.
            Arc::downgrade(&token_owner),
            disclosure_pubkey,
            version,
            metadata.clone(),
            &consent,
            &captures,
            &awaiting,
            state.shuffle_key.clone(),
        );
        // Bound, like `token_owner` above and for the same reason: it is the sole
        // strong hold on the applicant's consented fields, the persister has only
        // a `Weak`, and it must outlive `executor.run().await` so a callback can
        // still seal. It drops at the end of this fn, whichever way the fn ends.

        // Callbacks the keyless worker calls DURING a run: blob rehydration
        // (`media_load`) + state persistence (`session_change`). Bundle resolution
        // is NOT here — the orchestrator drives it itself on a cache miss (below),
        // under the `composition_key` IT computed, so the worker never names which
        // L2 slot a compile lands in.
        // Handed over as the UNTRUSTED view — there is no other kind to hand over.
        // The raw callback server is not engine-rpc's to export, so this side has
        // no unwrapped contract available to implement by accident.
        let callbacks = CallbackServer {
            persister: persister.clone(),
            media_store,
        };

        // Framed ONCE for both phases: the peel that closes `Covert` produces the
        // wire value, so the retry below re-sends the same constant-size frame
        // rather than re-encoding an identical one.
        let session_state = crate::executor::outbound_round_state(&session_state)
            .map_err(|e| classify_run_error(&session_id, &e))?;

        let reply = async {
            // Phase 1: cache-only run. The worker serves the composition from its
            // own L1, or reports a miss — no bundle crosses on this call.
            //
            // `map` carries the scope through: the concerns were answered about
            // the state, and assembling the request around it addresses none of
            // them and reopens none, so the receipt the door demands is the one
            // the mint wrote.
            let req = session_state.clone().map(|session_state| RunRequest {
                composition_key: composition_key.clone(),
                props: props.clone(),
                session_state,
                event: event.clone(),
            });
            // The reply is the worker's word as much as anything it pushes back,
            // so it arrives under the same scope and has to be judged before it
            // is used.
            let status = match state
                .executor
                .run(req, callbacks.clone())
                .await
                .map_err(|e| classify_run_error(&session_id, &e))?
                // CONTAINED, and the reason has to cover BOTH arms — an earlier
                // version spoke only about the miss, while the hit arm carried a
                // whole policy-authored prompt through the same peel. A cache miss
                // and a cache hit differ in whether the worker's L1 happened to
                // hold the composition, which is no reason for two different
                // judgements.
                .trust_unchecked::<Asserted, _>(reason!(
                    "contained: a miss names only a slot inside the composition namespace \
                     api itself computed, so a fabricated token costs a recompile and \
                     never yields another composition's code; a hit carries a prompt that \
                     is shown to the applicant, its sole auditor, or a decision api only \
                     compares with the one the round committed. The round's DISCLOSURE \
                     comes from api's own copy, never from this"
                ))
                .into_inner()
            {
                RunOutcome::Ran(status) => status
                    .open()
                    .map_err(|e| classify_run_error(&session_id, &e.into()))?,
                RunOutcome::CacheMiss { compat_token } => {
                    // L1 miss: resolve the bundle OURSELVES, keyed by the
                    // `composition_key` WE computed — never one echoed by the
                    // worker — which is what closes the L2 cache-poisoning vector.
                    // A resolution failure (e.g. 410 GONE) is a pure function of
                    // the pinned config, surfaced to the consumer verbatim. Phase
                    // 2: re-drive WITH the bundle via `run_with_bundle`, which
                    // always runs (no second miss).
                    let req = session_state.map(|session_state| RunRequest {
                        composition_key: composition_key.clone(),
                        props,
                        session_state,
                        event,
                    });
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
                    .trust_unchecked::<Asserted, _>(reason!(
                        "contained: a prompt is shown to the applicant, who is the \
                             sole auditor of what they see, and a decision api only \
                             compares with the one the round committed. The round's \
                             DISCLOSURE comes from api's own copy, never from this"
                    ))
                    .into_inner()
                }
            };
            Ok::<_, ApiError>(status)
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
                    return Err(StatusCode::INTERNAL_SERVER_ERROR.into());
                }
                status
            }
            // A failure, but the round's write may have landed first — the child
            // killed after its commit, a leg gone before its reply. If it did,
            // the session moved on all the same, and the applicant is answered
            // with where it now stands, which is what a reload would show them:
            // not an error inviting them to send this round's input again, to a
            // prompt it was never for. If nothing was written, the error stands.
            Err(e) => {
                committed(persister.decided().await, awaiting.lock().await.take()).ok_or(e)?
            }
        };
        Ok(progress_from(status, &locale))
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

/// Map a worker's [`ExecError`] to an HTTP-facing answer — a fixed answer per
/// value of a fixed enum.
///
/// It used to be a SUBSTRING SEARCH. The error was a `String` built with
/// `format!("{e:#}")` over the trap chain; this function looked for
/// "is not registered" and took whatever sat between the last two quotes before
/// it, then put that in a 422 body. Its own doc called it "fragile by nature" —
/// and it was worse than fragile: no engine error said "is not registered" (the
/// only producer was deleted in `7ccdbd9` and the search was left behind), so an
/// honest failure matched nothing, and the one input that DID match was a policy
/// putting the marker and quotes inside its own key. A scraper nobody could reach
/// except by injecting into it.
///
/// What the applicant is told, and why it is only this much. A 4xx says the fault
/// is not theirs — they can stop retrying and report it — and that is the whole of
/// what this side is willing to attribute. WHAT the policy did is authored by the
/// consumer's own wasm, so a field carrying it would be the policy choosing bytes
/// on a wire; WHICH ref it failed to declare is a string wasm picked and could be
/// a function of the applicant's own data. A 503 says nothing ran, so the same
/// request may be sent again.
///
/// The consumer, who could act on a diagnosis, deliberately gets none of this
/// here: a failure reason routed to them is an applicant-derived value reaching
/// the party that must not receive one outside a consent screen. That is its own
/// design and not a rider on an error mapping.
fn classify_run_error(session_id: &str, e: &ExecError) -> ApiError {
    safe_logger::debug!("session_run_ctx: executor.run failed for {session_id}: {e}");
    match e {
        // A fixed body. Nothing in it varies, so nothing in it is a channel.
        ExecError::Policy => ApiError::with_body(
            StatusCode::UNPROCESSABLE_ENTITY,
            serde_json::json!({
                "error": "policy_failed",
                "hint": "this session's verification policy failed during a round. \
                         Nothing the applicant did caused it, and retrying will not \
                         clear it; the policy's author has to fix and re-push it.",
            }),
        ),
        ExecError::Unknown => ApiError::Status(StatusCode::INTERNAL_SERVER_ERROR),
        // Nothing ran and nothing changed: the worker had no room for the round.
        // The one answer that means "the same request, later".
        ExecError::Busy => ApiError::Status(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// Map the compile hop's [`CompileError`] to an HTTP-facing answer — a fixed
/// answer per value of a fixed enum, as [`classify_run_error`] does for a round.
///
/// A refusal is the composition's and permanent: the compiler decided it from
/// the pinned bytes alone, so the answer is the 4xx a failing policy gets, with a
/// fixed body. Anything else is a 500: what failed may be the pins' or ours, and
/// this side cannot tell which.
fn classify_compile_error(session_id: &str, policy_ref: &str, e: CompileError) -> ApiError {
    safe_logger::debug!(
        "lookup_policy: compile failed for {session_id} (policy_ref {policy_ref}): {e}"
    );
    match e {
        // A fixed body. Nothing in it varies, so nothing in it is a channel.
        CompileError::Refused => ApiError::with_body(
            StatusCode::UNPROCESSABLE_ENTITY,
            serde_json::json!({
                "error": "policy_refused",
                "hint": "this session's verification policy, with the plugins the session \
                         pins, was refused by the compiler. Nothing the applicant did caused \
                         it, and retrying will not clear it; the policy, or the plugins \
                         pinned when the session was created, have to change.",
            }),
        ),
        CompileError::Failed => ApiError::Status(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

impl FromRequestParts<Arc<AppState>> for SessionRunCtx {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // Variable-shape routes — extract path params as a map and
        // pull the `id` key. Lets the same extractor work for
        // /connect (`{id}` only) and /input/{slot_id} alike without
        // committing to a per-route Path tuple shape here.
        let Path(params) = Path::<HashMap<String, String>>::from_request_parts(parts, state)
            .await
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        let session_id = params.get("id").cloned().ok_or(StatusCode::BAD_REQUEST)?;
        let CallerKey(applicant_session_token) =
            CallerKey::from_request_parts(parts, state).await?;
        // Applicant locale from `Accept-Language` — captured once per
        // request and threaded through view construction so every
        // text-ref resolves to the user's preferred language.
        let locale = Locale::from_request_parts(parts, state).await?;

        // Read metadata AND the prior state in ONE batched snapshot. Both are
        // always needed on /connect and /input, so batching saves a round-trip
        // (one HTTP-over-vsock + one Redis fetch instead of two), and it yields
        // ONE version coherent with both fields — the version that seeds the
        // persister then matches the metadata it also writes back. Not a
        // security property (the CAS is host-enforced); a consistency + latency
        // win.
        let ((metadata_untrusted, state_opt), version) = state
            .session_store
            .read(
                outbound_session_id(&session_id),
                (
                    Metadata,
                    StateField {
                        applicant_session_token: applicant_session_token.expose_secret(),
                    },
                ),
            )
            .await
            .map_err(|e| {
                // A state blob that won't open under this bearer is a wrong key /
                // different-device claim (the inner AEAD layer is keyed by the
                // applicant token) — the durable, cryptographic first-claim guard.
                // Metadata is sealed under tee_seal_key (NOT the applicant token),
                // so a Crypto error here is unambiguously the State field. Surface
                // it as 403 so the frontend offers `/reset`; everything else
                // (transport, codec) is a real 500. An ABSENT state is `Ok(None)`,
                // not an error, so a first `/connect` still proceeds.
                if matches!(e, hatch_client::BridgeError::Crypto(_)) {
                    return StatusCode::FORBIDDEN;
                }
                safe_logger::debug!(
                    "session_run_ctx: session_store.read(Metadata, State) failed for {session_id}: {e}",
                );
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        // Trust the metadata. Applicant flow has no per-tenant principal to
        // cross-check; security rides on the bearer-key auth layer + AEAD-
        // sealing under tee_seal_key/AAD=session_id (host tampering breaks the
        // seal at decode).
        let metadata = metadata_untrusted
            .trust_unchecked::<AuthZ, _>(reason!(
                r#"
Applicant flow doesn't authenticate per-tenant, so we have
no principal to cross-check here. Security relies on the
bearer-key auth layer at the route plus AEAD-binding on state
under applicant_session_token.
            "#
            ))
            .trust_unchecked::<Replay, _>(reason!(
                r#"
Metadata is NOT static — the persister mutates it each disclosure/media
round (captured_media, disclosure_count/entry_hashes, status) — so freshness is
UNVERIFIABLE here, not guaranteed: a stateless TEE cannot detect a
compromised host replaying an older (genuine, tee_seal_key-sealed,
AAD=session_id) snapshot. Safe because BOUNDED: the mutations are monotonic,
so a stale snapshot can only DROP entries — a later from-blob-ref then misses
the dropped capture and traps (session-local DoS), and a rewound disclosure
count surfaces as the consumer's own chain-verification failure. No leak
(host replays blobs it cannot read), no forgery (AEAD). Same containment as
the version vouch below (a lying host self-limits to DoS); full-coherent
rollback is an accepted residual of the host-holds-all-state model.
            "#
            ))
            .into_inner()
            .ok_or_else(|| {
                safe_logger::debug!("session_run_ctx: metadata is None for {session_id}");
                StatusCode::NOT_FOUND
            })?;

        let props = parse_props(&metadata)?;

        let session_state = state_opt
            .trust_unchecked::<Replay, _>(reason!(
                r#"
Stale state is bounded by per-call version-CAS during the run.
The first write on a stale snapshot fails with VersionMismatch
and the run aborts cleanly — replay from the latest persisted
state on retry.
            "#
            ))
            .into_inner();

        let version = version
            .trust_unchecked::<AuthN, _>(reason!(
                r#"
Version is a CAS token only. A lying host either fails our
writes (DoS) or stomps a concurrent winner (UX regression). No
data leak path.
            "#
            ))
            .trust_unchecked::<AuthZ, _>(reason!(
                r#"
Version counter is not an ownership signal — fed back as
expected_version on the next write, no access decision hangs on it.
            "#
            ))
            .trust_unchecked::<Replay, _>(reason!(
                r#"
Staleness on the version manifests as CAS mismatch on first
persist; same containment as above.
            "#
            ))
            .into_inner();

        // Compute the composition cache key — names the fused component in the
        // worker's L1 and keys the orchestrator's L2. The pull + compile is LAZY:
        // a worker L1 miss comes back as `RunOutcome::CacheMiss` and sends this
        // side into `run_resolved`, so nothing is compiled on the extractor
        // path.
        let composition_key = session_composition_key(&session_id, &metadata)?;

        // The recipient every disclosure this session seals to. Lifted here
        // because the extractor is where metadata is in hand; the persister that
        // uses it is built in `run`, which is the first point that knows what
        // the round consented to.
        let disclosure_pubkey = metadata
            .client
            .as_ref()
            .map(|c| c.disclosure_pubkey.clone())
            .ok_or_else(|| {
                safe_logger::debug!("session_run_ctx: metadata.client missing for {session_id}",);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        // The live host blob store: the worker's `blob::from-blob-ref` reads
        // sealed captures back through this (via the `media_load` callback) — a
        // pull-through cache over the hatch backing, gated by the session's
        // captured-hash set (from sealed metadata, prior rounds) so a fabricated
        // ref is refused without a hatch read. Same session keys as the
        // persister that WROTE them.
        let captured: HashSet<[u8; 32]> = metadata
            .captured_media
            .iter()
            .filter_map(|h| <[u8; 32]>::try_from(h.as_slice()).ok())
            .collect();
        let media_store = Arc::new(HatchMediaStore {
            session_store: state.session_store.clone(),
            session_id: session_id.clone(),
            // Weak: the strong lives in the SessionRunCtx below (sole owner).
            applicant_session_token: Arc::downgrade(&applicant_session_token),
            captured,
        });

        Ok(SessionRunCtx {
            state: state.clone(),
            session_id,
            session_state,
            locale,
            // Move the sole strong ref in — the media store above holds only a
            // `Weak` downgraded from it, and so will the persister `run` builds.
            applicant_session_token,
            disclosure_pubkey,
            version,
            media_store,
            props,
            composition_key,
            metadata,
        })
    }
}

/// Compute the composition cache key for a session — `sha256(policy_ref ‖
/// ordered plugin pins ‖ access authority)`. It is a pure function of the pinned
/// artifacts (nothing session-specific), so it (a) names the fused component in
/// the execution-worker's L1 cache — every session pinning the same policy +
/// plugins shares ONE compile — and (b) keys the orchestrator's L2 (paired with
/// the worker's `compat_token`). NO pull or compile happens here; that is lazy,
/// driven by [`run_resolved`] when the worker reports an L1 miss.
fn session_composition_key(
    session_id: &str,
    metadata: &SessionMetadata,
) -> Result<CompositionKey, StatusCode> {
    let client = metadata.client.as_ref().ok_or_else(|| {
        safe_logger::debug!("session_composition_key: metadata.client missing for {session_id}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(composition_key(
        &metadata.policy_ref,
        metadata.policy_key.as_ref(),
        &client.registry_auth,
        &client.plugins,
    ))
}

/// Resolve the compiled bundle for `(composition_key, compat_token)` and run the
/// round with it — what api does with a worker's cache miss. This is the ONE
/// place a compile is triggered: the orchestrator holds no in-memory component
/// cache, so it opens L2 (or compiles) each time the worker's L1 misses.
///
///   * L2 hit: the bundle goes to the worker straight from the cache, a piece at
///     a time, so api never holds the cwasm. An entry found bad on the way — it
///     did not open, or did not hold what its header said — fails this round as
///     any infra fault does, and is dropped, so the next miss compiles afresh.
///     The round is not retried here: the worker answers a bundle it refused as
///     it answers a round that failed after running, so this side cannot know
///     that nothing ran.
///   * L2 miss: cold-compile (OCI pull + compile-worker), then the worker and the
///     cache take the cwasm at once as it streams back from the compiler
///     ([`crate::tee`]), so api never holds it whole here either. A cache that
///     cannot keep it costs the next miss a compile; the round goes on. A cwasm
///     that is not what the compiler named reaches both as an abandoned stream,
///     and neither keeps it.
///
/// The outer error is resolution's, the inner the round's. Concurrent misses are
/// not coalesced: each round resolves and streams its own bundle, the worker
/// stages each one and runs every round on the first it commits; a cross-worker
/// race just re-reads L2 or double-compiles (idempotent write), acceptable and
/// rare.
async fn run_resolved<C>(
    state: &AppState,
    composition_key: &CompositionKey,
    compat_token: &CompatToken,
    session_id: &str,
    metadata: &SessionMetadata,
    req: Exposed<RunRequest, ()>,
    callbacks: C,
) -> Result<Result<Untrusted<RunStatus, C::Scope>, ExecError>, ApiError>
where
    C: CallbackServiceUntrusted + Send + Sync + 'static,
    C::Scope: Send,
{
    if let Some(hit) = cwasm_cache::open(&state.cache_store, composition_key, compat_token).await {
        let cwasm_cache::Hit { source, found_bad } = hit;
        let reply = state.executor.run_with_bundle(req, source, callbacks).await;
        if found_bad.get() {
            cwasm_cache::remove(&state.cache_store, composition_key, compat_token).await;
        }
        return Ok(reply);
    }
    let client = metadata.client.as_ref().ok_or_else(|| {
        safe_logger::debug!("run_resolved: metadata.client missing for {session_id}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let crate::compiler::Compiled {
        meta,
        cwasm_len,
        cwasm_sha256,
        cwasm,
    } = cold_compile(state, session_id, metadata, client).await?;
    let (feed, to_worker, to_cache) = crate::tee::tee(cwasm);
    let source = BundleSource::streamed(cwasm_len, cwasm_sha256, meta.clone(), to_worker)
        .ok_or_else(|| {
            safe_logger::debug!(
                "run_resolved: a bundle past the execute hop's bounds for {session_id}"
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let entry = cwasm_cache::Entry {
        meta: &meta,
        cwasm_len,
        cwasm_sha256,
        cwasm: to_cache,
    };
    let (reply, (), ()) = tokio::join!(
        state.executor.run_with_bundle(req, source, callbacks),
        cwasm_cache::store(&state.cache_store, composition_key, compat_token, entry),
        feed,
    );
    Ok(reply)
}

/// Cold path: pull the policy + pinned plugins (the orchestrator owns OCI +
/// registry auth), then hand the bytes to the [`Compiler`](crate::compiler::Compiler)
/// boundary, which fuses + compiles + parses sections into a cwasm and its
/// metadata, the cwasm streaming back as it comes.
/// Runs only on an L2 miss — [`run_resolved`] calls this, then sends the result
/// to the worker on `run_with_bundle` and to L2 at once.
///
/// Errors are the round's answer, returned as they are:
///   * 410 Gone — registry pull / decrypt failed (artifact removed / malformed)
///   * 422 — the compiler refused the composition; the same pins always are
///   * 500 — anything else in the compile, or an infra problem
async fn cold_compile(
    state: &AppState,
    session_id: &str,
    metadata: &SessionMetadata,
    client: &Client,
) -> Result<crate::compiler::Compiled, ApiError> {
    // Look up the bearer for the policy registry by hostname. Same
    // lookup applies per plugin below. Missing entry collapses to an
    // empty slice ⇒ anonymous pull (host attaches no Authorization
    // header).
    let policy_bearer = policy_pull::bearer_for_ref(&client.registry_auth, &metadata.policy_ref);

    // Context for the `kbs` key path: the hatch relay client that
    // couriers each RCAR leg. Shared by the policy and every plugin pull;
    // inline / plaintext artifacts ignore it.
    let kbs_ctx = crate::keyprovider::KbsContext { kbs: &state.kbs };

    // Every manifest first, concurrently, with every key it needs: all that
    // can be refused before a byte of wasm moves, so the /connect critical
    // path waits on the slowest of them rather than on their sum.
    let policy_fut = policy_pull::wasm_layer(
        &state.registry,
        &metadata.policy_ref,
        policy_bearer,
        metadata.policy_key.as_ref(),
        Some(&kbs_ctx),
    );
    let plugin_futs = client.plugins.iter().map(|pin| {
        let bearer = policy_pull::bearer_for_ref(&client.registry_auth, &pin.impl_ref);
        let registry = &state.registry;
        let kbs_ctx = &kbs_ctx;
        async move {
            policy_pull::wasm_layer(
                registry,
                &pin.impl_ref,
                bearer,
                pin.key.as_ref(),
                Some(kbs_ctx),
            )
            .await
            .map(|layer| (pin.package.clone(), layer))
        }
    });
    let (policy_res, plugin_results) =
        futures::future::join(policy_fut, futures::future::join_all(plugin_futs)).await;

    let policy = policy_res.map_err(|e| {
        safe_logger::debug!(
            "lookup_policy: the policy's manifest failed for session {session_id} \
             (policy_ref={}): {e}",
            metadata.policy_ref,
        );
        StatusCode::GONE
    })?;
    let mut plugins = Vec::with_capacity(plugin_results.len());
    for res in plugin_results {
        plugins.push(res.map_err(|e| {
            safe_logger::debug!(
                "lookup_policy: a plugin's manifest failed for session {session_id}: {e}"
            );
            StatusCode::GONE
        })?);
    }

    // Then the layers themselves, one after another in composition order —
    // policy first — as one stream into the COMPILE boundary: each fetched
    // when the one before it has been read, so no fetch waits half-read on
    // another. The compile-worker fuses + compiles + parses sections into a
    // cwasm and its metadata (the i18n/icons import manifest + per-component
    // catalogs, composition order), starting only once every component has
    // arrived whole. [`run_resolved`] passes the cwasm on to L2 and to the
    // execution-worker as it streams back; the worker files it in its own L1.
    //
    // A layer that turns out not to be what its manifest pinned ends the stream
    // in an error, which the compile answers as a failure; marked here, so the
    // round answers it as the pull failure it is, 410, as a manifest's would be.
    let policy_length = policy.length();
    let lengths = plugins
        .iter()
        .map(|(package, layer)| (package.clone(), layer.length()))
        .collect();
    let pull_failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let marked = pull_failed.clone();
    let layers = std::iter::once(policy).chain(plugins.into_iter().map(|(_, layer)| layer));
    let components = futures::stream::iter(layers)
        .flat_map(policy_pull::WasmLayer::pieces)
        .inspect_err(move |e| {
            safe_logger::debug!("lookup_policy: a layer did not arrive as pinned: {e}");
            marked.store(true, std::sync::atomic::Ordering::Relaxed);
        });
    let source = CompileSource::streamed(policy_length, lengths, components);
    let compiled = match source {
        Some(source) => state.compiler.compile(source).await,
        None => Err(CompileError::Refused),
    };
    compiled.map_err(|e| {
        if pull_failed.load(std::sync::atomic::Ordering::Relaxed) {
            StatusCode::GONE.into()
        } else {
            classify_compile_error(session_id, &metadata.policy_ref, e)
        }
    })
}

/// Content-address of a fused composition: each artifact (policy + ORDERED
/// plugins) as `(ref, ACCESS-AUTHORITY)`. The compiled [`PolicyEntry`] (fused
/// `Component` + `EmbeddedRegistry` + import manifest) is a pure function of the
/// pulled-and-decrypted artifact bytes and nothing session-specific, so it is
/// the right cache key — two sessions pinning the same artifacts (and equally
/// authorized to OBTAIN them) share one pull + fuse + Cranelift compile.
///
/// **Access authority is in the key, because a cache HIT bypasses the two gates
/// a MISS goes through** (download, then decrypt) — it hands back the already
/// pulled-and-decrypted component with no credential presented. Keying by
/// artifact identity ALONE would let a consumer who could neither download nor
/// decrypt an artifact obtain its compiled form via another consumer's entry. So
/// per artifact we mix in BOTH gates:
///   * **Download authority** — the per-hostname OCI bearer
///     ([`policy_pull::bearer_for_ref`]). For a third-party LICENSED plugin this
///     IS the license: the author grants pull only to licensed clients. Empty
///     (anonymous / public) → all share; non-empty → `sha256(bearer)` so only
///     credential-holders share and a non-holder misses → pulls → fails closed.
///   * **Decrypt authority** — the [`Key`]: `None` (plaintext) shares; `Inline`
///     (owner secret) mixes `sha256(bytes)`; `Kbs` a marker only. Encryption's
///     job is secrecy from the PLATFORM (KBS releases only to the attested TEE),
///     NOT per-client licensing — that's the download gate above — so `Kbs`
///     needs no per-client credential here. (A future metered/licensed KBS model
///     keeps its license token OUT of this key too: the KBS is consulted EVERY
///     session as the license/metering gate, and a successful response is the
///     precondition to REUSE the cached compile — the cache only ever skips the
///     decrypt+compile, never the per-session license check.)
/// Both secrets are HASHED, never embedded raw (the cache is TEE-only anyway).
///
/// Order matters (fusion order fixes merged first-match), so pins are hashed in
/// `client.plugins` order; every field is length-prefixed against
/// delimiter-collision. wasmtime version is excluded (in-process, one `Runner`
/// engine; a restart empties the cache). Assumes refs are effectively immutable
/// content-addresses (digest-pinned); a consumer pinning a MUTABLE tag could be
/// served a stale compilation within the cache TTL — a freshness tradeoff.
fn composition_key(
    policy_ref: &str,
    policy_key: Option<&Key>,
    registry_auth: &HashMap<String, Vec<u8>>,
    plugins: &[PluginPin],
) -> CompositionKey {
    let mut h = Sha256::new();
    hash_artifact(
        &mut h,
        policy_ref,
        policy_key,
        policy_pull::bearer_for_ref(registry_auth, policy_ref),
    );
    h.update((plugins.len() as u64).to_le_bytes());
    for p in plugins {
        h.update((p.package.len() as u64).to_le_bytes());
        h.update(p.package.as_bytes());
        hash_artifact(
            &mut h,
            &p.impl_ref,
            p.key.as_ref(),
            policy_pull::bearer_for_ref(registry_auth, &p.impl_ref),
        );
    }
    // Handed to the type as a DIGEST, not as a rendering of one. There is no
    // fallible constructor to get this wrong with: what leaves here has the shape
    // the worker's decoder demands because it could not have had another.
    CompositionKey::from_digest(h.finalize().into())
}

/// Feed one artifact's `(ref, download authority, decrypt authority)` into the
/// composition hash. See [`composition_key`] for the rationale.
fn hash_artifact(h: &mut Sha256, artifact_ref: &str, key: Option<&Key>, download_cred: &[u8]) {
    h.update((artifact_ref.len() as u64).to_le_bytes());
    h.update(artifact_ref.as_bytes());
    // Download authority: empty (anonymous / public) shares; otherwise partition
    // by sha256(bearer) so only credential-holders share (the license gate for
    // a download-gated third-party artifact).
    if download_cred.is_empty() {
        h.update([0x00u8]);
    } else {
        h.update([0x01u8]);
        let digest = Sha256::digest(download_cred);
        h.update((digest.len() as u64).to_le_bytes());
        h.update(digest);
    }
    // Decrypt authority.
    match key {
        None => h.update([0x00u8]),
        Some(Key::Inline(bytes)) => {
            h.update([0x01u8]);
            let digest = Sha256::digest(bytes);
            h.update((digest.len() as u64).to_le_bytes());
            h.update(digest);
        }
        Some(Key::Kbs(_)) => h.update([0x02u8]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hatch_client::{MediaSpec, PromptDisclosure};

    /// A worker with no room is the one failure that says "the same request,
    /// later" — an empty 503, nothing for a policy to have chosen.
    #[test]
    fn a_busy_worker_is_a_503() {
        assert!(matches!(
            classify_run_error("ses_test", &ExecError::Busy),
            ApiError::Status(StatusCode::SERVICE_UNAVAILABLE)
        ));
    }

    /// A refused composition is its pins' to fix — the fixed 422 a failing
    /// policy gets; any other compile failure stays a 500.
    #[test]
    fn a_refused_composition_is_a_422() {
        assert!(matches!(
            classify_compile_error("ses_test", "r/p@sha256:00", CompileError::Refused),
            ApiError::StatusWithBody(StatusCode::UNPROCESSABLE_ENTITY, _)
        ));
        assert!(matches!(
            classify_compile_error("ses_test", "r/p@sha256:00", CompileError::Failed),
            ApiError::Status(StatusCode::INTERNAL_SERVER_ERROR)
        ));
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

    fn consent_prompt(key: &str) -> Prompt {
        Prompt::ConsentDisclosure(PromptDisclosure {
            fields: vec![DisplayField {
                key: key.into(),
                label: Default::default(),
                value: "v".into(),
            }],
            ..Default::default()
        })
    }

    fn metadata(
        status: SessionStatus,
        decision: Option<hatch_client::Decision>,
    ) -> SessionMetadata {
        SessionMetadata {
            status,
            decision,
            ..Default::default()
        }
    }

    fn waiting_on(prompt: Prompt) -> SessionState {
        SessionState {
            current_prompt: Some(prompt),
            ..Default::default()
        }
    }

    /// The decision it was given, and no round — whatever its state still holds.
    #[test]
    fn a_completed_session_answers_with_its_decision() {
        let state = waiting_on(consent_prompt("dob"));
        let standing = standing(
            &metadata(
                SessionStatus::Completed,
                Some(hatch_client::Decision::Rejected),
            ),
            Some(&state),
            &Locale::default(),
        );
        assert!(matches!(
            standing,
            Ok(Some(SessionProgress::Completed {
                decision: crate::dto::DecisionView::Rejected
            }))
        ));
    }

    /// Never "start over" for a session that has finished.
    #[test]
    fn a_completed_session_without_its_decision_is_an_error_not_a_rerun() {
        let standing = standing(
            &metadata(SessionStatus::Completed, None),
            None,
            &Locale::default(),
        );
        assert_eq!(standing.err(), Some(StatusCode::INTERNAL_SERVER_ERROR));
    }

    /// Reopening the link carries on from the screen the applicant was on.
    #[test]
    fn a_started_session_answers_with_the_prompt_it_waits_on() {
        let state = waiting_on(Prompt::Media(MediaSpec::default()));
        let standing = standing(
            &metadata(SessionStatus::Running, None),
            Some(&state),
            &Locale::default(),
        );
        assert!(matches!(
            standing,
            Ok(Some(SessionProgress::AwaitingInput { .. }))
        ));
    }

    /// The one case `/connect` still runs: no round has reached the session.
    #[test]
    fn a_fresh_session_has_no_standing() {
        let running = metadata(SessionStatus::Running, None);
        assert!(matches!(
            standing(&running, None, &Locale::default()),
            Ok(None)
        ));
        assert!(matches!(
            standing(&running, Some(&SessionState::default()), &Locale::default()),
            Ok(None)
        ));
    }

    /// The only shape that seals, and it seals the screen's own fields.
    #[test]
    fn an_accepted_consent_seals_exactly_the_screen_it_answered() {
        let fields = consent_for_round(
            &Event::ConsentDisclosure(true),
            &Some(consent_prompt("dob")),
        )
        .expect("an accepted consent seals");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].key, "dob");
    }

    /// A decline is a first-class answer, and it shares nothing.
    #[test]
    fn a_declined_consent_seals_nothing() {
        assert!(
            consent_for_round(
                &Event::ConsentDisclosure(false),
                &Some(consent_prompt("dob")),
            )
            .is_none()
        );
    }

    /// The accept has to be answering a consent screen. Every other round —
    /// a capture, the genesis round, a session that has rendered nothing —
    /// seals nothing, whatever else happens during it.
    #[test]
    fn no_consent_screen_means_no_seal() {
        for prompt in [None, Some(Prompt::Media(MediaSpec::default()))] {
            assert!(consent_for_round(&Event::ConsentDisclosure(true), &prompt).is_none());
        }
        assert!(consent_for_round(&Event::Start, &Some(consent_prompt("dob"))).is_none());
    }

    fn pin(package: &str, impl_ref: &str) -> PluginPin {
        PluginPin {
            package: package.into(),
            impl_ref: impl_ref.into(),
            key: None,
        }
    }

    /// Empty registry-auth map = anonymous pull for every artifact.
    fn no_auth() -> HashMap<String, Vec<u8>> {
        HashMap::new()
    }

    #[test]
    fn composition_key_deterministic_and_order_sensitive() {
        let plugins = [
            pin("enclavid:well-known", "reg/wk@sha256:11"),
            pin("enclavid:face-age", "reg/fa@sha256:22"),
        ];
        let key = composition_key("reg/policy@sha256:aa", None, &no_auth(), &plugins);

        // Same composition → same key (the whole point: cross-session sharing).
        assert_eq!(
            key,
            composition_key("reg/policy@sha256:aa", None, &no_auth(), &plugins)
        );

        // Plugin ORDER is significant (fusion order fixes merged first-match) →
        // reversing must change the key.
        let reversed = [plugins[1].clone(), plugins[0].clone()];
        assert_ne!(
            key,
            composition_key("reg/policy@sha256:aa", None, &no_auth(), &reversed)
        );

        // Different policy ref → different key.
        assert_ne!(
            key,
            composition_key("reg/policy@sha256:bb", None, &no_auth(), &plugins)
        );

        // Different plugin set (dropping one) → different key.
        assert_ne!(
            key,
            composition_key("reg/policy@sha256:aa", None, &no_auth(), &plugins[..1])
        );
    }

    #[test]
    fn composition_key_length_prefixed_no_delimiter_collision() {
        // Without length-prefixing, field boundaries could be ambiguous: a
        // policy ref "ab" + package "c" would concat-collide with ref "a" +
        // package "bc". Length-prefixing must keep them distinct.
        let a = composition_key("ab", None, &no_auth(), &[pin("c", "r")]);
        let b = composition_key("a", None, &no_auth(), &[pin("bc", "r")]);
        assert_ne!(a, b);
    }

    #[test]
    fn composition_key_partitions_by_decryption_authority() {
        use hatch_client::{KbsKey, Key};
        let plugins = [pin("p", "r")];
        let none = composition_key("policy", None, &no_auth(), &plugins);
        let inline_a = composition_key(
            "policy",
            Some(&Key::Inline(vec![1, 2, 3])),
            &no_auth(),
            &plugins,
        );
        let inline_b = composition_key(
            "policy",
            Some(&Key::Inline(vec![9, 9, 9])),
            &no_auth(),
            &plugins,
        );

        // Plaintext (None) and encrypted (Inline) are distinct scopes, and two
        // different Inline keys never share — a non-holder can't hit a holder's
        // entry (the whole point: a cache hit must not bypass decrypt auth).
        assert_ne!(none, inline_a);
        assert_ne!(inline_a, inline_b);
        // Same Inline key → same key: key-holders DO share.
        assert_eq!(
            inline_a,
            composition_key(
                "policy",
                Some(&Key::Inline(vec![1, 2, 3])),
                &no_auth(),
                &plugins
            )
        );

        // Kbs is attestation-gated (every TEE session equally authorized), so it
        // does NOT partition by endpoint — that would only reduce sharing.
        let kbs_a = composition_key(
            "policy",
            Some(&Key::Kbs(KbsKey {
                endpoint: "a".into(),
            })),
            &no_auth(),
            &plugins,
        );
        let kbs_b = composition_key(
            "policy",
            Some(&Key::Kbs(KbsKey {
                endpoint: "b".into(),
            })),
            &no_auth(),
            &plugins,
        );
        assert_eq!(kbs_a, kbs_b);
    }

    #[test]
    fn composition_key_partitions_by_download_authority() {
        // The OCI download bearer is the license for a download-gated third-party
        // artifact: a cache HIT skips the pull, so a non-holder must not hit a
        // holder's entry.
        let pol = "reg.example.com/policy@sha256:aa";
        let plugins = [pin("p", "reg.example.com/plug@sha256:11")];

        let anon = composition_key(pol, None, &no_auth(), &plugins);

        let mut auth_a = HashMap::new();
        auth_a.insert("reg.example.com".to_string(), b"licensed-A".to_vec());
        let holder_a = composition_key(pol, None, &auth_a, &plugins);
        // A bearer-holder computes a DIFFERENT key than the anonymous non-holder.
        assert_ne!(anon, holder_a);

        // A different bearer → a different scope (different licenses don't share).
        let mut auth_b = HashMap::new();
        auth_b.insert("reg.example.com".to_string(), b"licensed-B".to_vec());
        assert_ne!(holder_a, composition_key(pol, None, &auth_b, &plugins));

        // Same bearer → same key (co-licensed clients share the compile).
        assert_eq!(holder_a, composition_key(pol, None, &auth_a, &plugins));
    }
}
