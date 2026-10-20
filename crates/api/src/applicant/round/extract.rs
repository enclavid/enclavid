//! Loading a session for a round — what [`SessionRunCtx`] is extracted from — and
//! the answer of one that has ended, given before any handler sees it.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::extract::{FromRequestParts, Path};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use secrecy::ExposeSecret;

use enclavid_boundary::{AuthN, AuthZ, Replay, reason};
use engine_rpc::CompositionKey;
use session_types::{SessionMetadata, SessionStatus};
use storage_client::{Metadata, State as StateField};

use crate::applicant::auth::CallerKey;
use crate::applicant::media_store::HatchMediaStore;
use crate::applicant::views::SessionProgress;
use crate::compositions::composition_key;
use crate::init;
use crate::locale::Locale;
use crate::state::AppState;

use super::SessionRunCtx;

/// The answer of a session that has ended, `None` for one that runs on. An
/// ended session runs no more rounds, and is answered here before any handler
/// sees it, on every route that runs one:
///   * one that could not be prepared to run, as the request that found that out
///     was ([`init::answer`]);
///   * a completed one, with the decision it was given. A second run could reach
///     `finish` a second time — another disclosure sealed, the decision the
///     consumer already read rewritten.
fn ended(metadata: &SessionMetadata) -> Option<Response> {
    match metadata.status {
        SessionStatus::InitFailed => {
            // Written together, by `init::record` alone.
            let status = metadata
                .init_error
                .as_ref()
                .map_or(StatusCode::INTERNAL_SERVER_ERROR, init::answer);
            Some(status.into_response())
        }
        SessionStatus::Completed => Some(match metadata.decision {
            Some(decision) => SessionProgress::Completed {
                decision: decision.into(),
            }
            .into_response(),
            // The round that finishes commits the two together.
            None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }),
        _ => None,
    }
}

impl FromRequestParts<Arc<AppState>> for SessionRunCtx {
    /// A failure to load the session, as a status; or the answer of a session
    /// that has [`ended`].
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let ctx = Self::load(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;
        match ended(&ctx.metadata) {
            Some(answer) => Err(answer),
            None => Ok(ctx),
        }
    }
}

impl SessionRunCtx {
    async fn load(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, StatusCode> {
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
                &session_id,
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
                // Surface it as 403 so the frontend offers `/reset`; everything
                // else (transport, codec) is a real 500. A Crypto error is also
                // what a host gets by altering the metadata or the state's outer
                // layer, both sealed under tee_seal_key: it then reads as the
                // wrong device, which costs the session no more than the host
                // deleting the state would. An ABSENT state is `Ok(None)`, not an
                // error, so a first `/connect` still proceeds.
                if matches!(e, storage_client::StoreError::Crypto(_)) {
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
            .trust(reason!(
                AuthZ::Matched,
                r#"
Applicant flow doesn't authenticate per-tenant, so there is no
principal to cross-check here. The match is upstream: the
bearer-key auth layer at the route, plus AEAD-binding on state
under applicant_session_token.
            "#
            ))
            .trust_accept_risk(reason!(
                Replay::AcceptedRisk,
                r#"
Metadata is NOT static — the persister mutates it each disclosure/media
round (captured_media, disclosure_count/entry_hashes, status) — and a
stateless TEE cannot tell a genuine older snapshot (sealed under
tee_seal_key, AAD=session_id) from the latest. A rollback of the session's
whole record — metadata, state and version restored together — passes the
version's CAS as well. Most of what it rewinds only drops entries: a later
from-blob-ref misses the dropped capture and traps, and a rewound disclosure
count fails the consumer's own chain check. But it also brings back `Running`
for a session that finished, so `ended` lets a round through and the policy
can reach `finish` again — another disclosure sealed, the decision the
consumer already read rewritten. Closing that needs a freshness source outside
the host, as `client::disclosures` says of the same rollback.
            "#
            ))
            .into_inner()
            .ok_or_else(|| {
                safe_logger::debug!("session_run_ctx: metadata is None for {session_id}");
                StatusCode::NOT_FOUND
            })?;

        let session_state = state_opt
            .trust(reason!(
                Replay::Fresh,
                r#"
Stale state is bounded by per-call version-CAS during the run.
The first write on a stale snapshot fails with VersionMismatch
and the run aborts cleanly — replay from the latest persisted
state on retry.
            "#
            ))
            .into_inner();

        let version = version
            .trust(reason!(
                AuthN::Indifferent,
                r#"
Version is a CAS token only. A lying host either fails our
writes (DoS) or stomps a concurrent winner (UX regression). No
data leak path.
            "#
            ))
            .trust(reason!(
                AuthZ::NoPrincipal,
                r#"
Version counter is not an ownership signal — fed back as
expected_version on the next write, no access decision hangs on it.
            "#
            ))
            .trust(reason!(
                Replay::Fresh,
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
            composition_key,
            metadata,
        })
    }
}

/// Compute the composition cache key for a session — `sha256(policy_ref ‖
/// ordered plugin pins ‖ decrypt keys)`. It is a pure function of the pinned
/// artifacts (nothing session-specific), so it (a) names the fused component in
/// the execution-worker's L1 cache — every session pinning the same policy +
/// plugins shares ONE compile — and (b) keys the orchestrator's L2 (paired with
/// the worker's `compat_token`). NO pull or compile happens here; that comes
/// when the worker reports an L1 miss, to a session's preparation
/// (`crate::init::prepare`) or to a round (`run_resolved`).
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
        &client.plugins,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use session_types::{Artifact, Decision, InitError, PullProblem};

    /// What an ended session is answered with in place of a round, `None` for
    /// one that runs on.
    async fn answer_of(metadata: &SessionMetadata) -> Option<(StatusCode, String)> {
        let response = ended(metadata)?;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the body");
        Some((
            status,
            String::from_utf8_lossy(&body).trim_end().to_string(),
        ))
    }

    /// A session that could not be prepared is answered as the request that
    /// found that out was; without the error it was marked with, it is not a
    /// state this code produces, and nothing runs on it either.
    #[tokio::test]
    async fn a_session_that_failed_init_runs_nothing() {
        let failed = SessionMetadata {
            status: SessionStatus::InitFailed,
            init_error: Some(InitError::Pull {
                artifact: Artifact::Plugin("enclavid:extra@0.1.0".into()),
                problem: PullProblem::Refused,
            }),
            ..Default::default()
        };
        assert_eq!(answer_of(&failed).await.unwrap().0, StatusCode::GONE);
        let unmarked = SessionMetadata {
            init_error: None,
            ..failed
        };
        assert_eq!(
            answer_of(&unmarked).await.unwrap().0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    /// A completed session answers with its decision and runs nothing; one
    /// without its decision is not a state this code produces. A running one
    /// goes on to its round.
    #[tokio::test]
    async fn a_completed_session_answers_with_its_decision() {
        let completed = SessionMetadata {
            status: SessionStatus::Completed,
            decision: Some(Decision::Rejected),
            ..Default::default()
        };
        assert_eq!(
            answer_of(&completed).await,
            Some((
                StatusCode::OK,
                r#"{"status":"completed","decision":"rejected"}"#.to_string()
            ))
        );
        let undecided = SessionMetadata {
            decision: None,
            ..completed
        };
        assert_eq!(
            answer_of(&undecided).await.unwrap().0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let running = SessionMetadata {
            status: SessionStatus::Running,
            ..Default::default()
        };
        assert_eq!(answer_of(&running).await, None);
    }
}
