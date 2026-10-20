//! The api side of the keyless execution-worker's callback boundary.
//!
//! During a run the worker calls BACK over the same remoc connection: `media_load`
//! to rehydrate a stored blob, and `session_change` to seal + persist the
//! post-round state — with, on the round that finishes, the policy's decision,
//! committed in the same write. Neither what the round disclosed nor what it
//! captured arrives here — the orchestrator holds both already.
//! [`CallbackServer`] wires those to the per-round [`SessionPersister`] +
//! [`HatchMediaStore`] (they hold the seal key + applicant token). It
//! implements `engine_rpc::RemoteCallbacksAt` at api's end of the leg; the
//! orchestrator stands one up per run and passes its client into
//! `RemoteExecutor::run` (see [`crate::executor`]).
//!
//! Bundle resolution is deliberately NOT a callback here. The composition is known
//! before the run, so the orchestrator resolves the compiled bundle UP FRONT (see
//! `SessionRunCtx::run`, on a `RunOutcome::CacheMiss`) under the `composition_key`
//! IT computed — the worker never names a cache slot, which closes the L2
//! cache-poisoning vector and keeps the OCI-pull / compile probe surface off the
//! worker entirely.
//!
//! ## Why this leg is judged `Asserted`, and not by one of the other four
//!
//! api typed its hatch and storage legs as untrusted and left the worker legs
//! bare — the ones reaching the process that runs adversary-authored wasm. Four
//! defects found by review turned out to be one defect four times, all there.
//! None of the existing markers asks the question they turned on:
//!
//!   * `AuthN` asks who produced the bytes. Mutual RA-TLS against a pinned
//!     measurement already answers that, and more strongly than a per-value check
//!     could. Nobody substituted these bytes — that is the problem. Discharging it
//!     here would be easy, true, cryptographic, and would say nothing about
//!     whether a prompt's fields are the ones the applicant approved.
//!   * `AuthZ` asks whether a principal may reach a resource. The worker is
//!     obviously allowed to write into the session it is running, and there is no
//!     principal on the return path at all.
//!   * `Replay` asks whether this is a stale snapshot. A remoc call over a TLS
//!     stream has no versions and no store to be stale from.
//!   * `Covert` is outbound-only by construction.
//!
//! How api judges this leg is declared once, on its end of it
//! (`crate::boundary::ExecutionWorker`), rather than in the contract, because it
//! is not a property of the bytes: the same `SessionState` from this worker and
//! from a peer that runs no adversary code carries a different scope. Two
//! consumers of one contract may disagree, each rightly about its own position.
//!
//! It does not follow the value everywhere, either. `current_prompt` reaches
//! `consent::for_round` on the NEXT round out of the sealed store rather than over
//! this leg, and the double AEAD legitimately closes AuthN/AuthZ over a blob the
//! worker authored — so the store launders the provenance, and this end's scope
//! says nothing about that field where it is finally read.

use std::sync::Arc;

use enclavid_boundary::{Asserted, Exposed, Untrusted};
use engine_rpc::{CallbackError, Committed, MediaBytes, MediaHash, Padded, RemoteCallbacksAt};
use session_types::{Decision, SessionState};

use super::media_store::HatchMediaStore;
use super::persister::SessionPersister;
use crate::boundary::ExecutionWorker;

/// A value a worker produced, open on what api's end leaves open on it. Whether
/// it came back from a call api made or arrived on a callback api serves makes no
/// difference: both are the worker's own word.
pub(super) type FromWorker<T> = Untrusted<T, (Asserted,), ExecutionWorker>;

/// Per-run callback target: delegates the callback methods to the seal-key-holding
/// persister + media store. One per round (both are per-round).
#[derive(Clone)]
pub(super) struct CallbackServer {
    pub(super) persister: Arc<SessionPersister>,
    pub(super) media_store: Arc<HatchMediaStore>,
}

impl RemoteCallbacksAt<ExecutionWorker> for CallbackServer {
    /// The hash arrives open and the blob leaves answered — this method is a
    /// crossing in BOTH directions, which is why the media store owns both halves:
    /// the gate that answers for the hash is the same predicate that makes the
    /// reply's `AuthZ` true.
    async fn media_load(
        &self,
        hash: FromWorker<MediaHash>,
    ) -> Result<Exposed<Option<MediaBytes>, (), ExecutionWorker>, CallbackError> {
        self.media_store.load(hash).await
    }

    /// Both arrive answered: api's end declares that the state is sealed verbatim
    /// and handed back only to its author, and that the verdict is the policy's to
    /// choose — the worker's word is all it ever was. api commits it as that, and
    /// checks the round's reply against it.
    ///
    /// Two separate questions, and closing one says nothing about the other. The
    /// frame answers "did the length tell the host anything" — settled by the wire
    /// type, on a hop api only receives on. The scope answers "whose word is the
    /// CONTENT".
    async fn session_change(
        &self,
        state: Untrusted<Padded<SessionState>, (), ExecutionWorker>,
        decision: Untrusted<Padded<Option<Decision>>, (), ExecutionWorker>,
    ) -> Result<Exposed<Committed, (), ExecutionWorker>, CallbackError> {
        let state = state.into_inner().open()?;
        let decision = decision.into_inner().open()?;
        self.persister.persist(state, decision).await?;
        Ok(ExecutionWorker::expose(Committed))
    }
}
