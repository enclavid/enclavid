//! The api side of the keyless execution-worker's callback boundary.
//!
//! During a run the worker calls BACK over the same remoc connection: `media_load`
//! to rehydrate a stored blob, and `session_change` to seal + persist the
//! post-round state. Neither what the round disclosed nor what it captured
//! arrives here — the orchestrator holds both already. [`CallbackServer`] wires those
//! to the per-round [`SessionPersister`] + [`HatchMediaStore`] (they hold the seal
//! key + applicant token). It implements `engine_rpc::CallbackService`; the
//! orchestrator stands one up per run and passes its client into
//! `ExecutorService::run` (see [`crate::executor`]).
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
//! api types its hatch and storage legs as untrusted and left the worker legs
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
//! The scope is declared HERE rather than in the contract because it is not a
//! property of the bytes: the same `SessionState` from this worker and from a peer
//! that runs no adversary code carries a different one. Two consumers of one
//! contract may disagree, each rightly about its own position.
//!
//! It does not follow the value everywhere, either. `current_prompt` reaches
//! `consent_for_round` on the NEXT round out of the sealed store rather than over
//! this leg, and the double AEAD legitimately closes AuthN/AuthZ over a blob the
//! worker authored — so the store launders the provenance, and this scope says
//! nothing about that field where it is finally read.

use std::sync::Arc;

use enclavid_boundary::{Asserted, Untrusted, reason};
use engine_rpc::{CallbackError, CallbackServiceUntrusted, Padded};
use hatch_client::SessionState;

use super::media_store::HatchMediaStore;
use super::persister::SessionPersister;

/// How api judges everything the worker leg hands it — see the module docs.
pub(super) type WorkerScope = (Asserted,);

/// A value a worker produced, for signatures below the seam. Whether it came back
/// from a call api made or arrived on a callback api serves makes no difference:
/// both are the worker's own word.
pub(super) type FromWorker<T> = Untrusted<T, WorkerScope>;

/// Per-run callback target: delegates the callback methods to the seal-key-holding
/// persister + media store. One per round (both are per-round).
#[derive(Clone)]
pub(super) struct CallbackServer {
    pub(super) persister: Arc<SessionPersister>,
    pub(super) media_store: Arc<HatchMediaStore>,
}

impl CallbackServiceUntrusted for CallbackServer {
    type Scope = WorkerScope;

    async fn media_load(
        &self,
        hash: Untrusted<[u8; 32], Self::Scope>,
    ) -> Result<Option<Vec<u8>>, CallbackError> {
        self.media_store.load(hash).await
    }

    async fn session_change(
        &self,
        state: Untrusted<Padded<SessionState>, Self::Scope>,
    ) -> Result<(), CallbackError> {
        // Two separate questions, and closing one says nothing about the other.
        // The frame answers "did the length tell the host anything" — settled by
        // the wire type, on a hop api only receives on, so no marker of api's
        // could have asked it. The scope answers "whose word is the CONTENT".
        //
        // Nothing api reads out of the round's own state is worth more than the
        // worker's word, and api does not read any of it: `state` is sealed
        // verbatim. The one field it DOES interpret — `current_prompt` — reaches
        // `consent_for_round` on the NEXT round, out of the sealed store rather
        // than over this leg, where this scope does not follow it.
        let state = state
            .trust_unchecked::<Asserted, _>(reason!(
                "contained: sealed verbatim and handed back only to the peer that \
                 authored it; api interprets nothing in it here"
            ))
            .into_inner()
            .open()?;
        self.persister.persist(state).await
    }
}
