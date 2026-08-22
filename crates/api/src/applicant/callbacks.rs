//! The api side of the keyless execution-worker's callback boundary.
//!
//! During a run the worker calls BACK over the same remoc connection: `media_load`
//! to rehydrate a stored blob, and `session_change` to seal + persist the
//! post-round state + disclosures + captured media. [`CallbackServer`] wires those
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

use std::sync::Arc;

use engine_rpc::{CallbackError, CallbackService, ConsentDisclosure};
use hatch_client::SessionState;

use super::media_store::HatchMediaStore;
use super::persister::SessionPersister;

/// Per-run callback target: delegates the callback methods to the seal-key-holding
/// persister + media store. One per round (both are per-round).
pub(super) struct CallbackServer {
    pub(super) persister: Arc<SessionPersister>,
    pub(super) media_store: Arc<HatchMediaStore>,
}

impl CallbackService for CallbackServer {
    async fn media_load(&self, hash: [u8; 32]) -> Result<Option<Vec<u8>>, CallbackError> {
        self.media_store.load(&hash).await
    }

    async fn session_change(
        &self,
        state: SessionState,
        disclosures: Vec<ConsentDisclosure>,
        media: Vec<([u8; 32], Vec<u8>)>,
    ) -> Result<(), CallbackError> {
        self.persister.persist(state, disclosures, media).await
    }
}
