//! The api side of the keyless execution-worker's callback boundary.
//!
//! During a run the worker calls BACK over the same remoc connection:
//! `load_component` to resolve the compiled bundle on an L1 miss (the worker
//! owns the only in-memory component cache; the orchestrator owns L2), `media_load`
//! to rehydrate a stored blob, and `session_change` to seal + persist the
//! post-round state + disclosures + captured media. [`CallbackServer`] wires
//! those to the per-round [`SessionPersister`] + [`BrokerMediaStore`] (they hold
//! the seal key + applicant token) and to [`resolve_bundle`](super::shared::resolve_bundle)
//! (L2 read, or cold compile on a miss). It implements `rpc::CallbackService`;
//! the orchestrator stands one up per run and passes its client into
//! `ExecutorService::run` (see [`crate::executor`]).

use std::sync::Arc;

use broker_client::{SessionMetadata, SessionState};
use rpc::{CallbackError, CallbackService, CompiledBundle, ConsentDisclosure, LoadError};

use crate::state::AppState;

use super::media_store::BrokerMediaStore;
use super::persister::SessionPersister;

/// Per-run callback target: delegates the callback methods to the seal-key-holding
/// persister + media store, and to the L2/compile bundle resolver. One per round
/// (the persister + media store are per-round; the state + metadata drive the
/// composition resolve).
pub(super) struct CallbackServer {
    pub(super) persister: Arc<SessionPersister>,
    pub(super) media_store: Arc<BrokerMediaStore>,
    /// Shared orchestrator state — the L2 [`CacheStore`](broker_client::CacheStore),
    /// registry / KBS / compiler clients `resolve_bundle` needs on a cache miss.
    pub(super) state: Arc<AppState>,
    /// This session's metadata — the pinned `policy_ref` / plugins / registry
    /// auth a cold compile pulls + fuses. Immutable for the session.
    pub(super) metadata: SessionMetadata,
    pub(super) session_id: String,
}

impl CallbackService for CallbackServer {
    async fn load_component(
        &self,
        composition_key: String,
        compat_token: String,
    ) -> Result<CompiledBundle, LoadError> {
        // A config-resolution status (410 GONE on a removed artifact, 500 on a
        // compile/infra fault) is a pure function of the pinned config — carry it
        // VERBATIM so the orchestrator surfaces it, not a flattened 500.
        super::shared::resolve_bundle(
            &self.state,
            &composition_key,
            &compat_token,
            &self.session_id,
            &self.metadata,
        )
        .await
        .map_err(|status| LoadError {
            status: status.as_u16(),
            message: format!("resolve bundle failed for session {}", self.session_id),
        })
    }

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
