use std::collections::HashSet;
use std::sync::Arc;

use enclavid_host_bridge::SessionState;
use wasmtime::{StoreLimits, StoreLimitsBuilder};

use crate::limits::POLICY_MAX_MEMORY;
use crate::listener::{ConsentDisclosure, SessionListener};
use crate::replay::Replay;

/// Data placed into wasmtime `Store<HostState>` for the duration of
/// one run. Owns the replay machinery, the per-call disclosure buffer,
/// and the listener.
///
/// Engine never talks to the host and holds no keys: every committed
/// CallEvent fires `SessionListener::on_session_change`, the listener (api
/// crate) does whatever encryption + persistence the destination
/// requires (`tee_key`/`applicant_key` AEAD for state via the bridge;
/// `client_pk` age-encrypt for disclosures inside the listener
/// itself). Symmetric with how state and metadata are already sealed
/// transparently inside host-bridge.
pub struct HostState {
    pub replay: Replay,
    /// Disclosure records staged during the current host call body.
    /// Structured (proto-typed fields) — listener owns the public
    /// JSON wire format and sealing to recipient. Drained and handed
    /// to the listener after each successful event commit; per-call
    /// lifetime, never accumulated across calls.
    pub pending_disclosures: Vec<ConsentDisclosure>,
    /// Hook fired after each committed CallEvent. Stored as Arc so the
    /// shim can clone it cheaply across the await point that calls it.
    pub listener: Arc<dyn SessionListener>,
    /// Snapshot of the `text-ref` keys the policy registered through
    /// `prepare-text-refs`. Frozen before any per-session input
    /// reaches the policy; the engine consults this set at every
    /// text-ref use-site (`prompt-disclosure` field key/label,
    /// reason, media labels) and traps if a ref is not in it. Closes
    /// the runtime text-ref-crafting channel where a policy might
    /// otherwise encode user-attribute bits into a freshly-minted
    /// key string at evaluate time.
    pub registered_text_refs: Arc<HashSet<String>>,
    /// Resource caps the wasmtime runtime consults via `Store::
    /// limiter`. Bounds linear-memory growth so the policy
    /// component can't OOM the enclave. Fuel (CPU-instruction
    /// budget) is set separately on the Store via `Store::set_fuel`.
    pub limits: StoreLimits,
}

/// Per-run resources assembled by the api crate and handed to
/// `HostState`. Carries the listener that ties this run to the
/// caller's persistence layer plus the policy's pre-registered
/// text-ref set.
pub struct HostResources {
    pub listener: Arc<dyn SessionListener>,
    pub registered_text_refs: Arc<HashSet<String>>,
}

impl HostState {
    pub(crate) fn new(session: SessionState, resources: HostResources) -> Self {
        Self {
            replay: Replay::new(session),
            pending_disclosures: Vec::new(),
            listener: resources.listener,
            registered_text_refs: resources.registered_text_refs,
            limits: StoreLimitsBuilder::new()
                .memory_size(POLICY_MAX_MEMORY)
                .build(),
        }
    }

    pub(crate) fn into_session(self) -> SessionState {
        self.replay.into_session()
    }
}

// The policy interface is `export`ed by the component, but its types
// (`text-ref`, `text-entry`) are `use`d by the imported interfaces
// (media, disclosure). wit-bindgen treats policy as both
// imported-for-types and exported-for-calls, which synthesises a
// host-side `Host` trait covering every method of the interface.
//
// Those methods are never actually called on the host side — host
// invokes them on the exported component instance — so we provide
// `unreachable!()` stubs to satisfy the trait. If one of these ever
// fires it's a bindgen wiring bug, not a runtime path.
#[allow(unused_variables)]
impl crate::enclavid::policy::policy::Host for HostState {
    async fn prepare_text_refs(
        &mut self,
    ) -> wasmtime::Result<Vec<crate::enclavid::policy::policy::TextDecl>> {
        unreachable!(
            "prepare-text-refs must be invoked on the policy export, not the host import"
        );
    }

    async fn evaluate(
        &mut self,
        _args: Vec<(String, crate::enclavid::policy::policy::EvalArgs)>,
    ) -> wasmtime::Result<crate::enclavid::policy::policy::Decision> {
        unreachable!(
            "evaluate must be invoked on the policy export, not the host import"
        );
    }
}
