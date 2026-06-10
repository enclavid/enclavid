use std::sync::Arc;

use enclavid_host_bridge::SessionState;
use wasm_runtime_composer::ResourceProxyView;
use wasmtime::component::ResourceTable;
use wasmtime::{StoreLimits, StoreLimitsBuilder};

use crate::embedded::EmbeddedRegistry;
use crate::intercept::replay::Replay;
use crate::limits::POLICY_MAX_MEMORY;
use crate::listener::{ConsentDisclosure, SessionListener};

/// Data placed into wasmtime `Store<HostState>` for the duration of
/// one run. Owns the replay machinery, the per-call disclosure buffer,
/// and the listener.
///
/// Engine never talks to the host and holds no keys: every committed
/// CallEvent fires `SessionListener::on_session_change`, the listener (api
/// crate) does whatever encryption + persistence the destination
/// requires (`tee_seal_key`/`applicant_session_token` AEAD for state via the bridge;
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
    /// Per-component `enclavid:embedded/*` registry, shared with every
    /// plugin's `PluginHostState` so the slot-bound mint closures and
    /// the use-site reverse-lookups read from the same frozen index.
    /// Frozen before any per-session input reaches any component; the
    /// engine consults it at every embedded-ref use-site
    /// (`prompt-disclosure` field key/label, reason / requester,
    /// media labels) and traps if a ref isn't in it. Closes the
    /// runtime ref-crafting channel where a policy might otherwise
    /// encode user-attribute bits into a freshly-minted key string
    /// at evaluate time, and the cross-component channel where one
    /// component might mint a ref attributing the message to another.
    pub embedded: Arc<EmbeddedRegistry>,
    /// Resource caps the wasmtime runtime consults via `Store::
    /// limiter`. Bounds linear-memory growth so the policy
    /// component can't OOM the enclave. Fuel (CPU-instruction
    /// budget) is set separately on the Store via `Store::set_fuel`.
    pub limits: StoreLimits,
    /// Proxy table used by wasm-runtime-composer to forward resource
    /// handles between this Store and other components in the
    /// composition. Owned per Store; the composer pushes / removes
    /// entries transparently during cross-store calls. We never read
    /// it directly — it lives here solely to satisfy
    /// [`ResourceProxyView`] so this Store can participate in
    /// compositions.
    pub proxy_table: ResourceTable,
}

/// Per-run inputs assembled by the api crate and handed to
/// [`HostState::new`]. Carries the listener that ties this run to
/// the caller's persistence layer plus the composition-wide
/// `EmbeddedRegistry` — constructed once at policy-cache build time
/// from policy + plugin embedded sections and shared by `Arc` with
/// every consumer (engine slot-bound mint, engine use-site reverse-
/// lookup, api view-layer ref resolution).
///
/// Distinct name from the component-model "resources" concept
/// (`wasmtime::component::Resource`) — these are the engine's
/// per-`Runner::run` inputs, not WIT resource handles.
pub struct RunInputs {
    pub listener: Arc<dyn SessionListener>,
    pub embedded: Arc<EmbeddedRegistry>,
}

impl HostState {
    pub(crate) fn new(session: SessionState, inputs: RunInputs) -> Self {
        Self {
            replay: Replay::new(session),
            pending_disclosures: Vec::new(),
            listener: inputs.listener,
            embedded: inputs.embedded,
            limits: StoreLimitsBuilder::new()
                .memory_size(POLICY_MAX_MEMORY)
                .build(),
            proxy_table: ResourceTable::new(),
        }
    }

    pub(crate) fn into_session(self) -> SessionState {
        self.replay.into_session()
    }
}

impl ResourceProxyView for HostState {
    fn proxy_table(&mut self) -> &mut ResourceTable {
        &mut self.proxy_table
    }
}

// Pure-types interfaces (no host functions) still generate empty
// `Host` traits via `bindgen!`. Implementing them on `HostState`
// satisfies the linker bound — there's nothing to actually implement.
impl crate::enclavid::disclosure::types::Host for HostState {}
impl crate::enclavid::form::types::Host for HostState {}
