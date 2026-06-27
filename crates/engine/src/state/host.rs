use std::sync::Arc;

use wasm_runtime_composer::ResourceProxyView;
use wasmtime::component::ResourceTable;
use wasmtime::{StoreLimits, StoreLimitsBuilder};

use crate::embedded::EmbeddedRegistry;
use crate::limits::POLICY_MAX_MEMORY;
use crate::listener::SessionListener;

/// Data placed into wasmtime `Store<HostState>` for the duration of one
/// `handle` call. The policy is a pure reducer, so this state carries
/// only ambient read surfaces (`enclavid:policy/context` props,
/// `enclavid:embedded/*` registry) plus the runtime plumbing
/// (listener, limits, composer proxy table). No replay log, no
/// per-call disclosure buffer — the runner fires the listener directly
/// on a consent-disclosure accept, around the `handle` call, not from a
/// host-fn body.
pub struct HostState {
    /// Static consumer config (`metadata.input`), surfaced to the
    /// policy through `enclavid:policy/context.props`. Constant for
    /// the session; the policy may read it any round.
    pub props: Vec<(String, crate::enclavid::policy::types::Prop)>,
    /// Per-component `enclavid:embedded/*` registry, shared with every
    /// plugin's `PluginHostState` so the slot-bound resolve closures and
    /// the use-site reverse-lookups read from the same frozen index.
    /// Frozen before any per-session input reaches any component; the
    /// runner consults it at every embedded-ref use-site (consent field
    /// key/label, reason / requester, media labels) and traps if a ref
    /// isn't in it. Closes the runtime ref-crafting channel and the
    /// cross-component attribution channel.
    pub embedded: Arc<EmbeddedRegistry>,
    /// Resource caps the wasmtime runtime consults via `Store::
    /// limiter`. Bounds linear-memory growth so the policy component
    /// can't OOM the enclave. Fuel (CPU-instruction budget) is set
    /// separately on the Store via `Store::set_fuel`.
    pub limits: StoreLimits,
    /// Proxy table used by wasm-runtime-composer to forward resource
    /// handles between this Store and other components in the
    /// composition. Owned per Store; the composer pushes / removes
    /// entries transparently during cross-store calls. We never read it
    /// directly — it lives here solely to satisfy [`ResourceProxyView`]
    /// so this Store can participate in compositions.
    pub proxy_table: ResourceTable,
}

/// Per-run inputs assembled by the api crate and handed to
/// [`HostState::new`]. Carries the listener that ties this run to the
/// caller's persistence layer plus the composition-wide
/// `EmbeddedRegistry` — constructed once at policy-cache build time from
/// policy + plugin embedded sections and shared by `Arc` with every
/// consumer (engine slot-bound resolve, engine use-site reverse-lookup,
/// api view-layer ref resolution).
pub struct RunInputs {
    pub listener: Arc<dyn SessionListener>,
    pub embedded: Arc<EmbeddedRegistry>,
}

impl HostState {
    pub(crate) fn new(
        props: Vec<(String, crate::enclavid::policy::types::Prop)>,
        embedded: Arc<EmbeddedRegistry>,
    ) -> Self {
        Self {
            props,
            embedded,
            limits: StoreLimitsBuilder::new()
                .memory_size(POLICY_MAX_MEMORY)
                .build(),
            proxy_table: ResourceTable::new(),
        }
    }
}

impl ResourceProxyView for HostState {
    fn proxy_table(&mut self) -> &mut ResourceTable {
        &mut self.proxy_table
    }
}

/// `enclavid:policy/context` — the policy's ambient `props` getter.
/// Referentially transparent: returns the same static consumer config
/// every call, no side effect, no replay concern.
impl crate::enclavid::policy::context::Host for HostState {
    async fn props(
        &mut self,
    ) -> wasmtime::Result<Vec<(String, crate::enclavid::policy::types::Prop)>> {
        Ok(self.props.clone())
    }
}

// Pure-types interfaces (no host functions) still generate empty `Host`
// traits via `bindgen!`. Implementing them on `HostState` satisfies the
// linker bound — there's nothing to actually implement.
impl crate::enclavid::policy::types::Host for HostState {}
impl crate::enclavid::shared_types::capture::Host for HostState {}
impl crate::enclavid::shared_types::disclosure::Host for HostState {}
