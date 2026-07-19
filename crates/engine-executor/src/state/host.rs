use std::sync::Arc;

use wasmtime::component::ResourceTable;
use wasmtime::{StoreLimits, StoreLimitsBuilder};

use crate::embedded::EmbeddedRegistry;
use crate::limits::POLICY_MAX_MEMORY;
use crate::listener::SessionListener;
use crate::media_store::MediaStore;

/// Data placed into wasmtime `Store<HostState>` for the duration of one
/// `handle` call. The policy is a pure reducer, so this state carries
/// only ambient read surfaces (`enclavid:host/session-context` props,
/// `enclavid:embedded/*` registry) plus the runtime plumbing
/// (listener, limits). No replay log, no per-call disclosure buffer —
/// the runner fires the listener directly on a consent-disclosure
/// accept, around the `handle` call, not from a host-fn body.
pub struct HostState {
    /// Static consumer config (`metadata.input`), surfaced to the
    /// policy through `enclavid:host/session-context.props`. Constant for
    /// the session; the policy may read it any round.
    pub props: Vec<(String, crate::enclavid::host::types::Prop)>,
    /// Per-composition `enclavid:host/embedded-*` registry — one frozen
    /// index built from the policy's and every fused plugin's embedded
    /// sections. The embedded host fns resolve a key against it (first
    /// match across the merged catalogs, or strict against one catalog
    /// for a routed twin) and MINT a ref resource into [`table`](Self::
    /// table) carrying the resolved data. Frozen before any per-session
    /// input reaches the component; a component can only reference a key
    /// some catalog declared.
    pub embedded: Arc<EmbeddedRegistry>,
    /// Handle table backing the host-owned ref resources
    /// (`localized-ref` / `icon-ref` / `disclosure-field-ref`) and the
    /// `blob` resources. The host funcs push resolved data / capture
    /// blobs here and hand the component an unforgeable handle; the runner
    /// dereferences the ref handles the returned prompt carries at the
    /// action boundary. Fresh per run, dropped with the Store — handles
    /// never outlive the round.
    pub table: ResourceTable,
    /// Host-side sealed blob store, injected by the runtime's I/O layer.
    /// Backs `blob::from-blob-ref` — the policy rehydrates a stored capture
    /// blob by its content ref mid-`handle`. `Arc<dyn>` so the host fn can
    /// clone it out before the `.await` (releasing the borrow of `self`).
    pub media_store: Arc<dyn MediaStore>,
    /// Resource caps the wasmtime runtime consults via `Store::
    /// limiter`. Bounds linear-memory growth so the policy component
    /// can't OOM the enclave. Fuel (CPU-instruction budget) is set
    /// separately on the Store via `Store::set_fuel`.
    pub limits: StoreLimits,
}

/// Per-run inputs assembled by the api crate and handed to
/// `HostState::new`. Carries the listener that ties this run to the
/// caller's persistence layer plus the composition-wide
/// `EmbeddedRegistry` — constructed once at policy-cache build time from
/// policy + plugin embedded sections and shared by `Arc` with every
/// consumer (engine first-match resolve, engine use-site reverse-lookup,
/// api view-layer ref resolution).
pub struct RunInputs {
    pub listener: Arc<dyn SessionListener>,
    pub embedded: Arc<EmbeddedRegistry>,
    pub media_store: Arc<dyn MediaStore>,
}

impl HostState {
    pub(crate) fn new(
        props: Vec<(String, crate::enclavid::host::types::Prop)>,
        embedded: Arc<EmbeddedRegistry>,
        media_store: Arc<dyn MediaStore>,
    ) -> Self {
        Self {
            props,
            embedded,
            table: ResourceTable::new(),
            media_store,
            limits: StoreLimitsBuilder::new()
                .memory_size(POLICY_MAX_MEMORY)
                .build(),
        }
    }
}

/// `enclavid:host/session-context` — the policy's ambient `props`
/// getter. Referentially transparent: returns the same static consumer
/// config every call, no side effect, no replay concern.
impl crate::enclavid::host::session_context::Host for HostState {
    async fn props(
        &mut self,
    ) -> wasmtime::Result<Vec<(String, crate::enclavid::host::types::Prop)>> {
        Ok(self.props.clone())
    }
}

// Pure-types interfaces (no host functions) still generate empty `Host`
// traits via `bindgen!`. Implementing them on `HostState` satisfies the
// linker bound — there's nothing to actually implement.
impl crate::enclavid::policy::types::Host for HostState {}
impl crate::enclavid::shared_types::capture::Host for HostState {}
impl crate::enclavid::shared_types::disclosure::Host for HostState {}
// `enclavid:host/types::Host` + the three ref-resource destructors live
// in `embedded::host`, next to the resolvers that mint them.
