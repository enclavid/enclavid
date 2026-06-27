//! Per-plugin Store data used by [`Runner::run`](crate::Runner::run).
//!
//! Each plugin component lives in its own wasmtime `Store` under the
//! wasm-runtime-composer runtime. The Store needs a `T` that satisfies
//! the composer's `ResourceProxyView` so resource handles can be
//! proxied across cross-component boundaries.
//!
//! ## Host-import constraint (refined 2026-06-10)
//!
//! Plugins MAY import the two pure scoped-lookup interfaces:
//!
//!   * `enclavid:embedded/disclosure-fields@0.1.0`
//!   * `enclavid:embedded/i18n@0.1.0`
//!
//! These are deterministic, idempotent, component-scoped:
//! `disclosure-field(key)` and `localized(key)` consult only the
//! plugin's OWN [`enclavid:embedded`](../../wit/embedded/embedded.wit)
//! sections (sealed at build time, immutable for the session) and
//! return slot-attributed refs the plugin can hand back to the policy
//! through `DisplayField` records. No side effects, no
//! privacy violation, no covert channel.
//!
//! Plugins MUST NOT import anything else — no WASI clock / random /
//! logging / network / disk. Composer fails loud at compose-time if a plugin
//! declares an unsatisfied import; the runner registers ONLY the two
//! `embedded` interfaces on each plugin's Linker before calling
//! `compose`.
//!
//! Hence this state carries just the composer-mandated proxy table and
//! the wasmtime memory limits. The slot-bound `enclavid:embedded/*`
//! resolve closures the runner registers on this plugin's Linker hold
//! their own `EmbeddedRegistry` handle, so it is not stored here. No
//! replay / listener / disclosure surface — those are policy-only.

use wasm_runtime_composer::ResourceProxyView;
use wasmtime::component::ResourceTable;
use wasmtime::{StoreLimits, StoreLimitsBuilder};

use crate::limits::POLICY_MAX_MEMORY;

/// Data placed into wasmtime `Store<PluginHostState>` for each plugin
/// component in a composition. Minimal: just enough to satisfy
/// [`ResourceProxyView`] and bound the plugin's linear memory.
pub struct PluginHostState {
    /// Proxy table used by composer's `ComposableLinker` to forward
    /// WIT resource handles between this Store and the policy / other
    /// plugins. Owned per Store; composer pushes / removes entries
    /// transparently during cross-store calls.
    pub proxy_table: ResourceTable,
    /// Resource caps the wasmtime runtime consults via
    /// `Store::limiter`. Bounds linear-memory growth so a single
    /// plugin can't exhaust the enclave's memory. Reuses
    /// [`POLICY_MAX_MEMORY`] for now — once we have a body of plugin
    /// workloads, we'll split into a dedicated `PLUGIN_MAX_MEMORY`
    /// constant tuned to typical plugin payloads (decoded image
    /// frames, ONNX inference tensors).
    pub limits: StoreLimits,
}

impl PluginHostState {
    pub fn new() -> Self {
        Self {
            proxy_table: ResourceTable::new(),
            limits: StoreLimitsBuilder::new()
                .memory_size(POLICY_MAX_MEMORY)
                .build(),
        }
    }
}

impl ResourceProxyView for PluginHostState {
    fn proxy_table(&mut self) -> &mut ResourceTable {
        &mut self.proxy_table
    }
}
