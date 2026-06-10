//! Per-plugin Store data used by [`Runner::run`](crate::Runner::run).
//!
//! Each plugin component lives in its own wasmtime `Store` under the
//! wasm-runtime-composer runtime. The Store needs a `T` that satisfies
//! the composer's `ResourceProxyView` so resource handles can be
//! proxied across cross-component boundaries.
//!
//! Plugins are **pure compute** in our trust model — they may not
//! import ANY host function (no WASI, no `enclavid:*`, nothing). See
//! `[[project-section-level-encryption-plan]]` → "Plugin host-import
//! constraint" for the privacy / consent-ownership / audit-trail
//! rationale. Plugin's Linker is intentionally empty; composer fails
//! loud at compose-time if a plugin declares any unsatisfied import.
//!
//! Consequently this state carries none of the policy-side machinery
//! (replay, listener, disclosures, registered text-refs) — and never
//! will. The only things on it are the composer-mandated proxy table
//! and the wasmtime memory limits.

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

impl Default for PluginHostState {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceProxyView for PluginHostState {
    fn proxy_table(&mut self) -> &mut ResourceTable {
        &mut self.proxy_table
    }
}
