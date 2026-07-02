//! Shared per-session runtime artifacts: compiled policy components.
//!
//! Both the client API (writes on /init) and the applicant API (reads on
//! /input) need access to this — same process, same Engine, separate
//! listeners. The cache key is `session_id`; the value is an `Arc<Component>`
//! ready to instantiate against the shared `Runner`'s engine.

use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;

use enclavid_engine::{Component, EmbeddedImport, EmbeddedRegistry, Runner};

/// Per-session compiled policy artifact: the fused wasmtime
/// `Component` (policy + its pinned plugins, wac single-store fused at
/// /connect via [`Runner::compose`](enclavid_engine::Runner::compose)),
/// the manifest of distinct per-catalog i18n/icons imports the host
/// `Linker` must register, and the composition-wide `EmbeddedRegistry`
/// (policy first, then plugins in pinned `Client.plugins` order; holds
/// the `disclosure_fields`, `localized`, and `icons` stores).
///
/// `embedded` is shared by Arc with every consumer (engine resolve +
/// use-site lookup, api views for projecting refs into user-facing
/// strings) so catalog attribution cannot drift across consumers.
///
/// All are immutable for the lifetime of the session entry; plugins
/// are pinned by `Client.plugins[].impl_ref` digests and fused into
/// `component` once, so the same client cannot mutate the set
/// mid-session.
pub struct PolicyEntry {
    pub component: Arc<Component>,
    pub embedded_imports: Arc<Vec<EmbeddedImport>>,
    pub embedded: Arc<EmbeddedRegistry>,
}

/// Cache of compiled policy components, keyed by session_id.
///
/// Compiled at /init from the decrypted wasm bytes; looked up on every
/// /input. Bounded in size to cap memory pressure under DoS, and bounded
/// in TTL to release abandoned sessions. The shared `Runner` owns the
/// `Engine` that produced these components — they are NOT portable across
/// engines, so all states sharing this cache must reference the same
/// `Runner` Arc below.
pub type SessionPolicyCache = Cache<String, Arc<PolicyEntry>>;

pub fn new_policy_cache() -> SessionPolicyCache {
    Cache::builder()
        .max_capacity(10_000)
        .time_to_idle(Duration::from_secs(3600))
        .build()
}

/// Construct the shared Runner. Wrapped in an Arc so both client and
/// applicant states can hold references; the underlying `Engine` is
/// thread-safe and intended for sharing.
pub fn new_runner() -> Arc<Runner> {
    Arc::new(Runner::new().expect("failed to create runner"))
}
