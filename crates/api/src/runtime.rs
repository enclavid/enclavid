//! Shared per-session runtime artifacts: compiled policy components.
//!
//! Both the client API (writes on /init) and the applicant API (reads on
//! /input) need access to this — same process, same Engine, separate
//! listeners. The cache key is `session_id`; the value is an `Arc<Component>`
//! ready to instantiate against the shared `Runner`'s engine.

use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;

use enclavid_engine::{Component, Runner};

use crate::text_registry::TextRegistry;

/// Per-session compiled policy artifact: the wasmtime `Component`
/// plus the localized-text registry the policy declared via
/// `prepare-localized-texts`. Both are immutable for the lifetime of
/// the session entry.
pub struct PolicyEntry {
    pub component: Arc<Component>,
    pub texts: Arc<TextRegistry>,
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
