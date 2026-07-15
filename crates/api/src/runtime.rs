//! Shared per-process runtime artifacts: the wasmtime engine and the
//! two-tier compiled-policy cache.
//!
//! Policy compilation is expensive (OCI pull + wac fusion + Cranelift
//! codegen), so a compiled [`PolicyEntry`] — a pure function of the
//! pinned `(policy, plugin-set)` — is cached and reused across every
//! session and round that pins the same composition. [`PolicyCache`]
//! folds two tiers behind one [`get_or_compute`](PolicyCache::get_or_compute):
//! an in-RAM L1 and a broker-backed L2 (sealed cwasm) that survives a TEE
//! restart.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use moka::future::Cache;

use broker_client::CacheStore;
use enclavid_engine::{Component, ComponentDecls, EmbeddedImport, EmbeddedRegistry, Runner};

use crate::cwasm_cache;

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

/// A freshly cold-compiled composition returned by the loader passed to
/// [`PolicyCache::get_or_compute`]: the L1 [`PolicyEntry`] plus the
/// per-component catalogs the L2 bundle stores alongside the cwasm (so a
/// later cache hit rebuilds the embedded registry without re-parsing the
/// artifacts). `catalogs` is composition order (policy first).
pub struct ColdPolicy {
    pub entry: Arc<PolicyEntry>,
    pub catalogs: Vec<([u8; 32], ComponentDecls)>,
}

/// Two-tier compiled-policy cache, keyed by COMPOSITION hash
/// (`sha256(policy_ref ‖ ordered plugin pins ‖ access authority)`; see
/// `applicant::shared::composition_key`).
///
/// * **L1** — in-RAM moka `Cache<composition_key, Arc<PolicyEntry>>`,
///   shared across sessions. Bounded in size and TTL to release unused
///   entries. A process restart empties it (which is why the composition
///   key need not include the wasmtime version — the same `Runner` engine
///   produced every live `Component`).
/// * **L2** — broker-backed sealed cwasm ([`CacheStore`]), survives a TEE
///   / broker restart so a cold start reuses the compile.
///
/// [`get_or_compute`](Self::get_or_compute) runs the ladder L1 → L2 →
/// cold loader under moka `try_get_with`, whose request coalescing means
/// the expensive pull + fuse + compile runs at most ONCE per key even
/// when many first-touch requests race.
pub struct PolicyCache {
    l1: Cache<String, Arc<PolicyEntry>>,
    l2: CacheStore,
    /// Shares the process `Engine` with the caller's `Runner`; the L2
    /// tier needs it to (de)serialize the compiled `Component`.
    runner: Arc<Runner>,
}

impl PolicyCache {
    pub fn new(l2: CacheStore, runner: Arc<Runner>) -> Self {
        let l1 = Cache::builder()
            // A hard ceiling on distinct compiled compositions — far above
            // the handful a deployment has.
            .max_capacity(10_000)
            .time_to_idle(Duration::from_secs(3600))
            .build();
        Self { l1, l2, runner }
    }

    /// Resolve the compiled entry for `key`, computing on a full miss.
    ///
    /// L1 hit → return it. L1 miss → (coalesced across concurrent callers)
    /// try L2; on an L2 miss run `loader` — the cold pull + fuse + compile
    /// — then persist its result to L2 and populate L1. Any L2 failure
    /// (miss, transport, decode, wasmtime skew) degrades silently to the
    /// loader; the L2 store is best-effort. The loader runs at most once
    /// per key thanks to moka's request coalescing.
    ///
    /// Errors from the loader (`StatusCode`) are NOT cached — every
    /// coalesced waiter gets the same status and the next request retries.
    pub async fn get_or_compute<F, Fut>(
        &self,
        key: String,
        loader: F,
    ) -> Result<Arc<PolicyEntry>, StatusCode>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<ColdPolicy, StatusCode>>,
    {
        self.l1
            .try_get_with(key.clone(), async move {
                // L1 miss (deduped). Try the restart-surviving L2 first.
                if let Some(entry) = cwasm_cache::try_load(&self.l2, &self.runner, &key).await {
                    return Ok(entry);
                }
                // Full miss: cold-compile, then persist to L2 for next time.
                let cold = loader().await?;
                cwasm_cache::store(
                    &self.l2,
                    &self.runner,
                    &key,
                    &cold.entry.component,
                    &cold.entry.embedded_imports,
                    &cold.catalogs,
                )
                .await;
                Ok(cold.entry)
            })
            .await
            // moka wraps the loader error in an Arc (shared with coalesced
            // waiters); StatusCode is Copy, so unwrap it back.
            .map_err(|arc| *arc)
    }
}

/// Construct the shared Runner. Wrapped in an Arc so both client and
/// applicant states can hold references; the underlying `Engine` is
/// thread-safe and intended for sharing.
pub fn new_runner() -> Arc<Runner> {
    Arc::new(Runner::new().expect("failed to create runner"))
}
