//! L2 cwasm-cache: best-effort load / store of a [`CompiledBundle`].
//!
//! This is the fleet's DURABLE cache tier and the orchestrator's ONLY compiled
//! artifact store — a hatch-backed blob store ([`hatch_client::CacheStore`],
//! AEAD-sealed under `tee_seal_key`) that survives a TEE restart. There is no
//! api-side in-RAM component cache; the sole in-memory L1 lives on the
//! execution-worker, which PULLS a bundle from here via `load_component` on an
//! L1 miss. A [`CompiledBundle`] is a pure function of the pinned artifacts, so
//! a cold compile stores it once and every later boot / worker-pull reloads it
//! without re-pulling or re-compiling.
//!
//! ## Compatibility / invalidation — guards
//!
//! A stale on-disk bundle after a code update must never load wrong:
//!   1. `compat_token` + [`CACHE_FORMAT_VERSION`] folded into `cache_id` — the
//!      token is the execution-worker's cwasm ABI id (wasmtime version + config +
//!      target), so a fleet runtime bump gives the new worker a new key ⇒ a MISS
//!      (recompile) instead of a stale, incompatible cwasm; a bundle-layout bump
//!      does the same via the format epoch. Old blobs are never addressed by the
//!      new binary/runtime.
//!   2. `#[serde(deny_unknown_fields)]` + no `#[serde(default)]` on
//!      [`CompiledBundle`] — even if a version bump is forgotten, ANY struct-shape
//!      drift makes the CBOR decode error (missing OR extra field), treated here
//!      as a miss.
//!   3. wasmtime's own compatibility header — the execution-worker's
//!      `deserialize_component` returns `Err` on a residual ABI skew. api can't
//!      pre-check that (no wasmtime), so it surfaces as a run failure; but guard 1
//!      makes it unreachable as long as the `compat_token` faithfully tracks the
//!      ABI. (The semantic case — same field shape, changed meaning — is caught
//!      only by guard 1.)
//!
//! Load/store are BEST-EFFORT: a miss, transport failure, or decode error all
//! degrade to the cold compile path. The cache is a pure optimization;
//! correctness never depends on it.

use hatch_client::CacheStore;

use engine_rpc::CompiledBundle;

/// Bumped whenever the [`CompiledBundle`] wire layout changes (a field
/// added / removed / retyped, or a nested serde type's shape changes). A bump
/// re-partitions the cache: old bundles get a different `cache_id` and are never
/// read (guard 1).
const CACHE_FORMAT_VERSION: u32 = 1;

/// Opaque cache key: the composition hash scoped by the runtime ABI
/// (`compat_token`) and the bundle-format epoch. [`CacheStore`] uses it as both
/// the AEAD AAD and the filename-label input, so a runtime bump OR a format bump
/// invalidates cleanly.
fn cache_id(composition_key: &str, compat_token: &str) -> String {
    format!("{composition_key}.{compat_token}.v{CACHE_FORMAT_VERSION}")
}

/// Try to load the [`CompiledBundle`] for `(composition_key, compat_token)` from
/// L2. Returns `None` on ANY failure (miss, transport error, decode error) — the
/// caller falls through to the cold compile path.
pub async fn try_load(
    cache: &CacheStore,
    composition_key: &str,
    compat_token: &str,
) -> Option<CompiledBundle> {
    let id = cache_id(composition_key, compat_token);
    let bytes = match cache.load(&id).await {
        Ok(Some(b)) => b,
        Ok(None) => return None, // clean miss (404 / unopenable blob)
        Err(e) => {
            eprintln!("cwasm_cache: L2 load transport error (cold path): {e}");
            return None;
        }
    };
    match ciborium::from_reader(&bytes[..]) {
        Ok(b) => Some(b),
        Err(e) => {
            // Format drift / corruption → miss (guard 2); recompiled + re-stored.
            eprintln!("cwasm_cache: bundle decode failed (cold path): {e}");
            None
        }
    }
}

/// Store a freshly-compiled [`CompiledBundle`] to the L2 cache under
/// `(composition_key, compat_token)`. The bundle already carries the serialized
/// cwasm (the compile-worker produced it), so this only encodes + writes — no
/// re-serialize. Best-effort: any failure (encode, transport) is logged and
/// swallowed; a broken cache never breaks a session.
pub async fn store(
    cache: &CacheStore,
    composition_key: &str,
    compat_token: &str,
    bundle: &CompiledBundle,
) {
    let mut encoded = Vec::new();
    if let Err(e) = ciborium::into_writer(bundle, &mut encoded) {
        eprintln!("cwasm_cache: bundle encode failed (skip store): {e}");
        return;
    }
    if let Err(e) = cache.store(&cache_id(composition_key, compat_token), encoded).await {
        eprintln!("cwasm_cache: L2 store failed (non-fatal): {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_id_scopes_by_composition_token_and_format() {
        assert_eq!(cache_id("abc", "tok"), format!("abc.tok.v{CACHE_FORMAT_VERSION}"));
        // Composition, token, and format each partition the key.
        assert_ne!(cache_id("abc", "tok"), cache_id("abd", "tok"));
        assert_ne!(cache_id("abc", "tok"), cache_id("abc", "tok2"));
    }
}
