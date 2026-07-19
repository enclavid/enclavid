//! L2 cwasm-cache: best-effort load / store of a [`CompiledBundle`].
//!
//! The L1 cache ([`PolicyCache`](crate::runtime::PolicyCache)) holds compiled
//! [`PolicyEntry`](crate::runtime::PolicyEntry)s in RAM, keyed by composition
//! hash. This is the tier below it: a broker-backed blob store
//! ([`broker_client::CacheStore`]) that survives a TEE restart. A `PolicyEntry`
//! is a pure function of the pinned artifacts, so its serialized form (the
//! [`CompiledBundle`] the [`Compiler`](crate::compiler::Compiler) produces) can
//! be stored once and reloaded on a later boot without re-pulling or
//! re-compiling — the same bundle a cold compile yields, so both paths
//! reconstruct via [`CompiledBundle::to_entry`].
//!
//! ## Compatibility / invalidation — three independent guards
//!
//! A stale on-disk bundle after a code update must never load wrong; it must
//! become a clean miss (→ recompile). Three layers, each catching a different
//! axis:
//!   1. [`CACHE_FORMAT_VERSION`] folded into `cache_id` — a change to the bundle
//!      layout yields a new blob name AND AAD, so old bundles are never
//!      addressed by the new binary.
//!   2. `#[serde(deny_unknown_fields)]` + no `#[serde(default)]` on
//!      [`CompiledBundle`] — even if the version bump is forgotten, ANY
//!      struct-shape drift makes the CBOR decode error (missing OR extra field),
//!      which this treats as a miss.
//!   3. wasmtime's own compatibility header — [`Runner::deserialize_component`]
//!      (via [`CompiledBundle::to_entry`]) returns `Err` on a toolchain skew, so
//!      an incompatible cwasm is a miss, then re-stored fresh. (The semantic
//!      case — same field shape, changed meaning — is caught only by guard 1, an
//!      inherent limit of any serialization, named honestly.)
//!
//! Both directions are BEST-EFFORT: a miss, transport failure, decode error, or
//! wasmtime skew all degrade silently to the cold path. The cache is a pure
//! optimization; correctness never depends on it.

use std::sync::Arc;

use broker_client::CacheStore;
use enclavid_engine::Runner;

use runtime_protocol::CompiledBundle;

use crate::compiler::bundle_to_entry;
use crate::runtime::PolicyEntry;

/// Bumped whenever the [`CompiledBundle`] wire layout changes (a field
/// added / removed / retyped, or a nested serde type's shape changes). A bump
/// re-partitions the cache: old bundles get a different `cache_id` and are never
/// read (guard 1).
const CACHE_FORMAT_VERSION: u32 = 1;

/// Opaque cache key: the composition hash scoped by the bundle-format epoch.
/// [`CacheStore`] uses this as both the AEAD AAD and the filename-label input,
/// so a format bump invalidates cleanly.
fn cache_id(composition_key: &str) -> String {
    format!("{composition_key}.v{CACHE_FORMAT_VERSION}")
}

/// Try to reconstruct a compiled [`PolicyEntry`] from the L2 cache. Returns
/// `None` on ANY failure (miss, transport error, decode error, wasmtime skew) —
/// the caller falls through to the cold compile path.
pub async fn try_load(
    cache: &CacheStore,
    runner: &Runner,
    composition_key: &str,
) -> Option<Arc<PolicyEntry>> {
    let id = cache_id(composition_key);
    let bytes = match cache.load(&id).await {
        Ok(Some(b)) => b,
        Ok(None) => return None, // clean miss (404 / unopenable blob)
        Err(e) => {
            eprintln!("cwasm_cache: L2 load transport error (cold path): {e}");
            return None;
        }
    };
    let bundle: CompiledBundle = match ciborium::from_reader(&bytes[..]) {
        Ok(b) => b,
        Err(e) => {
            // Format drift / corruption → miss (guard 2); recompiled + re-stored.
            eprintln!("cwasm_cache: bundle decode failed (cold path): {e}");
            return None;
        }
    };
    // Deserialize cwasm + rebuild registry via the same path the cold build
    // uses. `None` here = wasmtime toolchain skew / tamper → miss (guard 3).
    match bundle_to_entry(&bundle, runner) {
        Some(entry) => Some(entry),
        None => {
            eprintln!("cwasm_cache: cwasm deserialize failed (cold path)");
            None
        }
    }
}

/// Store a freshly-compiled [`CompiledBundle`] to the L2 cache. The bundle
/// already carries the serialized cwasm (the [`Compiler`](crate::compiler::Compiler)
/// produced it), so this only encodes + writes — no re-serialize. Best-effort:
/// any failure (encode, transport) is logged and swallowed; a broken cache never
/// breaks a session.
pub async fn store(cache: &CacheStore, composition_key: &str, bundle: &CompiledBundle) {
    let mut encoded = Vec::new();
    if let Err(e) = ciborium::into_writer(bundle, &mut encoded) {
        eprintln!("cwasm_cache: bundle encode failed (skip store): {e}");
        return;
    }
    if let Err(e) = cache.store(&cache_id(composition_key), encoded).await {
        eprintln!("cwasm_cache: L2 store failed (non-fatal): {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_id_scopes_by_composition_and_format() {
        assert_eq!(cache_id("abc"), format!("abc.v{CACHE_FORMAT_VERSION}"));
        assert_ne!(cache_id("abc"), cache_id("abd"));
    }
}
