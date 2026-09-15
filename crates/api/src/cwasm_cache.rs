//! L2 cwasm-cache: best-effort load / store of a [`CompiledBundle`].
//!
//! This is the fleet's DURABLE cache tier and the orchestrator's ONLY compiled
//! artifact store — [`hatch_client::CacheStore`], AEAD-sealed under
//! `tee_seal_key`, over the storage-CVM backend api dials at boot. It survives a
//! TEE restart. There is no
//! api-side in-RAM component cache; the sole in-memory L1 lives on the
//! execution-worker, which on a miss says so (`RunOutcome::CacheMiss`) and lets
//! api load from here. A [`CompiledBundle`] is a pure function of the pinned
//! artifacts, so a cold compile stores it once and every later boot or worker
//! miss reloads it without re-pulling or re-compiling.
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
//! ## What the seal bounds, and what it does not
//!
//! The AEAD binds a stored bundle to its `cache_id` under a key the host cannot
//! hold, so the host cannot substitute one composition's cwasm for another's or
//! forge an entry. That is the whole of it.
//!
//! It says nothing about whether the bytes are the right compilation of the
//! pinned artifacts, because api performs the seal — over whatever the
//! compile-worker returned. The binding runs from api's key to api's name, and a
//! compiler that returned something else would have that sealed just as faithfully.
//! Nothing on the compile leg closes that (see `crate::compiler`, where the
//! accepted risk is written); the store is not where it could be closed.
//!
//! Load/store are BEST-EFFORT: a miss, transport failure, or decode error all
//! degrade to the cold compile path. The cache is a pure optimization;
//! correctness never depends on it.

use hatch_client::CacheStore;

use engine_rpc::{CompatToken, CompiledBundle, CompositionKey};

/// Bumped whenever the [`CompiledBundle`] wire layout changes (a field
/// added / removed / retyped, or a nested serde type's shape changes). A bump
/// re-partitions the cache: old bundles get a different `cache_id` and are never
/// read (guard 1).
const CACHE_FORMAT_VERSION: u32 = 1;

/// Opaque cache key: the composition hash scoped by the runtime ABI
/// (`compat_token`) and the bundle-format epoch. [`CacheStore`] uses it as both
/// the AEAD AAD and the filename-label input, so a runtime bump OR a format bump
/// invalidates cleanly.
///
/// Both halves are types rather than strings, which is what makes the join
/// unambiguous: the first is 64 hex characters and the second cannot be empty, so
/// no two distinct pairs render to one id. As bare strings the second half was a
/// worker-chosen value of any length going straight into a name.
fn cache_id(composition_key: &CompositionKey, compat_token: &CompatToken) -> String {
    format!("{composition_key}.{compat_token}.v{CACHE_FORMAT_VERSION}")
}

/// Try to load the [`CompiledBundle`] for `(composition_key, compat_token)` from
/// L2. Returns `None` on ANY failure (miss, transport error, decode error) — the
/// caller falls through to the cold compile path.
pub async fn try_load(
    cache: &CacheStore,
    composition_key: &CompositionKey,
    compat_token: &CompatToken,
) -> Option<CompiledBundle> {
    let id = cache_id(composition_key, compat_token);
    let bytes = match cache.load(&id).await {
        Ok(Some(b)) => b,
        Ok(None) => return None, // clean miss (404 / unopenable blob)
        Err(e) => {
            safe_logger::debug!("cwasm_cache: L2 load transport error (cold path): {e}");
            return None;
        }
    };
    match ciborium::from_reader(&bytes[..]) {
        Ok(b) => Some(b),
        Err(e) => {
            // Format drift / corruption → miss (guard 2); recompiled + re-stored.
            safe_logger::debug!("cwasm_cache: bundle decode failed (cold path): {e}");
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
    composition_key: &CompositionKey,
    compat_token: &CompatToken,
    bundle: &CompiledBundle,
) {
    let mut encoded = Vec::new();
    if let Err(e) = ciborium::into_writer(bundle, &mut encoded) {
        safe_logger::debug!("cwasm_cache: bundle encode failed (skip store): {e}");
        return;
    }
    if let Err(e) = cache
        .store(&cache_id(composition_key, compat_token), encoded)
        .await
    {
        safe_logger::debug!("cwasm_cache: L2 store failed (non-fatal): {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> CompositionKey {
        CompositionKey::from_digest([byte; 32])
    }

    fn token(s: &str) -> CompatToken {
        CompatToken::parse(s).expect("a legal token shape")
    }

    #[test]
    fn cache_id_scopes_by_composition_token_and_format() {
        assert_eq!(
            cache_id(&key(0xAB), &token("tok")),
            format!("{}.tok.v{CACHE_FORMAT_VERSION}", key(0xAB))
        );
        // Composition, token, and format each partition the key.
        assert_ne!(
            cache_id(&key(0xAB), &token("tok")),
            cache_id(&key(0xAC), &token("tok"))
        );
        assert_ne!(
            cache_id(&key(0xAB), &token("tok")),
            cache_id(&key(0xAB), &token("tok2"))
        );
    }

    /// The two halves cannot be made to render as one another's: the first is a
    /// fixed 64 characters, so no token can push the boundary and land a pair on
    /// another pair's id. As bare strings that argument rested on the shapes
    /// nobody was checking.
    #[test]
    fn no_token_can_forge_another_pairs_id() {
        let honest = cache_id(&key(0xAB), &token("wt46-cm-fuel"));
        for forged in ["a", "a.b", &format!("x.{}", key(0xAC))] {
            let Ok(t) = CompatToken::parse(forged) else {
                continue;
            };
            assert_ne!(cache_id(&key(0xAC), &t), honest);
        }
    }
}
