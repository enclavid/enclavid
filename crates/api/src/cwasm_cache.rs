//! L2 cwasm-cache bundle codec + best-effort load / store.
//!
//! The L1 [`SessionPolicyCache`](crate::runtime::SessionPolicyCache) holds
//! compiled [`PolicyEntry`]s in RAM, keyed by composition hash. This is
//! the tier below it: a broker-backed blob store
//! ([`broker_client::CacheStore`]) that survives a TEE restart. A
//! `PolicyEntry` (fused `Component` + import manifest + embedded registry)
//! is a pure function of the pinned artifacts, so it can be serialized
//! once and reloaded on a later boot without re-pulling or re-compiling.
//!
//! ## Why the bundle carries more than the cwasm
//!
//! Compiling to `cwasm` drops the embedded custom sections (i18n / icons
//! / disclosure-fields catalogs) — host-side metadata wasmtime doesn't
//! keep. So the bundle carries the cwasm PLUS the small metadata needed
//! to rebuild the rest of the `PolicyEntry`: the per-component i18n/icons
//! import manifest and the parsed catalogs (the exact inputs to the
//! registry builder, so a hit reconstructs a byte-identical registry via
//! the same code path as the cold build).
//!
//! ## Compatibility / invalidation — three independent guards
//!
//! A stale on-disk bundle after a code update must never load wrong; it
//! must become a clean miss (→ recompile). Three layers, each catching a
//! different axis:
//!   1. [`CACHE_FORMAT_VERSION`] folded into `cache_id` — a change to the
//!      bundle layout yields a new blob name AND AAD, so old bundles are
//!      never addressed by the new binary.
//!   2. `#[serde(deny_unknown_fields)]` + no `#[serde(default)]` — even if
//!      the version bump is forgotten, ANY struct-shape drift makes the
//!      CBOR decode error (a missing field OR an extra field both fail),
//!      which this treats as a miss.
//!   3. wasmtime's own compatibility header — [`Runner::deserialize_component`]
//!      returns `Err` on a toolchain skew, so an incompatible cwasm is a
//!      miss, then re-stored fresh. (The semantic case — same field shape,
//!      changed meaning — is caught only by guard 1, an inherent limit of
//!      any serialization, named honestly.)
//!
//! Both directions are BEST-EFFORT: a miss, transport failure, decode
//! error, or wasmtime skew all degrade silently to the cold path. The
//! cache is a pure optimization; correctness never depends on it.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use broker_client::CacheStore;
use enclavid_engine::{Component, ComponentDecls, EmbeddedImport, EmbeddedRegistry, Runner};

use crate::runtime::PolicyEntry;

/// Bumped whenever the [`CachedBundle`] wire layout changes (a field
/// added / removed / retyped, or a nested serde type's shape changes). A
/// bump re-partitions the cache: old bundles get a different `cache_id`
/// and are never read (guard 1).
const CACHE_FORMAT_VERSION: u32 = 1;

/// Opaque cache key: the composition hash scoped by the bundle-format
/// epoch. [`CacheStore`] uses this as both the AEAD AAD and the
/// filename-label input, so a format bump invalidates cleanly.
fn cache_id(composition_key: &str) -> String {
    format!("{composition_key}.v{CACHE_FORMAT_VERSION}")
}

/// The serialized form of a compiled [`PolicyEntry`]. `deny_unknown_fields`
/// + no `#[serde(default)]` anywhere below is deliberate (guard 2): unlike
/// the broker wire DTOs — which span two independently-deployed processes
/// and WANT additive tolerance — this bundle is written and read by ONE
/// binary version, so any schema drift must fail-closed to a miss, never
/// silently default.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CachedBundle {
    /// wasmtime-serialized fused component — the amortized Cranelift codegen.
    cwasm: Vec<u8>,
    /// Per-catalog i18n / icons import manifest (lost in compile; needed
    /// to register the host `Linker` instances).
    embedded_imports: Vec<EmbeddedImport>,
    /// Per-component parsed catalogs, composition order (policy first) —
    /// the exact registry-builder inputs.
    catalogs: Vec<CatalogEntry>,
}

/// One component's `(content_hash, parsed catalog)` — a registry-builder
/// input pair.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogEntry {
    hash: [u8; 32],
    decls: ComponentDecls,
}

/// Try to reconstruct a compiled [`PolicyEntry`] from the L2 cache.
/// Returns `None` on ANY failure (miss, transport error, decode error,
/// wasmtime skew) — the caller falls through to the cold compile path.
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
    let bundle: CachedBundle = match ciborium::from_reader(&bytes[..]) {
        Ok(b) => b,
        Err(e) => {
            // Format drift / corruption → miss (guard 2); recompiled + re-stored.
            eprintln!("cwasm_cache: bundle decode failed (cold path): {e}");
            return None;
        }
    };
    let component = match runner.deserialize_component(&bundle.cwasm) {
        Ok(c) => c,
        Err(e) => {
            // wasmtime toolchain skew / tamper → miss (guard 3).
            eprintln!("cwasm_cache: cwasm deserialize failed (cold path): {e}");
            return None;
        }
    };
    // Rebuild the embedded registry from the stored catalogs via the same
    // builder the cold path uses → byte-identical registry.
    let mut builder = EmbeddedRegistry::builder();
    for c in &bundle.catalogs {
        builder.add_component(c.hash, c.decls.clone());
    }
    Some(Arc::new(PolicyEntry {
        component: Arc::new(component),
        embedded_imports: Arc::new(bundle.embedded_imports),
        embedded: Arc::new(builder.build()),
    }))
}

/// Serialize a freshly-compiled composition and store it to the L2 cache.
/// Best-effort: any failure (serialize, encode, transport) is logged and
/// swallowed — a broken cache never breaks a session.
pub async fn store(
    cache: &CacheStore,
    runner: &Runner,
    composition_key: &str,
    component: &Component,
    embedded_imports: &[EmbeddedImport],
    catalogs: &[([u8; 32], ComponentDecls)],
) {
    let cwasm = match runner.serialize_component(component) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cwasm_cache: serialize_component failed (skip store): {e}");
            return;
        }
    };
    let bundle = CachedBundle {
        cwasm,
        embedded_imports: embedded_imports.to_vec(),
        catalogs: catalogs
            .iter()
            .map(|(hash, decls)| CatalogEntry {
                hash: *hash,
                decls: decls.clone(),
            })
            .collect(),
    };
    let mut encoded = Vec::new();
    if let Err(e) = ciborium::into_writer(&bundle, &mut encoded) {
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
    use enclavid_engine::EmbeddedIface;

    fn sample_bundle() -> CachedBundle {
        let mut decls = ComponentDecls::default();
        decls.disclosure_fields.insert("dob".to_string());
        decls.icons.insert("passport".to_string());
        CachedBundle {
            cwasm: vec![1, 2, 3, 4],
            embedded_imports: vec![EmbeddedImport {
                instance_name: "embedded-slot:abcd/i18n".to_string(),
                catalog_hash: [7u8; 32],
                iface: EmbeddedIface::I18n,
                version: "0.1.0".to_string(),
            }],
            catalogs: vec![CatalogEntry {
                hash: [9u8; 32],
                decls,
            }],
        }
    }

    fn encode<T: Serialize>(v: &T) -> Vec<u8> {
        let mut b = Vec::new();
        ciborium::into_writer(v, &mut b).unwrap();
        b
    }

    #[test]
    fn bundle_round_trips() {
        let bytes = encode(&sample_bundle());
        let back: CachedBundle = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(back.cwasm, vec![1, 2, 3, 4]);
        assert_eq!(back.embedded_imports.len(), 1);
        assert_eq!(back.embedded_imports[0].catalog_hash, [7u8; 32]);
        assert_eq!(back.catalogs.len(), 1);
        assert!(back.catalogs[0].decls.disclosure_fields.contains("dob"));
    }

    #[test]
    fn cache_id_scopes_by_composition_and_format() {
        assert_eq!(cache_id("abc"), format!("abc.v{CACHE_FORMAT_VERSION}"));
        assert_ne!(cache_id("abc"), cache_id("abd"));
    }

    /// Guard 2: an EXTRA field (bundle written by a newer binary that
    /// added a field) must fail to decode into the current struct → miss,
    /// not a silent partial read.
    #[test]
    fn deny_unknown_fields_rejects_extra() {
        #[derive(Serialize)]
        struct BundlePlus {
            cwasm: Vec<u8>,
            embedded_imports: Vec<EmbeddedImport>,
            catalogs: Vec<CatalogEntry>,
            future_field: u32,
        }
        let b = sample_bundle();
        let plus = BundlePlus {
            cwasm: b.cwasm,
            embedded_imports: b.embedded_imports,
            catalogs: b.catalogs,
            future_field: 42,
        };
        let bytes = encode(&plus);
        assert!(
            ciborium::from_reader::<CachedBundle, _>(&bytes[..]).is_err(),
            "extra field must error (→ cache miss), not decode partially"
        );
    }

    /// Guard 2: a MISSING field (bundle written by an older binary before
    /// a field existed) must also fail → miss, never a defaulted value.
    #[test]
    fn missing_field_rejected() {
        #[derive(Serialize)]
        struct BundleMinus {
            cwasm: Vec<u8>,
            embedded_imports: Vec<EmbeddedImport>,
            // `catalogs` absent.
        }
        let minus = BundleMinus {
            cwasm: vec![1],
            embedded_imports: vec![],
        };
        let bytes = encode(&minus);
        assert!(
            ciborium::from_reader::<CachedBundle, _>(&bytes[..]).is_err(),
            "missing field must error (→ cache miss), not default"
        );
    }
}
