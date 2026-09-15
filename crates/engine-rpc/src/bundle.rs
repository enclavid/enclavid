//! The compiled-composition artifact — shared by BOTH boundaries.
//!
//! A [`CompiledBundle`] is the compile boundary's OUTPUT and the execute
//! boundary's priming INPUT (and the api L2 cache entry), so it is defined
//! ungated (`any(compile, execute)`) and both feature halves name it. It pulls
//! only the wasmtime-free `engine-types` leaf — an execution-worker referencing
//! it links `engine-types` (which it needs anyway: `ComponentDecls` to rebuild
//! the embedded registry, `EmbeddedImport` to register the strict resolvers),
//! but still NO Cranelift.

use serde::{Deserialize, Serialize};

use engine_types::composition::EmbeddedImport;
use engine_types::embedded::ComponentDecls;

/// A freshly compiled composition: the wasmtime-serialized fused component
/// (`cwasm`) plus the host-side metadata compile drops (the per-catalog
/// i18n/icons import manifest and the parsed per-component catalogs). This is
/// BOTH the compile RPC return value AND the L2 cache bundle
/// (`enclavid-api::cwasm_cache`) AND the execute-worker priming payload — one
/// compiled artifact, three consumers, so a cold compile, an L2 hit, and a
/// worker cache-prime all reconstruct through the same fields.
///
/// `deny_unknown_fields` + no `#[serde(default)]` is deliberate: the L2 bundle
/// is written and read by ONE binary version, so any schema drift must
/// fail-closed to a cache miss, never silently default. (The RPC uses — compile
/// reply, execute prime — are between same-version fleet nodes; the same
/// fail-closed shape is correct there too — a version-skewed node should error,
/// not misinterpret.)
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledBundle {
    /// wasmtime-serialized fused component — the amortized Cranelift codegen.
    /// `serde_bytes` so ciborium encodes it as one CBOR byte string, not a
    /// 7M-element integer array (which cost ~hundreds of ms per transfer over the
    /// api hop, the child hop, AND to seal into L2).
    #[serde(with = "serde_bytes")]
    pub cwasm: Vec<u8>,
    /// Per-catalog i18n / icons import manifest (lost in compile; needed to
    /// register the host `Linker` instances at run time).
    pub embedded_imports: Vec<EmbeddedImport>,
    /// Per-component parsed catalogs, composition order (policy first) — the
    /// exact registry-builder inputs.
    pub catalogs: Vec<CatalogEntry>,
}

impl CompiledBundle {
    /// Roughly what a cache keeping this bundle pays for it, in bytes.
    ///
    /// Every field, not just the cwasm, and that is the whole point. The
    /// execution-worker's L1 weighed `cwasm.len()` alone while each entry also
    /// retained `embedded_imports` and `catalogs` — taken verbatim from a caller
    /// that no leaf can identify, and bounded by nothing on decode. So a budget
    /// that looked like a RAM ceiling was a cwasm ceiling, and a caller sending a
    /// minimal header with megabytes of catalog was charged almost nothing for
    /// memory it kept for the cache's idle window.
    ///
    /// Approximate and biased HIGH, for the reason
    /// `ComponentDecls::retained_bytes` gives: under-charging is the failure mode,
    /// over-charging costs a little capacity.
    pub fn retained_bytes(&self) -> u64 {
        const PER_IMPORT_OVERHEAD: usize = 64;
        let imports: usize = self
            .embedded_imports
            .iter()
            .map(|i| i.instance_name.len() + i.version.len() + PER_IMPORT_OVERHEAD)
            .sum();
        let catalogs: usize = self
            .catalogs
            .iter()
            .map(|c| c.decls.retained_bytes() + PER_IMPORT_OVERHEAD)
            .sum();
        (self.cwasm.len() + imports + catalogs) as u64
    }
}

/// One component's `(content_hash, parsed catalog)` — a registry-builder input.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogEntry {
    pub hash: [u8; 32],
    pub decls: ComponentDecls,
}

/// The child-`prime` payload for the MMAP delivery path: the 7-15 MiB `cwasm` is
/// NOT shipped over the child hop — the child MMAPs it via
/// `Component::deserialize_file`, so `prime` carries only a host-local PATH to it
/// plus the small metadata. `cwasm_path` names an inherited fd the supervisor
/// installed before exec (`/proc/self/fd/N`, backed by an anonymous cwasm memfd);
/// the child just treats it as a path. Keeps the big blob off remoc AND lets
/// several children of the same composition share its read-only code pages.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleRef {
    /// Host-local path the child feeds to `Component::deserialize_file` (mmap) —
    /// its inherited cwasm fd, e.g. `/proc/self/fd/3`.
    pub cwasm_path: String,
    /// Per-catalog i18n/icons import manifest (needed to register the strict
    /// host `Linker` instances) — same as [`CompiledBundle::embedded_imports`].
    pub embedded_imports: Vec<EmbeddedImport>,
    /// Per-component parsed catalogs (the registry-builder inputs) — same as
    /// [`CompiledBundle::catalogs`].
    pub catalogs: Vec<CatalogEntry>,
}

#[cfg(test)]
pub(crate) fn sample_bundle() -> CompiledBundle {
    use engine_types::composition::EmbeddedIface;
    let mut decls = ComponentDecls::default();
    decls.disclosure_fields.insert("dob".to_string());
    decls.icons.insert("passport".to_string());
    CompiledBundle {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    fn encode<T: Serialize>(v: &T) -> Vec<u8> {
        let mut b = Vec::new();
        ciborium::into_writer(v, &mut b).unwrap();
        b
    }

    #[test]
    fn bundle_round_trips() {
        let bytes = encode(&sample_bundle());
        let back: CompiledBundle = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(back.cwasm, vec![1, 2, 3, 4]);
        assert_eq!(back.embedded_imports.len(), 1);
        assert_eq!(back.embedded_imports[0].catalog_hash, [7u8; 32]);
        assert_eq!(back.catalogs.len(), 1);
        assert!(back.catalogs[0].decls.disclosure_fields.contains("dob"));
    }

    /// The weight a cache charges follows every field, not just the cwasm.
    ///
    /// This is the shape the execution-worker's L1 was blind to: a minimal cwasm
    /// that passes the header check, carrying megabytes of catalog, was charged
    /// almost nothing for what it kept.
    #[test]
    fn a_bundle_is_charged_for_what_it_retains_not_just_its_cwasm() {
        let mut decls = ComponentDecls::default();
        for i in 0..4_000 {
            decls.icons.insert(format!("icon-{i}-{}", "x".repeat(200)));
        }
        let heavy = CompiledBundle {
            // A plausible header and nothing else — what a caller sends when the
            // payload it cares about is somewhere other than the cwasm.
            cwasm: vec![0u8; 64],
            embedded_imports: Vec::new(),
            catalogs: vec![CatalogEntry {
                hash: [0u8; 32],
                decls,
            }],
        };
        assert!(
            heavy.retained_bytes() > 1024 * 1024,
            "a bundle retaining ~1 MiB of catalog was charged {}",
            heavy.retained_bytes()
        );
        // And an ordinary bundle is still charged about its cwasm, so the budget
        // keeps meaning what it says for every entry that matters.
        let ordinary = CompiledBundle {
            cwasm: vec![0u8; 8 * 1024 * 1024],
            ..sample_bundle()
        };
        let cwasm_len = ordinary.cwasm.len() as u64;
        assert!(ordinary.retained_bytes() >= cwasm_len);
        assert!(ordinary.retained_bytes() < cwasm_len + 4096);
    }

    /// L2 guard: an EXTRA field (bundle written by a newer binary) must fail to
    /// decode → cache miss / version-skew error, not a silent partial read.
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
        assert!(ciborium::from_reader::<CompiledBundle, _>(&encode(&plus)[..]).is_err());
    }
}
