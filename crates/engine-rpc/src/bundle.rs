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
    pub cwasm: Vec<u8>,
    /// Per-catalog i18n / icons import manifest (lost in compile; needed to
    /// register the host `Linker` instances at run time).
    pub embedded_imports: Vec<EmbeddedImport>,
    /// Per-component parsed catalogs, composition order (policy first) — the
    /// exact registry-builder inputs.
    pub catalogs: Vec<CatalogEntry>,
}

/// One component's `(content_hash, parsed catalog)` — a registry-builder input.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogEntry {
    pub hash: [u8; 32],
    pub decls: ComponentDecls,
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
