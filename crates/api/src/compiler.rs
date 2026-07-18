//! The COMPILE boundary: fuse + compile a policy + its pinned plugins into a
//! [`CompiledBundle`], behind a [`Compiler`] trait so the compile step can move
//! OUT of process (a compile-worker CVM) later without touching the caller.
//!
//! [`LocalCompiler`] runs the compile in-process on the shared [`Runner`] today.
//! A future `RemoteCompiler` implements the same trait over a transport; the
//! orchestrator only ever holds an `Arc<dyn Compiler>` and `deserialize`s the
//! returned cwasm bytes — a boundary that is already PROCESS-HONEST (bytes in,
//! bytes out, no live `Component` crosses it), which is why it is the first seam
//! extracted for the CVM split.
//!
//! The [`CompiledBundle`] is ALSO the L2 cache wire format (see
//! [`crate::cwasm_cache`]): a compile output and a cache entry are the same
//! thing, so a cold compile and an L2 hit reconstruct a [`PolicyEntry`] through
//! the one [`CompiledBundle::to_entry`] path.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use enclavid_engine::{
    ComponentDecls, EmbeddedImport, EmbeddedRegistry, PluginInstance, Runner, load_embedded,
};

use crate::runtime::PolicyEntry;

/// A freshly compiled composition: the wasmtime-serialized fused component
/// (`cwasm`) plus the host-side metadata compile drops (the per-catalog
/// i18n/icons import manifest and the parsed per-component catalogs). This is
/// BOTH the [`Compiler`] output and the L2 cache bundle — see the module doc.
///
/// `deny_unknown_fields` + no `#[serde(default)]` is deliberate (L2 guard 2):
/// the bundle is written and read by ONE binary version, so any schema drift
/// must fail-closed to a cache miss, never silently default. See
/// [`crate::cwasm_cache`].
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledBundle {
    /// wasmtime-serialized fused component — the amortized Cranelift codegen.
    cwasm: Vec<u8>,
    /// Per-catalog i18n / icons import manifest (lost in compile; needed to
    /// register the host `Linker` instances at run time).
    embedded_imports: Vec<EmbeddedImport>,
    /// Per-component parsed catalogs, composition order (policy first) — the
    /// exact registry-builder inputs.
    catalogs: Vec<CatalogEntry>,
}

/// One component's `(content_hash, parsed catalog)` — a registry-builder input.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CatalogEntry {
    hash: [u8; 32],
    decls: ComponentDecls,
}

impl CompiledBundle {
    /// Reconstruct the in-RAM [`PolicyEntry`] from the serialized bundle:
    /// `deserialize` the cwasm into a live `Component` on `runner`'s engine and
    /// rebuild the embedded registry from the stored catalogs via the same
    /// builder the cold path uses (→ byte-identical registry). `None` on a
    /// wasmtime toolchain skew / tampered cwasm — an L2 hit treats that as a
    /// miss; the cold path (which deserializes bytes it just serialized on the
    /// same engine) never hits it in practice.
    pub fn to_entry(&self, runner: &Runner) -> Option<Arc<PolicyEntry>> {
        let component = runner.deserialize_component(&self.cwasm).ok()?;
        let mut builder = EmbeddedRegistry::builder();
        for c in &self.catalogs {
            builder.add_component(c.hash, c.decls.clone());
        }
        Some(Arc::new(PolicyEntry {
            component: Arc::new(component),
            embedded_imports: Arc::new(self.embedded_imports.clone()),
            embedded: Arc::new(builder.build()),
        }))
    }
}

/// A compile failure — fusion / codegen / section-parse. The orchestrator maps
/// it to a 500 (it is a pure function of the pinned config, no applicant input;
/// see the session error-model backlog for surfacing it to the consumer).
#[derive(Debug)]
pub struct CompileError(pub String);

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "compile failed: {}", self.0)
    }
}
impl std::error::Error for CompileError {}

/// The COMPILE boundary. Given already-pulled artifact bytes (the orchestrator
/// owns the OCI pull + registry auth), fuse + compile + parse-sections into a
/// [`CompiledBundle`]. Object-safe boxed-future (mirrors
/// [`MediaStore`](enclavid_engine::MediaStore)) so the impl can be swapped for
/// an out-of-process `RemoteCompiler` behind an `Arc<dyn Compiler>`.
pub trait Compiler: Send + Sync {
    fn compile<'a>(
        &'a self,
        policy_wasm: Vec<u8>,
        plugins: Vec<PluginInstance>,
    ) -> Pin<Box<dyn Future<Output = Result<CompiledBundle, CompileError>> + Send + 'a>>;
}

/// In-process compiler: runs fusion + Cranelift on the shared process
/// [`Runner`]. The compile is synchronous CPU work (as it is today); a later
/// `RemoteCompiler` moves it to a compile-worker CVM over a transport.
pub struct LocalCompiler {
    runner: Arc<Runner>,
}

impl LocalCompiler {
    pub fn new(runner: Arc<Runner>) -> Self {
        Self { runner }
    }
}

impl Compiler for LocalCompiler {
    fn compile<'a>(
        &'a self,
        policy_wasm: Vec<u8>,
        plugins: Vec<PluginInstance>,
    ) -> Pin<Box<dyn Future<Output = Result<CompiledBundle, CompileError>> + Send + 'a>> {
        let runner = self.runner.clone();
        Box::pin(async move {
            // Parse each component's embedded sections (dropped by compile) in
            // composition order: policy first, then plugins in pinned order —
            // fixes the merged-DF first-match order (mirrors `Runner::compose`).
            let policy_catalog =
                load_embedded(&policy_wasm).map_err(|e| CompileError(e.to_string()))?;
            let mut catalogs = Vec::with_capacity(1 + plugins.len());
            catalogs.push(CatalogEntry {
                hash: policy_catalog.hash,
                decls: policy_catalog.decls,
            });
            for p in &plugins {
                let c = load_embedded(&p.wasm).map_err(|e| CompileError(e.to_string()))?;
                catalogs.push(CatalogEntry {
                    hash: c.hash,
                    decls: c.decls,
                });
            }
            // Fuse + compile (blocking Cranelift), then serialize to cwasm — the
            // process-honest boundary output (bytes, not a live `Component`).
            let composition = runner
                .compose(&policy_wasm, &plugins)
                .map_err(|e| CompileError(e.to_string()))?;
            let cwasm = runner
                .serialize_component(&composition.component)
                .map_err(|e| CompileError(e.to_string()))?;
            Ok(CompiledBundle {
                cwasm,
                embedded_imports: composition.embedded_imports,
                catalogs,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclavid_engine::EmbeddedIface;

    fn sample_bundle() -> CompiledBundle {
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

    /// L2 guard 2: an EXTRA field (bundle written by a newer binary that added a
    /// field) must fail to decode into the current struct → miss, not a silent
    /// partial read.
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
            ciborium::from_reader::<CompiledBundle, _>(&bytes[..]).is_err(),
            "extra field must error (→ cache miss), not decode partially"
        );
    }

    /// L2 guard 2: a MISSING field (bundle written by an older binary before a
    /// field existed) must also fail → miss, never a defaulted value.
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
            ciborium::from_reader::<CompiledBundle, _>(&bytes[..]).is_err(),
            "missing field must error (→ cache miss), not default"
        );
    }
}
