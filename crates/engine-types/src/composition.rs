//! Composition domain types: the plugin fusion input (`PluginInstance`), the
//! model files an artifact carries (`ModelLayer`), and what fusion produces for
//! the host `Linker`: the embedded-import manifest (`EmbeddedImport` /
//! `EmbeddedIface`) and the models (`ModelImport`, `ModelFile`).
//!
//! These cross the compile→execute seam: `PluginInstance` is the
//! compiler's input, `EmbeddedImport` is what the compiler emits and the
//! executor's host `Linker` consumes. Plain data (serde), so both halves
//! and the client-only orchestrator name them without wasmtime.

/// One plugin's component bytes bundled with the WIT package id it
/// satisfies. The api crate constructs these from the client-supplied
/// `PluginPin` list at session start (pull → bytes) and hands them to
/// `Compiler::compose`. `package` is the value the client passed in
/// `PluginPin.package` (e.g. `"vendor:plugin@0.1.0"`); it identifies
/// which set of imports declared in the policy's WIT world this plugin
/// is meant to satisfy and names the plugin in the composition graph.
/// `wasm` is the raw component binary — fusion happens on bytes, so no
/// pre-compiled `Component` is kept.
///
/// serde: rides the compile RPC directly (the `engine_rpc::RemoteCompiler::compile`
/// argument) — no separate wire-mirror type is needed, mirroring how
/// `EmbeddedImport` already crosses the wire.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PluginInstance {
    pub package: String,
    /// `serde_bytes` so ciborium ships this as one CBOR byte string, not a
    /// per-byte integer array (which balloons the compile request + costs
    /// hundreds of ms for a multi-MiB plugin — see `engine_rpc::CompiledBundle::cwasm`).
    #[serde(with = "serde_bytes")]
    pub wasm: Vec<u8>,
    /// The model files the plugin's artifact carries beside its component.
    pub model_layers: Vec<ModelLayer>,
}

/// One file of a model an artifact carries — a layer of it beside the
/// component — as the artifact's manifest declares it: `<function>.onnx`, the
/// model's graph, or `<function>.onnx.data`, the data file its graph points
/// into, for the function of the component's `models` that hands the model
/// out. The compile reads what the layer is called and what it is; its bytes
/// reach only the execution worker, when a round first runs the model.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ModelLayer {
    /// The layer's name: its file's.
    pub name: String,
    /// The SHA-256 of the file.
    pub sha256: [u8; 32],
    /// Its length in bytes.
    pub length: u64,
}

/// One of a composition's model files — a graph or a data file — held once
/// however many models name it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ModelFile {
    pub sha256: [u8; 32],
    pub length: u64,
}

/// One model of a composition: a function of a slot's models,
/// `enclavid-ext:<slot>/models`, as the fused composition imports it; the
/// resource of the slot it hands out, whose `run` takes the host's tensors and
/// gives them back; and the files the model is: its graph, and the data file
/// the graph points into, if it has one. The host `Linker` registers
/// `function`, `resource` and its `run` in the instance `instance_name`, the
/// `run` as the type the composition imports it at.
///
/// serde: part of the L2 cwasm-cache bundle, beside the cwasm, as
/// [`EmbeddedImport`] is.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ModelImport {
    pub instance_name: String,
    pub function: String,
    pub resource: String,
    /// The graph: its index in the composition's model files.
    pub graph: u32,
    /// The data file: its index in the composition's model files.
    pub data: Option<u32>,
}

/// The embedded interfaces a slot is served from a catalog: its texts alone.
/// The policy's disclosure fields are served by their interface's name, and
/// icons are no catalog at all — the host's own functions ([`crate::icons`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EmbeddedIface {
    I18n,
}

impl EmbeddedIface {
    /// Slug segment used in the distinct import name, and the tag by
    /// which the host `Linker` picks the matching registry store.
    pub fn as_str(self) -> &'static str {
        match self {
            EmbeddedIface::I18n => "i18n",
        }
    }
}

/// One slot's texts, as the fused composition imports them:
/// `enclavid-ext:<slot>/i18n@<version>`, every component's import of them made
/// one by the fusion, and served from the one catalog that names the slot,
/// which the compile found. The host `Linker` registers an instance named
/// `instance_name` whose func resolves keys against the catalog with
/// `catalog_hash` alone, so one slot's text never resolves to another's.
///
/// serde: part of the L2 cwasm-cache bundle — the import manifest is
/// stored beside the cwasm so a cache hit reconstructs the host
/// `Linker` registrations without re-fusing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmbeddedImport {
    pub instance_name: String,
    pub catalog_hash: [u8; 32],
    pub iface: EmbeddedIface,
    /// Version of the imported interface — its `@x.y.z`. Part of
    /// `instance_name`.
    pub version: String,
}
