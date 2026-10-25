//! Composition domain types: the plugin fusion input (`PluginInstance`)
//! and the embedded-import manifest fusion produces (`EmbeddedImport` /
//! `EmbeddedIface`).
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
