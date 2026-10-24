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

/// The embedded interfaces a component imports through a slot of its own:
/// its texts alone. DF stays merged, so it is not one of these, and icons are
/// no catalog at all — the host's own functions ([`crate::icons`]).
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

/// One slot a component's texts come through: the import its embedding
/// renamed its `i18n` to, after its catalog, which the compile found among
/// an artifact's imports with that catalog nested in the same artifact. The
/// host `Linker` registers an instance named `instance_name` whose func
/// resolves keys against the catalog with `catalog_hash` alone, so a
/// plugin's text never resolves to the policy's (or another plugin's). DF is
/// merged and served first-match.
///
/// serde: part of the L2 cwasm-cache bundle — the import manifest is
/// stored beside the cwasm so a cache hit reconstructs the host
/// `Linker` registrations without re-fusing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmbeddedImport {
    pub instance_name: String,
    pub catalog_hash: [u8; 32],
    pub iface: EmbeddedIface,
    /// Version of the renamed interface — its `@x.y.z` (empty if
    /// unversioned). Part of `instance_name`, so a same-catalog
    /// different-version import can't collide onto one slot.
    pub version: String,
}
