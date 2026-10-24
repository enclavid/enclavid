//! Host implementations of the embedded resolvers and the ref resources.
//!
//! The `enclavid:host/embedded-disclosure-fields` func resolves a key
//! against the frozen [`EmbeddedRegistry`](super::registry::EmbeddedRegistry)
//! and MINTS an unforgeable WIT `resource` whose rep carries the RESOLVED
//! data (the DF key). A component cannot fabricate a handle, so membership
//! needs no keyed token — the handle IS the proof the key was declared.
//! The engine dereferences the rep at the action boundary
//! (`runner::convert`), so the resolved data is self-contained (nothing
//! downstream re-consults the registry). The other refs are minted the same
//! way in `runner`: a text through the slot its component's catalog names,
//! the policy's typed disclosure fields, and an icon from a name of the
//! host's own.
//!
//! Two resolution modes share the stores:
//!   * MERGED (first match across catalogs) — disclosure fields, by the
//!     plugins' string keys here and the policy's typed ones in `runner`.
//!   * STRICT (one bound catalog) — a component's texts, minted in
//!     `runner::register_slots` off
//!     [`RefStore::resolve_strict`](super::store::RefStore::resolve_strict).

use wasmtime::component::Resource;

use super::store::{DisclosureFieldRef, DisclosureFields, IconRef, LocalizedRef, RefKind};
use crate::state::HostState;

/// A disclosure field by the key a plugin's helper names, resolved MERGED
/// (first match) and minted as a resource carrying it. Traps if no catalog
/// declared the key.
impl crate::enclavid::host::embedded_disclosure_fields::Host for HostState {
    async fn disclosure_field(
        &mut self,
        key: String,
    ) -> wasmtime::Result<Resource<DisclosureFieldRef>> {
        let data = self
            .embedded
            .disclosure_fields
            .resolve_first_match(&key)
            .ok_or_else(|| undeclared_trap::<DisclosureFields>(&key))?
            .clone();
        Ok(self.table.push(DisclosureFieldRef(data))?)
    }
}

// Resource destructors. The rep is a plain owned value in the table;
// dropping the handle just removes it. The types interface (`Host`)
// carries no functions of its own.
impl crate::enclavid::host::types::Host for HostState {}

impl crate::enclavid::host::types::HostLocalizedRef for HostState {
    async fn drop(&mut self, rep: Resource<LocalizedRef>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}
impl crate::enclavid::host::types::HostIconRef for HostState {
    async fn drop(&mut self, rep: Resource<IconRef>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}
impl crate::enclavid::host::types::HostDisclosureFieldRef for HostState {
    async fn drop(&mut self, rep: Resource<DisclosureFieldRef>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

/// Trap for a key no catalog (merged) or the bound catalog (strict)
/// declared under this kind. Shared by the merged host func above and
/// the ones `runner` registers.
///
/// The `key` is interpolated, and it stays in THIS process: wasm chose that
/// string, so it could be a function of the applicant's data, and nothing carries
/// this message off the guest. `engine_rpc::ExecError` has one value for every way
/// a policy can fail, precisely so that no part of this sentence reaches a hop the
/// host counts.
pub fn undeclared_trap<K: RefKind>(key: &str) -> wasmtime::Error {
    wasmtime::Error::msg(format!(
        "embedded {kind}: no component declared key '{key}' \
         in its enclavid:embedded.{kind}s.v1 section",
        kind = K::NAME,
    ))
}
