//! Host implementations of the ref resources.
//!
//! The host MINTS an unforgeable WIT `resource` whose rep carries the
//! RESOLVED data. A component cannot fabricate a handle, so membership needs
//! no keyed token — the handle IS the proof the key was declared. The engine
//! dereferences the rep at the action boundary (`runner::convert`), so the
//! resolved data is self-contained (nothing downstream re-consults the
//! registry). Every ref is minted in `runner`: a text through its slot's
//! catalog, a disclosure field through the policy's, and an icon from a name
//! of the host's own.
//!
//! Two resolution modes share the stores:
//!   * STRICT (one bound catalog) — a slot's texts, minted in
//!     `runner::register_slots` off
//!     [`RefStore::resolve_strict`](super::store::RefStore::resolve_strict).
//!   * FIRST MATCH across catalogs — the policy's disclosure fields, the one
//!     list a composition has, in `runner::register_disclosure_fields`.

use super::store::{DisclosureFieldRef, IconRef, LocalizedRef, RefKind};
use crate::state::HostState;
use wasmtime::component::Resource;

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

/// Trap for a key the catalog it resolves against did not declare under this
/// kind. Shared by the host funcs `runner` registers.
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
