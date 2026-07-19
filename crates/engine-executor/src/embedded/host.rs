//! Host implementations of the embedded resolvers and the ref resources.
//!
//! Each `enclavid:host/embedded-*` func resolves a key against the
//! frozen [`EmbeddedRegistry`](super::registry::EmbeddedRegistry) and
//! MINTS an unforgeable WIT `resource` whose rep carries the RESOLVED
//! data (translations / icon name / DF key). A component cannot
//! fabricate a handle, so membership needs no keyed token — the handle
//! IS the proof the key was declared. The engine dereferences the rep at
//! the action boundary (`runner::convert`), so the resolved data is
//! self-contained (nothing downstream re-consults the registry).
//!
//! Two resolution modes share the stores:
//!   * MERGED (first match across catalogs) — the canonical `Host` funcs
//!     below: disclosure-fields always, and i18n / icons for a lone
//!     unfused policy whose imports weren't routed to a twin.
//!   * STRICT (one bound catalog) — the per-component twins fusion
//!     produced; minted in `runner::register_strict_embedded` off
//!     [`RefStore::resolve_strict`](super::store::RefStore::resolve_strict).

use wasmtime::component::Resource;

use super::store::{DisclosureFieldRef, IconRef, LocalizedRef, RefKind};
use crate::state::HostState;

/// Emit the bindgen `Host` impl for one embedded resolver: resolve the
/// key MERGED (first match), then mint a resource carrying the resolved
/// data. Traps if no catalog declared the key.
macro_rules! embedded_kind {
    (
        host_trait = $host_trait:path,
        host_method = $host_method:ident,
        store = $store:ident,
        kind = $kind:ty,
        rep = $rep:path $(,)?
    ) => {
        impl $host_trait for HostState {
            async fn $host_method(&mut self, key: String) -> wasmtime::Result<Resource<$rep>> {
                let data = self
                    .embedded
                    .$store
                    .resolve_first_match(&key)
                    .ok_or_else(|| undeclared_trap::<$kind>(&key))?
                    .clone();
                Ok(self.table.push($rep(data))?)
            }
        }
    };
}

embedded_kind! {
    host_trait = crate::enclavid::host::embedded_disclosure_fields::Host,
    host_method = disclosure_field,
    store = disclosure_fields,
    kind = super::store::DisclosureFields,
    rep = DisclosureFieldRef,
}

embedded_kind! {
    host_trait = crate::enclavid::host::embedded_i18n::Host,
    host_method = localized,
    store = localized,
    kind = super::store::Localized,
    rep = LocalizedRef,
}

embedded_kind! {
    host_trait = crate::enclavid::host::embedded_icons::Host,
    host_method = icon,
    store = icons,
    kind = super::store::Icon,
    rep = IconRef,
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
/// declared under this kind. Shared by the merged host funcs above and
/// the strict twins in `runner`.
pub fn undeclared_trap<K: RefKind>(key: &str) -> wasmtime::Error {
    wasmtime::Error::msg(format!(
        "embedded {kind}: no component declared key '{key}' \
         in its enclavid:embedded.{kind}s.v1 section",
        kind = K::NAME,
    ))
}
