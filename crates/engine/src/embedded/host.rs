//! Host implementations of `enclavid:embedded/disclosure-fields` and
//! `enclavid:embedded/i18n`.
//!
//! Two registration paths exist, both ending in
//! [`get_token_or_trap`] — single source of trap wording shared
//! across slot 0 and slots ≥ 1:
//!
//!   * **Policy slot (0)** — bindgen wires its `Host` traits onto
//!     [`HostState`] via `add_to_linker`; the impls below hard-code
//!     [`POLICY_SLOT`] because the policy always occupies slot 0.
//!   * **Plugin slots (≥ 1)** — bindgen has no per-instance Linker
//!     hook so each plugin's slot index is captured in a closure
//!     registered manually on the plugin's
//!     `Linker<PluginHostState>`. [`register_for_slot`] is that
//!     helper.
//!
//! Both paths trap if the calling component never declared the key
//! in its own `enclavid:embedded.*` sections — the registry is the
//! single source of truth and is consulted identically here.
//!
//! ## Per-kind boilerplate is collapsed into a macro
//!
//! Each `enclavid:embedded/*` interface needs two pieces of
//! protocol-specific glue: one bindgen-driven `Host` trait impl for
//! slot 0 and one Linker `func_wrap_async` registration for each
//! plugin slot. Both pieces have identical bodies — look up the
//! token in the matching store, convert `None` to a trap — but
//! their surrounding shapes differ enough that no single function
//! can express both.
//!
//! [`embedded_kind!`](embedded_kind) emits both pieces per kind,
//! taking the protocol artifacts (Host trait path, method name,
//! store field, WIT instance/func names) as macro args. This keeps
//! the data-side [`RefKind`] free of protocol artifacts and the
//! call-site code to one line per piece.

use std::sync::Arc;

use super::registry::{EmbeddedRegistry, Slot};
use super::store::{RefKind, RefStore};
use crate::state::{HostState, PluginHostState};

/// Slot reserved for the policy across the engine. Plugins occupy
/// slots 1..N in `PluginInstance` list order, registered manually
/// via [`register_for_slot`].
const POLICY_SLOT: Slot = 0;

/// Emit the static binding (bindgen `Host` trait impl for slot 0)
/// and the dynamic binding (per-plugin Linker registration helper
/// for slots ≥ 1) for one `enclavid:embedded/*` interface.
///
/// Args:
///
///   * `host_trait` — bindgen-generated `Host` trait path to impl
///     on [`HostState`].
///   * `host_method` — `Host`-trait method name (matches the WIT
///     interface's function name in snake_case).
///   * `store` — `EmbeddedRegistry` field carrying this kind's
///     [`RefStore`]. Type inference picks the right `RefKind` from
///     the field type so the shared helper's `K::NAME` resolves
///     correctly.
///   * `wit_instance` — fully-qualified WIT instance name as
///     imported by guest components (used at Linker-registration
///     time only).
///   * `wit_func` — WIT function name inside `wit_instance`.
///   * `register_fn` — name of the per-kind plugin Linker
///     registration fn this macro emits. Called once per kind from
///     [`register_for_slot`].
/// The `slot` passed to the emitted `$register_fn` is the slot the
/// plugin closure will validate against — picked by the caller
/// (`register_for_slot`). DF closures get pinned to `POLICY_SLOT`
/// at that call site (single bandwidth gate); i18n/icons closures
/// get the plugin's own slot (per-component scoping). The macro
/// itself is symmetric — asymmetry lives in one place at the
/// `register_for_slot` body below.
macro_rules! embedded_kind {
    (
        host_trait = $host_trait:path,
        host_method = $host_method:ident,
        store = $store:ident,
        wit_instance = $wit_instance:literal,
        wit_func = $wit_func:literal,
        register_fn = $register_fn:ident $(,)?
    ) => {
        impl $host_trait for HostState {
            async fn $host_method(&mut self, key: String) -> wasmtime::Result<String> {
                get_token_or_trap(&self.embedded.$store, POLICY_SLOT, &key)
            }
        }

        fn $register_fn(
            linker: &mut wasmtime::component::Linker<PluginHostState>,
            slot: Slot,
            embedded: Arc<EmbeddedRegistry>,
        ) -> wasmtime::Result<()> {
            linker.root().instance($wit_instance)?.func_wrap_async(
                $wit_func,
                move |_store, (key,): (String,)| {
                    let embedded = embedded.clone();
                    Box::new(async move {
                        let token = get_token_or_trap(&embedded.$store, slot, &key)?;
                        Ok((token,))
                    })
                },
            )?;
            Ok(())
        }
    };
}

embedded_kind! {
    host_trait = crate::enclavid::embedded::disclosure_fields::Host,
    host_method = disclosure_field,
    store = disclosure_fields,
    wit_instance = "enclavid:embedded/disclosure-fields@0.1.0",
    wit_func = "disclosure-field",
    register_fn = register_disclosure_fields_for_slot,
}

embedded_kind! {
    host_trait = crate::enclavid::embedded::i18n::Host,
    host_method = localized,
    store = localized,
    wit_instance = "enclavid:embedded/i18n@0.1.0",
    wit_func = "localized",
    register_fn = register_localized_for_slot,
}

embedded_kind! {
    host_trait = crate::enclavid::embedded::icons::Host,
    host_method = icon,
    store = icons,
    wit_instance = "enclavid:embedded/icons@0.1.0",
    wit_func = "icon",
    register_fn = register_icons_for_slot,
}

/// Wire the three `enclavid:embedded/*` interfaces onto a plugin's
/// Linker. Each register fn captures the slot it's handed into the
/// closure that backs the host import. **The asymmetry between
/// kinds lives here, in the slot we pick per kind:**
///
///   * `disclosure-fields` → `POLICY_SLOT`. DF is the only kind
///     that reaches the consumer envelope, so the policy (slot 0)
///     is the single bandwidth gate — every plugin resolve validates
///     against slot 0's catalog regardless of which plugin made
///     the call. Emitted token is slot-0-flavored.
///   * `i18n` / `icons` → the plugin's own `slot`. These refs are
///     applicant-facing only (i18n resolved to text in TEE before
///     wire, icons dispatched on the applicant frontend), never
///     reach the consumer, so per-component scoping is sufficient.
///
/// Registration happens in `Runner::run` once per plugin Linker,
/// before `compose()`. Plugin Linkers that don't import a given
/// interface are unaffected — wasmtime ignores Linker entries the
/// component never imports.
pub fn register_for_slot(
    linker: &mut wasmtime::component::Linker<PluginHostState>,
    slot: Slot,
    embedded: Arc<EmbeddedRegistry>,
) -> wasmtime::Result<()> {
    register_disclosure_fields_for_slot(linker, POLICY_SLOT, embedded.clone())?;
    register_localized_for_slot(linker, slot, embedded.clone())?;
    register_icons_for_slot(linker, slot, embedded)?;
    Ok(())
}

/// Look up the ref token for `(slot, key)` in `store`, converting
/// an "undeclared" `None` into the canonical wasm trap. `slot` is
/// the effective lookup slot the caller picked (policy slot for
/// policy-gated kinds, the calling component's own slot for
/// per-component kinds) — the trap names it so authors know which
/// component's section the host expected the key in.
fn get_token_or_trap<K: RefKind>(
    store: &RefStore<K>,
    slot: Slot,
    key: &str,
) -> wasmtime::Result<String> {
    store.get_token(slot, key).ok_or_else(|| {
        wasmtime::Error::msg(format!(
            "embedded {kind}: slot {slot} did not declare key '{key}' \
             in its enclavid:embedded.{kind}s.v1 section",
            kind = K::NAME,
        ))
    })
}
