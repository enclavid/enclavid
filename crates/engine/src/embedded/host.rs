//! Host implementations of `enclavid:embedded/disclosure-fields` and
//! `enclavid:embedded/i18n`.
//!
//! Two registration paths exist, both ending in a `Store::get_token`
//! call on the embedded-registry store matching the called interface,
//! with the calling component's slot captured up-front:
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

use std::sync::Arc;

use super::registry::{EmbeddedRegistry, Slot};
use crate::enclavid::embedded::disclosure_fields::Host as DisclosureFieldsHost;
use crate::enclavid::embedded::i18n::Host as I18nHost;
use crate::state::{HostState, PluginHostState};

/// Slot reserved for the policy across the engine. Plugins occupy
/// slots 1..N in `PluginInstance` list order, registered manually
/// via [`register_for_slot`].
const POLICY_SLOT: Slot = 0;

impl DisclosureFieldsHost for HostState {
    async fn disclosure_field(&mut self, key: String) -> wasmtime::Result<String> {
        self.embedded
            .disclosure_fields
            .get_token(POLICY_SLOT, &key)
            .ok_or_else(|| undeclared_trap("disclosure-field", POLICY_SLOT, &key))
    }
}

impl I18nHost for HostState {
    async fn localized(&mut self, key: String) -> wasmtime::Result<String> {
        self.embedded
            .localized
            .get_token(POLICY_SLOT, &key)
            .ok_or_else(|| undeclared_trap("localized", POLICY_SLOT, &key))
    }
}

/// Build the wasm trap surfaced when [`DisclosureFieldsStore::
/// get_token`](super::registry::DisclosureFieldsStore::get_token) or
/// [`LocalizedStore::get_token`](super::registry::LocalizedStore::
/// get_token) returns `None`. Shared by both Host impls and the
/// plugin-side `register_for_slot` closures so trap wording stays
/// consistent across slot 0 and slots ≥ 1. `kind` matches the
/// `enclavid:embedded/*` interface name a misuse came from.
fn undeclared_trap(kind: &str, slot: Slot, key: &str) -> wasmtime::Error {
    wasmtime::Error::msg(format!(
        "embedded {kind}: cannot issue token for slot {slot} key '{key}' \
         (component did not declare it in its enclavid:embedded.{kind}s section)",
    ))
}

/// Register `enclavid:embedded/disclosure-fields` and `enclavid:
/// embedded/i18n` on a plugin's Linker with the plugin's slot index
/// captured in the closure environment.
///
/// The plugin can pass any string as `key`, but only keys it
/// declared in its own embedded sections (loaded at session start
/// into the registry's two stores) round-trip; everything else
/// traps inside `get_token`. This is the per-component scoping
/// mechanism — the plugin cannot obtain a token for a foreign
/// slot's key because `slot` is baked into the closure, not passed
/// by the guest.
///
/// Registration happens in `Runner::run` once per plugin Linker,
/// before `compose()`. Plugin Linkers that don't import these
/// interfaces are unaffected — wasmtime ignores Linker entries the
/// component never imports.
pub fn register_for_slot(
    linker: &mut wasmtime::component::Linker<PluginHostState>,
    slot: Slot,
    embedded: Arc<EmbeddedRegistry>,
) -> wasmtime::Result<()> {
    let registry_for_df = embedded.clone();
    linker
        .root()
        .instance("enclavid:embedded/disclosure-fields@0.1.0")?
        .func_wrap_async(
            "disclosure-field",
            move |_store, (key,): (String,)| {
                let registry = registry_for_df.clone();
                Box::new(async move {
                    let token = registry
                        .disclosure_fields
                        .get_token(slot, &key)
                        .ok_or_else(|| undeclared_trap("disclosure-field", slot, &key))?;
                    Ok((token,))
                })
            },
        )?;

    linker
        .root()
        .instance("enclavid:embedded/i18n@0.1.0")?
        .func_wrap_async(
            "localized",
            move |_store, (key,): (String,)| {
                let registry = embedded.clone();
                Box::new(async move {
                    let token = registry
                        .localized
                        .get_token(slot, &key)
                        .ok_or_else(|| undeclared_trap("localized", slot, &key))?;
                    Ok((token,))
                })
            },
        )?;

    Ok(())
}
