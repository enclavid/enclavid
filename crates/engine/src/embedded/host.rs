//! Host implementations of `enclavid:embedded/disclosure-fields`,
//! `enclavid:embedded/i18n`, and `enclavid:embedded/icons`.
//!
//! bindgen wires each interface's `Host` trait onto [`HostState`] via
//! `add_to_linker`. Under wac single-store fusion the per-component
//! `enclavid:embedded/*` imports unify into one host impl each, so a
//! single call site serves the policy AND every fused plugin — the
//! host can't attribute a call to a specific component. All three
//! kinds therefore resolve the bare key by **first match across every
//! merged catalog** ([`resolve`]), composition order (policy slot 0
//! first). A call traps if no catalog declared the key — the registry
//! is the single source of truth.
//!
//! Scoping is by **catalog membership + the keyed-hash token**
//! ([`super::store`]), not by which slot the caller sits in: a
//! component cannot fabricate a ref for a key nobody declared, and the
//! token round-trips through the reverse index regardless of which
//! catalog first satisfied the lookup. Disclosure-fields are the one
//! kind that reaches the consumer, but that concern is handled where
//! it belongs — the policy chooses which `display-field`s enter a
//! `render(consent-disclosure)`, and the applicant consents to every
//! `(key, label, value)` on screen (the sole auditor). It is NOT a
//! resolution-time gate here, so a plugin's DF helper resolves the
//! same way its i18n label does.
//!
//! ## Per-kind boilerplate is collapsed into a macro
//!
//! Each `enclavid:embedded/*` interface needs one bindgen-driven
//! `Host` trait impl whose body just calls [`resolve`].
//! [`embedded_kind!`] emits that impl per kind, taking the protocol
//! artifacts (Host trait path, method name, store field) as macro
//! args, keeping the data-side [`RefKind`] free of protocol artifacts.

use super::store::{RefKind, RefStore};
use crate::state::HostState;

/// Emit the bindgen `Host` trait impl for one `enclavid:embedded/*`
/// interface, backing it with [`resolve`].
///
/// Args:
///
///   * `host_trait` — bindgen-generated `Host` trait path to impl
///     on [`HostState`].
///   * `host_method` — `Host`-trait method name (matches the WIT
///     interface's function name in snake_case).
///   * `store` — `EmbeddedRegistry` field carrying this kind's
///     [`RefStore`]. Type inference picks the right `RefKind` from
///     the field type so the resolver's `K::NAME` resolves correctly.
macro_rules! embedded_kind {
    (
        host_trait = $host_trait:path,
        host_method = $host_method:ident,
        store = $store:ident $(,)?
    ) => {
        impl $host_trait for HostState {
            async fn $host_method(&mut self, key: String) -> wasmtime::Result<String> {
                resolve(&self.embedded.$store, &key)
            }
        }
    };
}

embedded_kind! {
    host_trait = crate::enclavid::embedded::disclosure_fields::Host,
    host_method = disclosure_field,
    store = disclosure_fields,
}

embedded_kind! {
    host_trait = crate::enclavid::embedded::i18n::Host,
    host_method = localized,
    store = localized,
}

embedded_kind! {
    host_trait = crate::enclavid::embedded::icons::Host,
    host_method = icon,
    store = icons,
}

/// Resolve `key` to its ref token across every merged catalog, first
/// match wins (composition order, policy first). Traps if no catalog
/// declared it. The MERGED path — DF always, and i18n / icons for a
/// lone unfused policy (served under their canonical import names).
fn resolve<K: RefKind>(store: &RefStore<K>, key: &str) -> wasmtime::Result<String> {
    store
        .get_token_first_match(key)
        .ok_or_else(|| undeclared_trap::<K>(key))
}

/// Resolve `key` to its ref token against ONE specific catalog (by
/// content-hash). The STRICT path — the i18n / icons instances the
/// fusion routed per component, so a plugin's key resolves only against
/// its own catalog. Traps if that catalog didn't declare `key`.
pub fn strict_token<K: RefKind>(
    store: &RefStore<K>,
    catalog_hash: &[u8; 32],
    key: &str,
) -> wasmtime::Result<String> {
    store
        .get_token(catalog_hash, key)
        .ok_or_else(|| undeclared_trap::<K>(key))
}

/// Canonical trap for a key no catalog (merged) or the bound catalog
/// (strict) declared under this kind.
fn undeclared_trap<K: RefKind>(key: &str) -> wasmtime::Error {
    wasmtime::Error::msg(format!(
        "embedded {kind}: no component declared key '{key}' \
         in its enclavid:embedded.{kind}s.v1 section",
        kind = K::NAME,
    ))
}
