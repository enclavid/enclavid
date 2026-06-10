//! Host implementations of `enclavid:embedded/disclosure-fields` and
//! `enclavid:embedded/i18n` — resolution of component-local keys to
//! opaque text-refs.
//!
//! **Current state: stubs.** Both implementations return the key
//! string unchanged, so the existing string-based
//! `registered_text_refs` validation continues to work for components
//! that call `disclosure-fields::disclosure-field("foo")` or
//! `i18n::localized("foo")` and put the result into a host fn. The
//! returned ref == "foo" gets caught by `ensure_registered` if "foo"
//! isn't declared in the relevant embedded section.
//!
//! **Future**: replace with per-component-scoped HMAC of (slot,
//! interface, key) tuple using a session-derived TEE key. Returned
//! refs will be opaque hex strings; validation will use a reverse-
//! index `String -> (slot, interface, key)` instead of a flat string
//! set. Per-component linker dance lives in the runner (each plugin/
//! policy instance gets a closure bound to its own slot index).
//!
//! Keeping these stubs during the migration lets the WIT interface
//! split, engine bindings, and downstream component refactors land in
//! independent commits — no one is forced to migrate to the HMAC path
//! in the same change.

use crate::enclavid::embedded::disclosure_fields::Host as DisclosureFieldsHost;
use crate::enclavid::embedded::i18n::Host as I18nHost;
use crate::state::HostState;

impl DisclosureFieldsHost for HostState {
    /// Stub: return key unchanged. Caller's downstream host fn
    /// (e.g., `prompt_disclosure`) runs `ensure_registered` on the
    /// returned string, which catches unregistered keys.
    async fn disclosure_field(&mut self, key: String) -> wasmtime::Result<String> {
        Ok(key)
    }
}

impl I18nHost for HostState {
    /// Stub: return key unchanged. Same rationale as
    /// `disclosure-fields::disclosure-field`.
    async fn localized(&mut self, key: String) -> wasmtime::Result<String> {
        Ok(key)
    }
}
