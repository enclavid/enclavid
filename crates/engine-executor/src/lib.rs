//! `engine-executor` — the EXECUTE half of the engine fleet.
//!
//! Deserialize a compiled `cwasm`, instantiate it, and drive ONE
//! pure-reducer round of `enclavid:policy/policy.handle(state, event) ->
//! (state, action)` through the bindgen host world. [`Executor`] owns the
//! runtime wasmtime `Engine`; it runs the UNTRUSTED policy wasm and carries
//! NO Cranelift — codegen lives in `engine-compiler`, and a serialized
//! `cwasm` is the only input crossing in. The engine owns the mailbox
//! (builds the inbound `event` from `/input`), persistence (threads the
//! opaque `state` blob), and effects (renders prompts, seals consented
//! disclosures). No intercept / replay / compaction.
//!
//! ```text
//! runner/      ← Executor + RunStatus; WIT⇄domain conversions +
//!                media/consent validation
//! embedded/    ← `enclavid:embedded/*` ref registry (EmbeddedRegistry) +
//!                the embedded host-fn impls (slot 0 via bindgen) + the ref
//!                resource reps. Section parsing / hashing is in
//!                engine-compiler.
//!   ↓ uses
//! state/       ← Store<T> data layer (HostState, RunInputs)
//! listener     ← outbound contract (SessionListener trait, SessionChange);
//!                fired on a consent-disclosure accept
//! limits, sanitize  ← leaf utilities
//! ```

mod embedded;
pub mod limits;

/// This runtime's cwasm ABI identifier — the `compat_token` the execution-worker
/// hands the orchestrator on an L1-miss `load_component` so the orchestrator keys
/// L2 (and, later, routes compiles) by it. A cwasm is portable only across
/// runtimes sharing `(wasmtime version + engine_config + target)`.
///
/// The wasmtime half is derived AUTOMATICALLY from wasmtime's own major version
/// via [`ModuleVersionStrategy::WasmtimeVersion`](wasmtime::ModuleVersionStrategy) —
/// the SAME string wasmtime embeds in every serialized cwasm and checks on
/// `deserialize`, so it tracks the exact ABI boundary and needs no manual bump.
/// (We can't use `Engine::precompile_compatibility_hash`, which folds in the full
/// `Config` too, because it is `cfg(cranelift)` and this engine is runtime-only.)
/// The `-cm-fuel` suffix marks our fixed `engine_config` (component-model +
/// consume-fuel); bump it by hand only if `engine_config` ever changes without a
/// wasmtime major bump.
pub fn compat_token() -> String {
    format!(
        "wt{}-cm-fuel",
        wasmtime::ModuleVersionStrategy::WasmtimeVersion.as_str()
    )
}
mod listener;
mod media;
mod media_store;
mod runner;
mod sanitize;
mod state;

pub use embedded::{
    ComponentDecls, DisclosureFields, DisclosureFieldsStore, EmbeddedRegistry,
    EmbeddedRegistryBuilder, Icon, IconStore, Localized, LocalizedStore, RefKind, RefStore,
    Translation,
};
pub use broker_client::{
    Action, Decision, Event, MediaResult, Prompt, SessionMetadata, SessionState,
};
pub use listener::{CapturedMedia, ConsentDisclosure, SessionChange, SessionListener};
pub use media_store::MediaStore;
pub use runner::{EmbeddedIface, EmbeddedImport, Executor, PluginInstance, RunStatus};
pub use state::RunInputs;
/// The bindgen-generated `enclavid:host/types.prop` — the consumer's
/// static-config value variant. Re-exported so the api crate can build
/// the `props` list it hands to [`Executor::run`] without taking a direct
/// bindgen dependency.
pub use crate::enclavid::host::types::Prop;
/// Re-exported for the api crate so it can apply the same
/// control/BIDI/zero-width/Unicode-tag stripping to manifest
/// translation values at resolve time (lazy validation strategy —
/// see `runner::load_manifest` docs).
pub use sanitize::sanitize_text_value;
/// Re-exports for API callers so they can implement `SessionListener` and
/// build futures with the right error type without depending on
/// wasmtime directly. `RunError` is `anyhow::Error` under the hood.
pub use wasmtime::{Error as RunError, Result as RunResult};
// Re-exported so callers (api crate) can hold compiled components in
// their session caches without taking a direct wasmtime dependency.
pub use wasmtime::component::Component;

#[cfg(test)]
mod compat_tests {
    /// The token is DERIVED from wasmtime's own major version (not hardcoded), so
    /// a wasmtime bump moves it automatically — proving the derivation without
    /// pinning a version number this test would have to chase.
    #[test]
    fn compat_token_is_derived_from_wasmtime_version() {
        let major = wasmtime::ModuleVersionStrategy::WasmtimeVersion.as_str();
        assert!(!major.is_empty(), "wasmtime major version should be non-empty");
        assert_eq!(super::compat_token(), format!("wt{major}-cm-fuel"));
    }
}

wasmtime::component::bindgen!({
    inline: r#"
        package enclavid:engine@0.1.0;

        world host {
            import enclavid:host/types@0.1.0;
            import enclavid:host/embedded-disclosure-fields@0.1.0;
            import enclavid:host/embedded-i18n@0.1.0;
            import enclavid:host/embedded-icons@0.1.0;
            import enclavid:host/session-context@0.1.0;
            export enclavid:policy/policy@0.1.0;
        }
    "#,
    path: [
        "../../wit/host",
        "../../wit/shared-types",
        "../../wit/policy",
    ],
    imports: { default: async | trappable },
    exports: { default: async },
    // The three embedded refs are host-owned resources; back each with
    // the rep that carries its RESOLVED data (see `embedded::store`), so
    // the action-boundary deref in `runner::convert` is self-contained.
    // `blob` is likewise host-owned — its rep holds one stored blob's
    // bytes + content ref (see `media`); the runtime mints a handle per
    // captured frame into `event::media`'s `clip` record. `clip` itself is a
    // plain policy-side record (no rep).
    with: {
        "enclavid:host/types.localized-ref": crate::embedded::LocalizedRef,
        "enclavid:host/types.icon-ref": crate::embedded::IconRef,
        "enclavid:host/types.disclosure-field-ref": crate::embedded::DisclosureFieldRef,
        "enclavid:host/types.blob": crate::media::BlobRep,
    },
});
