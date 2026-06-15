//! Engine: policy + plugin composition + execution.
//!
//! ```text
//! runner/      ← top-level executor (Runner, RunStatus)
//!   ↓ uses
//! host/        ← bindgen Host trait impls for suspending host fns
//!                (prompt-disclosure, prompt-media)
//! embedded/    ← `enclavid:embedded/*` slice: section parsing
//!                (TextDecls + load_embedded), per-component scoping
//!                registry (EmbeddedRegistry), and the embedded host
//!                fn impls (slot 0 via bindgen, plugin slots via
//!                register_for_slot)
//!   ↓ uses
//! state/       ← Store<T> data layer (HostState, PluginHostState, RunInputs)
//! intercept/   ← shim Linker + replay machinery (wraps every host call)
//! listener     ← outbound contract (SessionListener trait, SessionChange)
//! limits, sanitize  ← leaf utilities
//! ```

mod embedded;
mod host;
pub mod intercept;
pub mod limits;
mod listener;
mod runner;
mod sanitize;
mod state;

pub use embedded::{
    ComponentDecls, DisclosureFields, DisclosureFieldsStore, EmbeddedRegistry,
    EmbeddedRegistryBuilder, Icon, IconStore, Localized, LocalizedStore, RefKind, RefStore,
    Slot, Translation, load_embedded,
};
pub use broker_client::{SessionMetadata, SessionState, suspended};
pub use listener::{ConsentDisclosure, SessionChange, SessionListener};
pub use runner::{Decision, EvalArgs, PluginInstance, RunStatus, Runner};
pub use state::RunInputs;
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

wasmtime::component::bindgen!({
    inline: r#"
        package enclavid:engine@0.1.0;

        world host {
            import enclavid:embedded/disclosure-fields@0.1.0;
            import enclavid:embedded/i18n@0.1.0;
            import enclavid:embedded/icons@0.1.0;
            import enclavid:disclosure/disclosure@0.1.0;
            import enclavid:form/media@0.1.0;
            export enclavid:policy/policy@0.1.0;
        }
    "#,
    path: [
        "../../wit/embedded",
        "../../wit/disclosure",
        "../../wit/form",
        "../../wit/policy",
    ],
    imports: { default: async | trappable },
    exports: { default: async },
    additional_derives: [
        serde::Serialize,
        serde::Deserialize,
    ],
    wasmtime_crate: crate::intercept::shim,
});
