//! Engine: policy + plugin composition + execution.
//!
//! The policy is a PURE REDUCER. `enclavid:policy/policy.handle
//! (state, event) -> (state, action)` is called ONCE per round; the engine
//! owns the mailbox (builds the inbound `event` from `/input`), persistence
//! (threads the opaque `state` blob), and effects (renders prompts, seals
//! consented disclosures). No intercept / replay / compaction.
//!
//! ```text
//! runner/      ← top-level executor (Runner, RunStatus); WIT⇄domain
//!                conversions + media/consent validation live here now
//! embedded/    ← `enclavid:embedded/*` slice: section parsing
//!                (load_embedded), per-component scoping registry
//!                (EmbeddedRegistry), and the embedded host fn impls
//!                (slot 0 via bindgen)
//!   ↓ uses
//! state/       ← Store<T> data layer (HostState, RunInputs)
//! listener     ← outbound contract (SessionListener trait, SessionChange);
//!                fired by the runner on a consent-disclosure accept
//! limits, sanitize  ← leaf utilities
//! ```

mod embedded;
pub mod limits;
mod listener;
mod runner;
mod sanitize;
mod state;

pub use embedded::{
    ComponentDecls, DisclosureFields, DisclosureFieldsStore, EmbeddedCatalog, EmbeddedRegistry,
    EmbeddedRegistryBuilder, Icon, IconStore, Localized, LocalizedStore, RefKind, RefStore,
    Translation, catalog_hash, load_embedded, load_embedded_nested, slug, top_level_imports,
};
pub use broker_client::{
    Action, Decision, Event, MediaResult, Prompt, SessionMetadata, SessionState,
};
pub use listener::{ConsentDisclosure, SessionChange, SessionListener};
pub use runner::{
    Composition, EmbeddedIface, EmbeddedImport, PluginInstance, RunStatus, Runner,
};
pub use state::RunInputs;
/// The bindgen-generated `enclavid:host/types.prop` — the consumer's
/// static-config value variant. Re-exported so the api crate can build
/// the `props` list it hands to [`Runner::run`] without taking a direct
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

wasmtime::component::bindgen!({
    inline: r#"
        package enclavid:engine@0.1.0;

        world host {
            import enclavid:embedded/disclosure-fields@0.1.0;
            import enclavid:embedded/i18n@0.1.0;
            import enclavid:embedded/icons@0.1.0;
            import enclavid:host/session-context@0.1.0;
            export enclavid:policy/policy@0.1.0;
        }
    "#,
    path: [
        "../../wit/embedded",
        "../../wit/shared-types",
        "../../wit/policy",
        "../../wit/host",
    ],
    imports: { default: async | trappable },
    exports: { default: async },
    additional_derives: [
        serde::Serialize,
        serde::Deserialize,
    ],
});
