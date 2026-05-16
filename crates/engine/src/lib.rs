mod disclosure;
mod host_state;
pub mod limits;
mod listener;
mod media;
mod replay;
pub mod policy;
mod sanitize;
pub mod wasmtime_shim;

pub use enclavid_host_bridge::{suspended, SessionMetadata, SessionState};
pub use listener::{ConsentDisclosure, SessionChange, SessionListener};
pub use policy::{load_manifest, EvalArgs, LocalizedDecl, RunStatus, Runner, TextDecls};
/// Re-exported for the api crate so it can apply the same
/// control/BIDI/zero-width/Unicode-tag stripping to manifest
/// translation values at resolve time (lazy validation strategy —
/// see `policy::load_manifest` docs).
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
        package enclavid:engine;

        world host {
            import enclavid:disclosure/disclosure;
            import enclavid:form/media;
            export enclavid:policy/policy;
        }
    "#,
    path: [
        "../../wit/types",
        "../../wit/policy",
        "../../wit/disclosure",
        "../../wit/form",
    ],
    imports: { default: async | trappable },
    exports: { default: async },
    additional_derives: [
        serde::Serialize,
        serde::Deserialize,
    ],
    wasmtime_crate: crate::wasmtime_shim,
});
