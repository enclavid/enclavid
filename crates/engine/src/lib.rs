mod biometrics;
mod disclosure;
mod documents;
mod form_group;
mod host_state;
mod listener;
mod replay;
pub mod policy;
mod sanitize;
pub mod wasmtime_shim;

pub use enclavid_host_bridge::{suspended, SessionMetadata, SessionState};
pub use listener::{SessionChange, SessionListener};
pub use policy::{EvalArgs, RunStatus, Runner};
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
            import enclavid:form/documents;
            import enclavid:form/biometrics;
            import enclavid:form/form-group;
            export enclavid:policy/policy;
        }
    "#,
    path: [
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
    wasmtime_crate: crate::wasmtime_shim,
});
