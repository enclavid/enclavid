mod biometrics;
mod disclosure;
mod documents;
mod form_group;
mod host_state;
mod replay;
pub mod policy;
mod sanitize;
pub mod wasmtime_shim;

pub use enclavid_session_store::{suspended, SessionMetadata, SessionState};
pub use policy::{EvalArgs, RunStatus, Runner};
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
