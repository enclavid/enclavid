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
