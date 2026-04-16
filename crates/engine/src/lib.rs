mod disclosure;
mod form;
mod runner;
mod suspend;

pub use enclavid_session_store::{SessionMetadata, SessionState};
pub use runner::{RunOutcome, Runner};
pub use suspend::{MediaRequest, Suspend};

wasmtime::component::bindgen!({
    inline: r#"
        package enclavid:engine;

        world host {
            import enclavid:disclosure/disclosure;
            import enclavid:form/form;
        }
    "#,
    path: [
        "../../wit/disclosure",
        "../../wit/form",
        "../../wit/policy",
    ],
    imports: {
        "enclavid:form/form": trappable,
        "enclavid:disclosure/disclosure": trappable,
    },
});
