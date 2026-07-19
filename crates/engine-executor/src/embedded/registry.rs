//! `enclavid:embedded/*` ref scoping — re-exported from the pure-data
//! [`engine_types::embedded::registry`] leaf.
//!
//! `ComponentDecls` (a component's parsed catalog) and `EmbeddedRegistry`
//! (the composition-wide, first-match ref→data projection) carry no
//! wasmtime, so they live in `engine-types` where the client-only api
//! orchestrator can project refs into user-facing strings without pulling
//! the runtime. Engine code keeps addressing them as `super::registry::*`;
//! the wasmtime-coupled ref resource reps stay in [`super::store`].

pub use engine_types::embedded::registry::{
    ComponentDecls, DisclosureFieldsStore, EmbeddedRegistry, EmbeddedRegistryBuilder, IconStore,
    LocalizedStore, Translation,
};
