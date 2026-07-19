//! `enclavid:embedded/*` domain types — the pure-data half of the engine's
//! embedded layer (section declarations + composition-wide ref scoping).
//!
//! ```text
//! registry ← ComponentDecls (per-component parsed catalog) + the
//!            composition-wide EmbeddedRegistry (three per-kind stores).
//! store    ← the generic RefStore<K> backing each kind + the kind
//!            markers (DisclosureFields / Localized / Icon).
//! ```
//!
//! The wasmtime-coupled pieces live in `enclavid-engine`: the bindgen ref
//! resource reps (`LocalizedRef` / `IconRef` / `DisclosureFieldRef`) and
//! the section parsers (`load_embedded`), which import these types.

pub mod registry;
pub mod store;

pub use registry::{
    ComponentDecls, DisclosureFieldsStore, EmbeddedRegistry, EmbeddedRegistryBuilder, IconStore,
    LocalizedStore, Translation,
};
pub use store::{DisclosureFields, Icon, Localized, RefKind, RefStore};
