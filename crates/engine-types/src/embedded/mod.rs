//! `enclavid:embedded/*` domain types — the pure-data half of the engine's
//! embedded layer (section declarations + composition-wide ref scoping).
//!
//! ```text
//! registry ← ComponentDecls (per-component parsed catalog) + the
//!            composition-wide EmbeddedRegistry (two per-kind stores).
//! store    ← the generic RefStore<K> backing each kind + the kind
//!            markers (DisclosureFields / Localized).
//! ```
//!
//! The wasmtime-coupled pieces live in `engine-executor`: the bindgen ref
//! resource reps (`LocalizedRef` / `IconRef` / `DisclosureFieldRef`) and
//! the section parsers (`load_embedded`), which import these types. Icons
//! keep no catalog: their names are the host's own ([`crate::icons`]).

pub mod registry;
pub mod store;

pub use registry::{
    ComponentDecls, DisclosureFieldsStore, EmbeddedRegistry, EmbeddedRegistryBuilder,
    LocalizedStore, Translation,
};
pub use store::{DisclosureFields, Localized, RefKind, RefStore};
