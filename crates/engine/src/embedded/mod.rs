//! `enclavid:embedded/*` layer — everything related to the embedded
//! sections a wasm component ships inside itself.
//!
//! ```text
//! decls    ← walks a component's wasm custom sections + projects into
//!            ComponentDecls (disclosure-field keys + i18n translations).
//!            Author-time on disk, load-time inside the engine.
//! registry ← composition-wide EmbeddedRegistry with two stores:
//!            disclosure_fields (Store<DisclosureFields>) and
//!            localized (Store<Localized>). Shared by Arc with every
//!            consumer so slot attribution can't drift.
//! host     ← `enclavid:embedded/disclosure-fields` and `enclavid:
//!            embedded/i18n` host-fn impls. Policy slot (0) lives on
//!            the `Host` trait; plugin slots are registered on each
//!            plugin's Linker via `register_for_slot`.
//! ```
//!
//! Stays out of `runner/` (which is about execution). Embedded is its
//! own self-contained concern — section schema + scoping contract + ref
//! resolution all sit here.

pub(crate) mod decls;
pub(crate) mod host;
pub(crate) mod registry;
pub(crate) mod store;

pub use decls::load_embedded;
pub use host::register_for_slot;
pub use registry::{
    ComponentDecls, DisclosureFieldsStore, EmbeddedRegistry, EmbeddedRegistryBuilder,
    IconStore, LocalizedStore, Slot, Translation,
};
pub use store::{DisclosureFields, Icon, Localized, RefKind, RefStore};
