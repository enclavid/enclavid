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
//!            embedded/i18n` host-fn impls, wired onto the policy's
//!            `HostState` (slot 0) via the bindgen `Host` trait.
//! ```
//!
//! Stays out of `runner/` (which is about execution). Embedded is its
//! own self-contained concern — section schema + scoping contract + ref
//! resolution all sit here.

pub(crate) mod decls;
pub(crate) mod hash;
pub(crate) mod host;
pub(crate) mod registry;
pub(crate) mod store;

pub use decls::{EmbeddedCatalog, load_embedded, load_embedded_nested, top_level_imports};
pub use hash::{catalog_hash, embedded_import_name, slug};
pub use host::undeclared_trap;
pub use registry::{
    ComponentDecls, DisclosureFieldsStore, EmbeddedRegistry, EmbeddedRegistryBuilder,
    IconStore, LocalizedStore, Translation,
};
pub use store::{
    DisclosureFieldRef, DisclosureFields, Icon, IconRef, Localized, LocalizedRef, RefKind,
    RefStore,
};
