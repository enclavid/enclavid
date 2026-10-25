//! `enclavid:embedded/*` layer — everything related to the embedded
//! sections a wasm component ships inside itself.
//!
//! Section parsing (`load_embedded`) + catalog hashing moved to the
//! `engine-compiler` crate (they run at compile time, alongside fusion);
//! what remains here is the run-time view: the ref registry + the host
//! resolvers that mint ref resources during a round.
//!
//! ```text
//! registry ← composition-wide EmbeddedRegistry with two stores:
//!            disclosure_fields (Store<DisclosureFields>) and
//!            localized (Store<Localized>). Shared by Arc with every
//!            consumer so slot attribution can't drift.
//! host     ← the ref resources' destructors, wired onto `HostState` via
//!            the bindgen `Host` traits. The slots and the policy's typed
//!            disclosure fields are registered in `runner`, since their
//!            types are the components' own.
//! ```
//!
//! Stays out of `runner/` (which is about execution). Embedded is its
//! own self-contained concern — section schema + scoping contract + ref
//! resolution all sit here.

pub(crate) mod host;
pub(crate) mod registry;
pub(crate) mod store;

pub use host::undeclared_trap;
pub use registry::{
    CatalogUnreadable, ComponentDecls, DisclosureFieldsStore, EmbeddedRegistry,
    EmbeddedRegistryBuilder, LocalizedStore, Translation,
};
pub use store::{
    DisclosureFieldRef, DisclosureFields, IconRef, Localized, LocalizedRef, RefKind, RefStore,
};
