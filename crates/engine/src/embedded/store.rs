//! Embedded ref stores + their WIT resource reps.
//!
//! The generic `key → data` backing ([`RefStore`], the kind markers
//! [`DisclosureFields`] / [`Localized`] / [`Icon`], and [`RefKind`]) is
//! pure data and lives in the [`engine_types::embedded::store`] leaf,
//! re-exported here so engine code keeps addressing it as
//! `super::store::*`.
//!
//! ## Refs are resources, not tokens
//!
//! A component never sees a ref VALUE — `localized`/`icon`/
//! `disclosure-field` return an opaque WIT `resource` handle it cannot
//! forge (wasmtime owns the handle table). The host mints a resource
//! whose rep IS the resolved data — [`LocalizedRef`] / [`IconRef`] /
//! [`DisclosureFieldRef`], defined below. These reps are the one
//! wasmtime-coupled piece (bindgen's `with:` maps each WIT resource to
//! the matching type here), so they stay in `enclavid-engine`; the engine
//! dereferences a rep at the action boundary (`runner::convert`), so the
//! resolved data is self-contained (no registry needed to render it
//! later).

use engine_types::embedded::registry::Translation;

pub use engine_types::embedded::store::{
    DisclosureFields, Icon, Localized, RefKind, RefStore,
};

// ---------------------------------------------------------------------
// Resource reps — the host-owned backing of each WIT ref resource. Carry
// the RESOLVED data (mint-time resolution) so the engine's boundary
// deref is self-contained. `bindgen!`'s `with` maps each WIT resource to
// the matching type here.
// ---------------------------------------------------------------------

/// Backing rep of `enclavid:host/types.localized-ref` — the full
/// translation set the applicant-locale text is later picked from.
pub struct LocalizedRef(pub Vec<Translation>);
/// Backing rep of `enclavid:host/types.icon-ref` — the resolved icon
/// name the applicant frontend dispatches.
pub struct IconRef(pub String);
/// Backing rep of `enclavid:host/types.disclosure-field-ref` — the
/// resolved machine `display-field.key` the consumer receives.
pub struct DisclosureFieldRef(pub String);
