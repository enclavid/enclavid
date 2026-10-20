//! The icons the applicant frontend draws: the functions of
//! `enclavid:host-icons/icons`, one per icon, each minting that icon's
//! `icon-ref`.
//!
//! The set only grows, a new icon being a function added in a compatible
//! version, so the host serves the latest [`INTERFACE`] and an import of any
//! earlier version on its track takes the functions it names from it. The
//! compile admits an import whose functions are all icons of [`NAMES`].

/// The interface at the version the host serves.
pub const INTERFACE: &str = "enclavid:host-icons/icons@0.1.0";

/// Every icon — the functions of `wit/host-icons/icons.wit`.
pub const NAMES: [&str; 4] = ["passport", "id-card", "drivers-license", "selfie"];
