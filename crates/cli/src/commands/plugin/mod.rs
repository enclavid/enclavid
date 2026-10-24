//! `enclavid plugin ...` — **authoring** of plugin artifacts: embed +
//! validate. Symmetric with `enclavid policy ...` minus the parts that
//! don't apply to plugins:
//!
//!   * Plugins declare no disclosure fields — their helpers name fields
//!     of the policy's list. `plugin embed` / `validate` handle only
//!     the texts.
//!   * `embed` asserts the component is NOT a policy (does not export
//!     `enclavid:policy/policy`); a policy handed here is rejected with
//!     a pointer to `enclavid policy embed`.
//!
//! Registry push is role-agnostic — see `enclavid oci push`.

pub mod embed;
pub mod validate;
