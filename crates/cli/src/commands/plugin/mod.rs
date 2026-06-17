//! `enclavid plugin ...` — **authoring** of plugin artifacts: embed +
//! validate. Symmetric with `enclavid policy ...` minus the parts that
//! don't apply to plugins:
//!
//!   * Plugins don't ship `disclosure-fields.json` — the policy is
//!     the single bandwidth gate for disclosure-field refs (Option C,
//!     see `[[project-df-policy-gated]]`). `plugin embed` / `validate`
//!     handle only `--i18n` and `--icons`.
//!   * `embed` asserts the component is NOT a policy (does not export
//!     `enclavid:policy/policy`); a policy handed here is rejected with
//!     a pointer to `enclavid policy embed`.
//!
//! Registry push is role-agnostic — see `enclavid oci push`.

pub mod embed;
pub mod validate;
