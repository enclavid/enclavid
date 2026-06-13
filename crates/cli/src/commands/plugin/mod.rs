//! `enclavid plugin ...` — OCI artifact operations on plugin
//! components. Symmetric with `enclavid policy ...` minus the parts
//! that don't apply to plugins:
//!
//!   * Plugins don't ship `disclosure-fields.json` — the policy is
//!     the single bandwidth gate for disclosure-field refs (Option C,
//!     see `[[project-df-policy-gated]]`). `plugin embed` accepts
//!     only `--i18n` and `--icons`.
//!   * Plugin encryption (Phase 6) is code-section-only with a
//!     KBS-released key, not the whole-component age envelope used
//!     for policies. `plugin encrypt` is not yet implemented.

pub mod embed;
