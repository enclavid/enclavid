//! Output of one [`Runner::run`](super::Runner::run) call, plus the
//! typed payloads bindgen produces for the policy's `evaluate` export.

use enclavid_host_bridge::suspended;

// Re-exported so the api crate can construct `EvalArgs` and read
// `Decision` without taking a direct bindgen dependency.
pub use crate::exports::enclavid::policy::policy::{Decision, EvalArgs};

/// Status of a policy session run.
pub enum RunStatus {
    /// Policy completed with a decision.
    Completed(Decision),
    /// Policy suspended, awaiting user input for the carried request.
    Suspended(suspended::Request),
}
