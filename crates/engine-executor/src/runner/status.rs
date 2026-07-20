//! Output of one [`Runner::run`](super::Runner::run) call.

use hatch_client::{Decision, Prompt};

/// Status of a policy round.
pub enum RunStatus {
    /// The policy rendered a prompt and is awaiting the matching
    /// applicant input. The carried [`Prompt`] is also persisted as
    /// [`SessionState::current_prompt`](hatch_client::SessionState) so the
    /// next round can build the inbound event and gate the consent seal.
    AwaitingInput(Prompt),
    /// The policy finished with a terminal decision.
    Completed(Decision),
}
