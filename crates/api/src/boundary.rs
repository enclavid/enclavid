//! api's ends of its legs, declared.
//!
//! One declaration per end, written by api about how it judges what crosses that
//! end: a scope is a property of the channel and of the side holding it, so api
//! names its own, and the role across the leg names its.

use enclavid_boundary::{Asserted, AuthN, AuthZ, Covert};
use enclavid_boundary_macros::boundary;
use engine_rpc::{
    BundleStream, CallbackError, Committed, ExecError, MediaBytes, MediaHash, Padded,
    PrepareOutcome, PrepareReply, PrepareRequest, RunOutcome, RunReply, RunRequest,
};
use session_types::{Decision, SessionState};

boundary! {
    /// The execution-worker: the process that runs the consumer's policy, over one
    /// RA-TLS leg api pins and the host splices.
    ///
    /// Nothing it sends is forged — api pinned it — and nothing it sends is a
    /// function of anything api or the applicant established, because it is the
    /// output of adversary-supplied code. That is `Asserted`, and the only concern
    /// this end opens on what arrives.
    pub(crate) ExecutionWorker {
        calls: [engine_rpc::RemoteExecutor],
        serves: [engine_rpc::RemoteCallbacks],
        observer: HostSplices,
    }

    out (AuthN, AuthZ, Covert) {
        /// This leg dials ONE compile-time-pinned measurement, the handshake fails
        /// before a byte moves if the peer is not it, and the peer keeps what it is
        /// handed in its own memory.
        _: AuthN::Identified,
        RunRequest,
        /// The session's own props, key and terms, released to the image this leg
        /// pins, which is the party that runs the session's composition.
        PrepareRequest: AuthZ::Matched,
        /// The consumer's own props, whose length the host saw when the session was
        /// created, beside a key of fixed length and the ceiling the operator's
        /// limits gave; nothing of an applicant's is in any.
        PrepareRequest: Covert::AlreadyHeld,
        /// The code of the composition this session runs — decrypted, where its
        /// artifacts were encrypted — released to the image this leg pins, which is
        /// the party that runs it.
        BundleStream: AuthZ::Matched,
        /// Its lengths are the composition's, fixed when it was compiled and never a
        /// function of applicant data; "this composition was cold" is already legible
        /// on this hop.
        BundleStream: Covert::AlreadyHeld,
        Option<MediaBytes>,
        /// The callback server is stood up for this one round, so the only write this
        /// reply speaks about is the session the peer is running.
        Committed: AuthZ::Scoped,
        /// One bit: whether the write landed — this, or a `CallbackError`.
        Committed: Covert::Bounded,
        /// The callback server is stood up for this one round, so a failure speaks
        /// only about the session the peer is running.
        CallbackError: AuthZ::Scoped,
        /// One fixed value, carrying no detail.
        CallbackError: Covert::Bounded,
    }

    in (Asserted,) {
        /// A miss names only a slot inside the composition namespace api itself
        /// computed, so a fabricated token costs a recompile and never yields another
        /// composition's code; a hit carries a prompt shown to the applicant, its
        /// sole auditor, or a decision api only compares with the one the round
        /// committed. The round's disclosure comes from api's own copy, never this.
        RunOutcome: Asserted::Contained,
        /// A prompt is shown to the applicant, its sole auditor, and a decision api
        /// only compares with the one the round committed.
        RunReply: Asserted::Contained,
        PrepareOutcome,
        PrepareReply,
        /// One of three fixed values: the policy failed, something else did, or there
        /// was no room.
        ExecError: Asserted::Bounded,
        MediaHash,
        /// Sealed verbatim and handed back only to the peer that authored it. Its
        /// `current_prompt` is shown to the applicant, its sole auditor — when a
        /// round's reply is lost, and on the next round — and what of it reaches the
        /// consumer, the policy's author, reaches it only on the applicant's accept.
        Padded<SessionState>: Asserted::Contained,
        /// The verdict is the policy's to choose by design, one of four fixed values:
        /// the worker's word is all it ever was.
        Padded<Option<Decision>>: Asserted::Contained,
    }
}

#[cfg(test)]
mod tests {
    use enclavid_boundary::declaration::Direction;

    use super::ExecutionWorker;

    /// Everything the execution-worker sends is the output of the consumer's
    /// code, so nothing arrives without `Asserted` open on it.
    #[test]
    fn nothing_arrives_without_its_provenance_asked() {
        for crossing in ExecutionWorker::DECLARATION.crossings {
            if crossing.direction == Direction::In {
                assert!(crossing.opens.contains(&"Asserted"), "{}", crossing.ty);
            }
        }
    }

    /// The one answer given for every type is about the channel — the pin — and
    /// every other answer is about the value it is given on.
    #[test]
    fn only_the_pin_is_answered_for_every_type() {
        for crossing in ExecutionWorker::DECLARATION.crossings {
            for answer in crossing.answers.iter().filter(|a| a.every_type) {
                assert_eq!(
                    (answer.marker, answer.kind),
                    ("AuthN", "Identified"),
                    "{}",
                    crossing.ty
                );
            }
        }
    }
}
