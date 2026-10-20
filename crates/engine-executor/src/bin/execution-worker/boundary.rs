//! This role's end of the api leg, declared.
//!
//! The listener accepts any attested guest — it cannot pin api, whose
//! measurement is a function of this one's — so a completed handshake proves a
//! genuine SNP guest on this part and NOT that it is api. That is why `AuthN` is
//! open on what arrives here, in a way it never is on api's side of the same
//! wire: "RA-TLS against a pinned measurement" is true over there and false here.
//!
//! What answers the missing pin is a property of this role's POSITION rather
//! than of the bytes: the caller's own L1 partition. A slot is named from the
//! measurement the caller's handshake proved (`Caller::slot`), so a caller
//! reaches its own entries and nothing else, the work runs in a disposable child,
//! and the answer goes back only to whoever asked. That is what the INDIFFERENT
//! answers below rest on — not "nothing outlives the call", which is the
//! compile-worker's sentence and is false here: `run_with_bundle` files an entry
//! under the key the request named, and it is served to later calls for as long
//! as it is kept.
//!
//! The decoder bounds are the PREMISE of that, not the answer — "the whole range
//! is safe to act on" is only a sentence if the range is bounded:
//!
//!   * `composition_key` — `CompositionKey`'s decoder: 64 lowercase hex, so it is
//!     a digest rendering and nothing else.
//!   * `session_state`, `props` — `Padded`'s exact-frame decode; the props also
//!     the byte bound where the frame opens.
//!   * `event` — the frame count and clip budget in `Clip`'s decoder.
//!   * `max_cwasm_bytes` — any number: it only decides whether the caller's own
//!     entry is a hit or a miss, and refuses a bundle of more.
//!
//! None of that is a check on AUTHENTICITY and none of it is claimed as one. The
//! thing that would make authenticity checkable is a pin this leaf cannot have.
//!
//! On the way out there is no `AuthN`, and that is not a gap. What it asks of a
//! release — can anyone but the intended party read this? — has an answer in the
//! channel only where the channel names the party, and this one names none: the
//! host that splices it reads ciphertext, but a guest of the host's own that dials
//! in reads what it is sent. Nor is the recipient this role's to choose: it only
//! ever answers the call that asked, and calls back only the client that call
//! handed over.
//!
//! So the whole question is `AuthZ`'s — whether everything a value carries is the
//! asker's own — and the partition is what answers it: every input to a release
//! came from that same caller, the round's arguments it just sent and the
//! compiled code it cached itself. It is answered per type, never for the whole
//! block, because it is a fact about what each value is computed from, and a type
//! added later has to say what it is computed from before it can leave. If this
//! role ever returns something derived from ANOTHER caller's input, that answer
//! becomes false and the release becomes a leak.

use enclavid_boundary::{AuthN, AuthZ, Covert};
use enclavid_boundary_macros::boundary;
use engine_executor::{Decision, SessionState};
use engine_rpc::{
    BundleStream, CallbackError, Committed, ExecError, MediaBytes, MediaHash, Padded,
    PrepareOutcome, PrepareReply, PrepareRequest, RunOutcome, RunReply, RunRequest,
};

boundary! {
    /// Whoever called: a genuine SNP guest on this part, not identifiably api.
    pub(crate) AnyCaller {
        calls: [engine_rpc::RemoteCallbacks],
        serves: [engine_rpc::RemoteExecutor],
        observer: HostSplices,
    }

    in (AuthN,) {
        /// Nothing derived from a round leaves the caller's own partition, and every
        /// field was bounded by its own decoder.
        RunRequest: AuthN::Indifferent,
        /// Nothing derived from a preparation leaves the caller's own partition; the
        /// key and the props were bounded by their own decoders.
        PrepareRequest: AuthN::Indifferent,
        BundleStream,
        /// Whatever blob the caller hands back, it reaches only the round of its own
        /// that asked for it.
        Option<MediaBytes>: AuthN::Indifferent,
        /// One value, about the caller's own round's write.
        Committed: AuthN::Indifferent,
        /// One fixed value; it ends only the caller's own round.
        CallbackError: AuthN::Indifferent,
    }

    out (AuthZ, Covert) {
        /// A round's status from the caller's own slot and the request it just sent.
        /// A miss carries this build's ABI id, a constant of the image and no
        /// function of the request, and says that the slot is not held — with one
        /// budget for every caller, possibly another's doing: load, which the host
        /// sees anyway on every connection it splices.
        RunOutcome: AuthZ::NoSecret,
        /// A round's status, run over the caller's own slot: the bundle it just
        /// streamed, or the entry an earlier call of its own filled, when one did.
        RunReply: AuthZ::NoSecret,
        /// The props the caller sent, read in its own slot; a miss as a round's.
        PrepareOutcome: AuthZ::NoSecret,
        /// The props the caller sent, read over its own slot's entry, as a round's
        /// reply is.
        PrepareReply: AuthZ::NoSecret,
        /// `Policy` and `Unknown` speak of the caller's own round. `Busy` is this
        /// worker's load, other callers' rounds included — which the host sees
        /// anyway on every connection it splices.
        ExecError: AuthZ::NoSecret,
        /// Three fixed values and no detail.
        ExecError: Covert::Bounded,
        /// A hash the caller's own round named, going back to that caller.
        MediaHash: AuthZ::NoSecret,
        /// Every hash is one byte string of 32 bytes, so its length takes one value
        /// whichever the policy named; how many cross, the child's per-round memo
        /// bounds to one per blob.
        MediaHash: Covert::Bounded,
        /// The round's new state, computed from what the caller sent over code it
        /// cached itself; what this side adds is the round's fresh randomness and the
        /// clock, which tell of no one.
        Padded<SessionState>: AuthZ::NoSecret,
        /// The decision the caller's own round made.
        Padded<Option<Decision>>: AuthZ::NoSecret,
    }
}

#[cfg(test)]
mod tests {
    use enclavid_boundary::declaration::Direction;

    use super::AnyCaller;

    /// What leaves is answered for `AuthZ` type by type, never for the whole
    /// block: what a value is computed from is a fact about that value, so a
    /// type added later cannot leave without saying it.
    #[test]
    fn every_release_says_what_it_is_computed_from() {
        for crossing in AnyCaller::DECLARATION.crossings {
            for answer in crossing.answers {
                assert!(
                    !answer.every_type,
                    "{} is answered for every type in its block",
                    answer.marker
                );
            }
            if crossing.direction == Direction::Out {
                assert!(
                    crossing.answers.iter().any(|a| a.marker == "AuthZ"),
                    "{} leaves with no AuthZ answer",
                    crossing.ty
                );
            }
        }
    }

    /// This end names no peer, so nothing about the channel is said of what
    /// leaves: there is no `AuthN` on the way out.
    #[test]
    fn no_release_rests_on_the_channel() {
        for crossing in AnyCaller::DECLARATION.crossings {
            if crossing.direction == Direction::Out {
                assert!(!crossing.opens.contains(&"AuthN"), "{}", crossing.ty);
            }
        }
    }
}
