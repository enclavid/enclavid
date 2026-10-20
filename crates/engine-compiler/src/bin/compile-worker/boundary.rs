//! This role's end of the api leg, declared.
//!
//! The listener accepts any attested guest — it cannot pin api, whose
//! measurement is a function of this one's — so a completed handshake proves a
//! genuine SNP guest on this part and NOT that it is api. `AcceptAny` is not an
//! absence of attestation: the quote is verified whole, bound to the very TLS key
//! in front of it. What is missing is WHICH image. That is why `AuthN` is open on
//! what arrives here, in a way it never is on api's side of the same wire.
//!
//! What answers the missing pin is a property of this role's POSITION rather
//! than of the bytes: nothing derived from a request outlives its call. A compile
//! runs in a disposable child that keeps nothing, and its answer goes back only
//! to whoever asked, so one caller's input cannot reach another's compile. That
//! is what the INDIFFERENT answer below rests on, and it is load-bearing rather
//! than incidental: a cache added here would end it, and would need the
//! execution-worker's per-caller partitioning before it could. What IS shared is
//! a concurrency budget — the runner's slots — so a caller can make others WAIT:
//! availability, answered by the deadline and the compile's memory max rather
//! than by a judgement about the bytes.
//!
//! Not `AuthZ` on the way in: this role holds no resource a caller could reach
//! past another's. Not `Replay`: no request outlives its own call, so there is no
//! version for one to be stale from — and whether the peer invented it is
//! `Asserted`'s question, which only a receiver of this role's OUTPUT can ask.
//!
//! On the way out there is no `AuthN`, for the reason the execution-worker's end
//! gives: the channel names no peer, and the recipient is not this role's to
//! choose — it answers only the call that asked. What a reply carries is computed
//! from that call's own components, so `AuthZ` is answered type by type with what
//! each is computed from.

use enclavid_boundary::{AuthN, AuthZ, Covert};
use enclavid_boundary_macros::boundary;
use engine_rpc::{CompileError, CompileReply, CompileRequest};

boundary! {
    /// Whoever called: a genuine SNP guest on this part, not identifiably api.
    pub(crate) AnyCaller {
        serves: [engine_rpc::RemoteCompiler],
        observer: HostSplices,
    }

    in (AuthN,) {
        /// Nothing derived from a request outlives its call, so hostile input reaches
        /// only its own compile and its own caller; the shared runner slots are
        /// availability, capped elsewhere.
        CompileRequest: AuthN::Indifferent,
    }

    out (AuthZ, Covert) {
        /// The compile of the components this call sent, by a child that kept
        /// nothing of any other: a function of what the caller just sent.
        CompileReply: AuthZ::NoSecret,
        /// A fault of the components this call sent, or a failure that names none.
        CompileError: AuthZ::NoSecret,
        /// A value of a fixed set whose only text is a name held to the WIT
        /// alphabet and 128 bytes, so its length on the wire takes a few hundred
        /// values at most.
        CompileError: Covert::Bounded,
    }
}

#[cfg(test)]
mod tests {
    use enclavid_boundary::declaration::Direction;

    use super::AnyCaller;

    /// What leaves is answered for `AuthZ` type by type, never for the whole
    /// block, and nothing leaves on the channel's word: this end names no peer.
    #[test]
    fn every_release_says_what_it_is_computed_from() {
        for crossing in AnyCaller::DECLARATION.crossings {
            assert!(
                crossing.answers.iter().all(|a| !a.every_type),
                "{}",
                crossing.ty
            );
            if crossing.direction == Direction::Out {
                assert!(!crossing.opens.contains(&"AuthN"), "{}", crossing.ty);
                assert!(
                    crossing.answers.iter().any(|a| a.marker == "AuthZ"),
                    "{} leaves with no AuthZ answer",
                    crossing.ty
                );
            }
        }
    }
}
