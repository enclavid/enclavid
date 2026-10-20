//! This role's end of the api leg, declared.
//!
//! The listener accepts any attested guest — it cannot pin api, whose
//! measurement is a function of this one's — and the relay in front of its port
//! takes calls from api alone. That relay is the host's, though, so what arrives
//! here arrives from a genuine SNP guest of this host, and the host may launch
//! one of its own: `AuthN` is open on what arrives, in a way it never is on
//! api's side of the same wire.
//!
//! What answers it is that this role holds nothing a caller could be handed
//! that the host does not hold: no applicant data, no seal key, no cache. A
//! request is made on what it carries — the credential, the bearer, the
//! handshake — and on nothing of another's: a registry client made for each
//! pull, and for broker legs one client that keeps no cookie and follows no
//! redirect. What comes back is the hooks', the registry's or the broker's
//! answer to it, or this role's refusal of it, which the host could have from
//! its own network. What IS shared is a budget — the turns at registries, and
//! the creations the limits hook counts for the operator — so a caller can make
//! others wait or be refused: availability, which the host holds in any case.
//!
//! Not `AuthZ` on the way in: no resource here is one caller's to reach past
//! another's. Not `Replay`: nothing that arrives here was served by a store.
//!
//! On the way out there is no `AuthN`: the channel names no peer, and the
//! recipient is not this role's to choose — it answers only the call that
//! asked. What a reply carries is computed from that call's own request, so
//! `AuthZ` is answered type by type with what each is computed from; and its
//! length is the length of something the host carried in, or one of a few
//! fixed values, so `Covert` is answered type by type with which.
//!
//! These are the measured build's facts, `sev-snp` with `vsock`. Without
//! `vsock` the listener is TCP, the identity's seed is public, and the hooks sit
//! on 127.0.0.1, where a broker leg can reach them.

use enclavid_boundary::{AuthN, AuthZ, Covert};
use enclavid_boundary_macros::boundary;
use fleet_stream::bin;
use hatch_rpc::{
    AuthorizeError, AuthorizeRequest, BlobRequest, KbsError, KbsRequest, KbsResponse, Manifest,
    ManifestRequest, PullError, Verdict,
};

boundary! {
    /// Whoever called: a genuine SNP guest of this host, which the host's relay in
    /// front of the port says is api.
    pub AnyCaller {
        serves: [hatch_rpc::RemoteHatch],
        observer: HostSplices,
    }

    in (AuthN,) {
        /// It has the operator's hooks asked about the credential it carries, and a
        /// creation counted: the operator is the host every caller runs on, so no
        /// caller learns or spends through it what its host could not with its own
        /// hooks.
        AuthorizeRequest: AuthN::Indifferent,
        /// A pull of what it names with the bearer it carries, by a registry client
        /// made for it alone: one any caller could make from the host's own network.
        ManifestRequest: AuthN::Indifferent,
        /// A pull of what it names with the bearer it carries, as a manifest's is.
        BlobRequest: AuthN::Indifferent,
        /// A request to wherever it names, sent unread from the interface the host
        /// carries on its own network, with nothing of this role's added and nothing
        /// of another call's kept: one the host could send itself.
        KbsRequest: AuthN::Indifferent,
    }

    out (AuthZ, Covert) {
        /// The operator's hooks' answer, from what they keep, to the credential this
        /// call sent: one they would give their own operator.
        Verdict: AuthZ::NoSecret,
        /// The answer the host's own hooks gave.
        Verdict: Covert::AlreadyHeld,
        /// A hook that did not answer this call's question, or answered it with no
        /// verdict.
        AuthorizeError: AuthZ::NoSecret,
        /// What the host's own hook did: no answer, an answer outside the contract,
        /// or the status it chose.
        AuthorizeError: Covert::AlreadyHeld,
        /// The registry's answer to the reference and bearer this call sent.
        Manifest: AuthZ::NoSecret,
        /// Carried in on the interface the host runs, so its length is in the records
        /// the host saw go by.
        Manifest: Covert::AlreadyHeld,
        /// A failure of the pull this call asked for: the registry's word about the
        /// reference it sent, or this role's about the request itself.
        PullError: AuthZ::NoSecret,
        /// One of a handful of fixed values: absent, refused, too large, or one of a
        /// few fixed texts for a registry that did not answer as one does.
        PullError: Covert::Bounded,
        /// The blob this call's request named, as the registry streams it.
        bin::Receiver: AuthZ::NoSecret,
        /// Carried in on the interface the host runs, as a manifest is.
        bin::Receiver: Covert::AlreadyHeld,
        /// The broker's answer to the leg this call sent.
        KbsResponse: AuthZ::NoSecret,
        /// Carried in on the interface the host runs, as a manifest is.
        KbsResponse: Covert::AlreadyHeld,
        /// A leg this call sent that did not happen, or that this role does not send.
        KbsError: AuthZ::NoSecret,
        /// One of a few fixed texts: no answer, an answer that broke off or ran past
        /// its bound, or a leg this role does not send.
        KbsError: Covert::Bounded,
    }
}

#[cfg(test)]
mod tests {
    use enclavid_boundary::declaration::Direction;

    use super::AnyCaller;

    /// What leaves is answered for `AuthZ` and `Covert` type by type, never for the
    /// whole block, and nothing leaves on the channel's word: this end names no
    /// peer.
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
                for marker in ["AuthZ", "Covert"] {
                    assert!(
                        crossing.answers.iter().any(|a| a.marker == marker),
                        "{} leaves with no {marker} answer",
                        crossing.ty
                    );
                }
            }
        }
    }
}
