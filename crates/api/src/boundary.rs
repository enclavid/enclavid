//! api's ends of its legs, declared: the workers and the hatch.
//!
//! One declaration per end, written by api about how it judges what crosses that
//! end: a scope is a property of the channel and of the side holding it, so api
//! names its own, and the role across the leg names its.

use enclavid_boundary::{Asserted, AuthN, AuthZ, Covert};
use enclavid_boundary_macros::boundary;
use engine_rpc::{
    BundleStream, CallbackError, Committed, CompileError, CompileReply, CompileRequest, ExecError,
    MediaBytes, MediaHash, ModelFileDigest, ModelFileStream, Padded, PrepareOutcome, PrepareReply,
    PrepareRequest, RunOutcome, RunReply, RunRequest,
};
use fleet_stream::bin;
use hatch_rpc::{
    AuthorizeError, AuthorizeRequest, BlobRequest, KbsError, KbsRequest, KbsResponse, Manifest,
    ManifestRequest, PullError, Verdict,
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
        /// A model file of the composition this session runs, released to the
        /// image this leg pins, which is the party that runs it.
        ModelFileStream: AuthZ::Matched,
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
        ModelFileDigest,
    }
}

boundary! {
    /// The compile-worker: the process that compiles the consumer's composition,
    /// over one RA-TLS leg api pins and the host splices.
    ///
    /// Nothing it sends is forged — api pinned it — but what it sends is
    /// Cranelift's output over the consumer's wasm, the adversary-supplied input a
    /// toolchain escape rides in on with the handshake succeeding throughout. That
    /// is `Asserted`, and the only concern this end opens on what arrives.
    pub(crate) CompileWorker {
        calls: [engine_rpc::RemoteCompiler],
        observer: HostSplices,
    }

    out (AuthN, AuthZ, Covert) {
        /// This leg dials ONE compile-time-pinned measurement, the handshake fails
        /// before a byte moves if the peer is not it, and the peer keeps nothing past
        /// the compile it is handed.
        _: AuthN::Identified,
        /// The consumer's own artifacts — decrypted, where they were encrypted —
        /// released to the image this leg pins, which is the code that exists to
        /// compile them.
        CompileRequest: AuthZ::Matched,
        /// The HOST performed the OCI pull that produced these bytes, so their length
        /// is a quantity it measured itself.
        CompileRequest: Covert::AlreadyHeld,
    }

    in (Asserted,) {
        CompileReply,
        /// A value of a fixed set whose only text is a name held to the WIT alphabet
        /// and 128 bytes as it is decoded, read only by the consumer that pinned this
        /// composition, about its own artifacts and imports; a compile child its
        /// composition turned picks no more than that per compile.
        CompileError: Asserted::Bounded,
    }
}

boundary! {
    /// The hatch-CVM: the fleet's one way out, over one RA-TLS leg api pins and the
    /// host splices.
    ///
    /// The hatch is our own build, but what it answers is the hooks', a registry's,
    /// a broker's, or its own refusal of a request. So `AuthN` is open on what
    /// arrives — the pin says who carried it, not who made it — and `AuthZ` with
    /// it, for a manifest and a blob: their arrival is the registry's word that the
    /// consumer's bearer may pull them, which a cache hit relies on. Not `Replay`:
    /// nothing that arrives is a version of something api keeps. A manifest and a
    /// blob are named by the digest api pinned, so an older one is another digest;
    /// a broker's release opens only under the ephemeral key of the handshake that
    /// asked for it; and a stale verdict is the operator answering as it chooses,
    /// which it may do in any case.
    ///
    /// Nor does the pin answer `AuthN` for what leaves, as it does on the worker
    /// legs: the hatch keeps nothing it is handed but hands it on. A credential
    /// goes to the operator's hook in the host's sight, so its answer is the
    /// operator's; a request to a registry or a broker is answered where it is
    /// made, by the scheme its consumer wrote — over TLS that ends inside the hatch,
    /// or in the host's sight.
    pub(crate) Hatch {
        calls: [hatch_rpc::RemoteHatch],
        observer: HostSplices,
    }

    out (AuthN, AuthZ, Covert) {
        /// A credential the operator issued, read by the operator's own hook beside the
        /// route api took it on: the reader is the party it came from, and the route
        /// is api's, carrying nothing of an applicant's or a policy's.
        AuthorizeRequest: AuthN::Indifferent,
        /// The credential and the route go to the operator's hook, the party that
        /// decides who may call which route.
        AuthorizeRequest: AuthZ::Matched,
        /// Nothing in either came from a policy: the header is the consumer's
        /// credential, the operation the route's.
        AuthorizeRequest: Covert::NotChosen,
        ManifestRequest,
        /// The registry is handed the bearer it accepts for its own repository, and a
        /// reference to a manifest it hosts.
        ManifestRequest: AuthZ::NoSecret,
        /// The reference and the bearer are the consumer's, given when the session was
        /// created; no policy chose either.
        ManifestRequest: Covert::NotChosen,
        BlobRequest,
        /// The registry is handed the bearer it accepts for its own repository, and a
        /// digest from a manifest it hosts.
        BlobRequest: AuthZ::NoSecret,
        /// Every part is the consumer's, or read from the consumer's own manifest; no
        /// policy chose any.
        BlobRequest: Covert::NotChosen,
        KbsRequest,
        /// The handshake for an artifact's key goes to the broker the consumer named
        /// for it when the session was created: the party that releases that key.
        KbsRequest: AuthZ::Matched,
        /// The broker is the consumer's, the resource the one the artifact's pinned
        /// manifest names, and each leg's shape the protocol's; no policy chose any.
        KbsRequest: Covert::NotChosen,
    }

    in (AuthN, AuthZ) {
        /// A return value on this side's own call, about the request it was asked
        /// for.
        Verdict: AuthZ::NoPrincipal,
        /// Every value ends the same way — no verdict, and the request answered as
        /// unavailable — and its text is dropped.
        AuthorizeError: AuthN::Indifferent,
        /// A return value on this side's own call.
        AuthorizeError: AuthZ::NoPrincipal,
        Manifest,
        /// Four cases, each ending the pull — absent, refused and too large as the
        /// consumer's fixed problems, a failure as a pull to ask again — and a
        /// failure's text reaches only the debug log.
        PullError: AuthN::Indifferent,
        /// A return value on this side's own call.
        PullError: AuthZ::NoPrincipal,
        bin::Receiver,
        /// The broker, not api, authorizes a release — by its resource policy and
        /// the token it gave — and api only consumes what it answered to api's own
        /// call.
        KbsResponse: AuthZ::NoPrincipal,
        /// One case, the leg not happening, which ends the handshake as no answer
        /// does; its text reaches only the debug log.
        KbsError: AuthN::Indifferent,
        /// A return value on this side's own call.
        KbsError: AuthZ::NoPrincipal,
    }
}

#[cfg(test)]
mod tests {
    use enclavid_boundary::declaration::{Direction, End};

    use super::{CompileWorker, ExecutionWorker, Hatch};

    /// api's ends of the legs to the workers, which run the consumer's code.
    const WORKERS: [End; 2] = [ExecutionWorker::DECLARATION, CompileWorker::DECLARATION];

    /// Everything a worker sends is the output of the consumer's code, so nothing
    /// arrives without `Asserted` open on it.
    #[test]
    fn nothing_arrives_without_its_provenance_asked() {
        for end in WORKERS {
            for crossing in end.crossings {
                if crossing.direction == Direction::In {
                    assert!(
                        crossing.opens.contains(&"Asserted"),
                        "{}: {}",
                        end.name,
                        crossing.ty
                    );
                }
            }
        }
    }

    /// The hatch hands on what it is handed, so the pin answers nothing alone: no
    /// answer is given for every type, and none here is `Identified` — where the
    /// pin covers a request, it covers it for the scheme the request's mint sees.
    /// What a registry serves keeps `AuthN` open, for the digest check at the use
    /// site.
    #[test]
    fn the_pin_answers_nothing_alone() {
        for crossing in Hatch::DECLARATION.crossings {
            for answer in crossing.answers {
                assert!(!answer.every_type, "{}", crossing.ty);
                assert_ne!(answer.kind, "Identified", "{}", crossing.ty);
            }
        }
        for pulled in ["Manifest", "bin::Receiver"] {
            let crossing = Hatch::DECLARATION
                .crossings
                .iter()
                .find(|c| c.direction == Direction::In && c.ty == pulled)
                .unwrap_or_else(|| panic!("{pulled} crosses"));
            assert!(crossing.left.contains(&"AuthN"), "{pulled}");
        }
    }

    /// The one answer given for every type is about the channel — the pin — and
    /// every other answer is about the value it is given on.
    #[test]
    fn only_the_pin_is_answered_for_every_type() {
        for end in WORKERS {
            for crossing in end.crossings {
                for answer in crossing.answers.iter().filter(|a| a.every_type) {
                    assert_eq!(
                        (answer.marker, answer.kind),
                        ("AuthN", "Identified"),
                        "{}: {}",
                        end.name,
                        crossing.ty
                    );
                }
            }
        }
    }
}
