//! The concern markers — the axes a value can be untrusted or unreleased on.
//!
//! A marker is a question, and its doc is the only place that question is
//! written down. Everything else in this crate is machinery for carrying the
//! answers around: [`Untrusted`](crate::Untrusted) and
//! [`Exposed`](crate::Exposed) hold a tuple of these, the peel methods take them
//! off one at a time, and `Remove` is what makes the tuple shrink. None of that
//! knows what any marker means. So this file, not the wrappers, is what a
//! reviewer reads to find out what was being asked.
//!
//! **Adding one is a real decision, not a convenience.** A new marker earns its
//! place only if no existing one asks its question — and the test is adversarial:
//! write the answer you would have to write under the nearest existing marker,
//! and see whether it would pass review while leaving the defect in. `Asserted`
//! was added on exactly that ground; "RA-TLS against a pinned measurement" under
//! `AuthN` is true, passes review, and ships every one of the four defects it
//! exists to catch.
//!
//! **Each marker lists its legal answers as constants of its own type** —
//! `AuthN::Verified`, `AuthZ::NoSecret`, `Asserted::Contained` — and the peel
//! methods take nothing else. Each is classed by what answering with it takes,
//! and the class decides which method accepts it:
//!
//!   * [`Work`](crate::Work) — the answer IS work done on the value at the peel:
//!     a check over its bytes, a transformation of its encoding. Taken by
//!     `trust_with` / `vouch_with`, never by the argued form, so a kind like this
//!     cannot be claimed without the work being in front of the reader.
//!   * [`Argued`](crate::Argued) — the kind's own argument is the answer, and no
//!     work at the peel is needed for it to hold. Taken by `trust` / `vouch` with a
//!     reason, and by `trust_with` / `vouch_with` where work backs it anyway.
//!   * [`Risk`](crate::Risk) — `AcceptedRisk`, on every marker: no kind fits.
//!     Taken by `trust_accept_risk` / `vouch_accept_risk` alone, so the standing
//!     risks are one grep away.
//!
//! Every marker also names a NON-discharge: the true-sounding sentence that would
//! close it while leaving the defect in. That is what lets a review ask "which of
//! the kinds?" and treat a reason that fits none as a finding rather than a matter
//! of taste — a reason is not refuted by argument, it is refuted by a list it
//! fails to be on. Every non-discharge below was taken from a defect this
//! repository actually shipped, not invented as an illustration.
//!
//! **A value may also have NO kind, and say so.** That is `AcceptedRisk`, and it
//! is the honest answer when nothing on the list fits — a standing risk that
//! should surface on every audit, because it is still open. What is never allowed
//! is inventing a kind to close it: the sentence that would do it ("the damage is
//! bounded", "the peer is attested") fits every value ever shipped, so admitting
//! it hollows out the list for all the values it does not fit.
//!
//! Direction is part of a marker's meaning. `Covert` is outbound-only because
//! this side is not the encoder on the way in; `Asserted` is inbound-only because
//! releasing TO such a peer is a release decision the outbound wrapper already
//! names. A marker that appeared in both scopes would be answering two different
//! questions under one name — except where the two readings are written down
//! side by side, as `AuthN`'s and `AuthZ`'s are. Each marker says which scopes it
//! may stand in by implementing [`InboundConcern`] and [`OutboundConcern`], and a
//! declaration's block opens nothing else.

use crate::{Argued, InboundConcern, Kind, OutboundConcern, Risk, Work};

/// Authenticity concern: bytes might have been fabricated or substituted by an
/// untrusted source. Outbound, its mirror: confidentiality — someone other than
/// the party a value is for might read it.
///
/// **"The peer completed a handshake" is NOT an answer.** `Identified` requires a
/// pin. Where a leg accepts any attested guest — which the fleet leaves must, since
/// pinning api would be circular — a completed handshake proves a genuine SNP guest
/// and not a particular one, so it is true of every caller including a hostile one.
/// That sentence is what the L1 cache-poisoning defect was made of. On the way out
/// it is the same sentence: a value sent to an unpinned peer is readable by
/// whichever guest dialled, and the host can launch one.
pub struct AuthN;

impl InboundConcern for AuthN {}
impl OutboundConcern for AuthN {}

#[allow(non_upper_case_globals)]
impl AuthN {
    /// A cryptographic check over the bytes themselves: an AEAD open under a key
    /// the other side cannot hold, a signature, a digest match against a value
    /// established elsewhere. Outbound, the same work run the other way: an AEAD
    /// seal under a key the reader cannot hold.
    pub const Verified: Kind<AuthN, Work> = Kind::__define();
    /// The channel binds the producer to ONE specific party and that binding is
    /// checked: mutual RA-TLS against a PINNED measurement. Outbound, the same pin
    /// binds the reader: only that party's image can read what crosses.
    pub const Identified: Kind<AuthN, Argued> = Kind::__define();
    /// The value never left this side; it is being re-read, not received.
    /// Inbound only.
    pub const SelfProduced: Kind<AuthN, Argued> = Kind::__define();
    /// The whole range is safe to act on, so who produced it cannot matter (a
    /// fixed-cardinality enum with every variant handled). Outbound, the value is
    /// safe for whoever reads it: public material, or the reader's own.
    pub const Indifferent: Kind<AuthN, Argued> = Kind::__define();
    /// No kind fits: a standing risk, named as one.
    pub const AcceptedRisk: Kind<AuthN, Risk> = Kind::__define();
}

/// Authorization concern: the principal who made this request might not be allowed
/// to reach this resource. Never a cryptographic property — it is settled at the
/// application layer or by the shape of the namespace.
///
/// **"The caller is inside the fleet" is NOT an answer.** Membership is not
/// permission: it is the same sentence for every member, and a leg that pins nobody
/// cannot even establish membership in a useful sense. `Scoped` is what replaced
/// exactly that reasoning after it failed.
///
/// Outbound, its mirror: release — whether the party receiving a value may have
/// it.
pub struct AuthZ;

impl InboundConcern for AuthZ {}
impl OutboundConcern for AuthZ {}

#[allow(non_upper_case_globals)]
impl AuthZ {
    /// A predicate compares the authenticated principal against the resource's
    /// owner — at the peel, or upstream where the reason says.
    pub const Matched: Kind<AuthZ, Argued> = Kind::__define();
    /// The resource NAME is derived from the principal, so reaching another's is
    /// not expressible. `storage::scope::Name` and the executor's per-caller L1
    /// partition are this kind.
    pub const Scoped: Kind<AuthZ, Argued> = Kind::__define();
    /// The release decision is empty because the recipient learns nothing it did
    /// not already hold: a pure function of what it just sent, or a value it
    /// supplied.
    pub const NoSecret: Kind<AuthZ, Argued> = Kind::__define();
    /// There is no principal on this path to authorize. A return value on a call
    /// this side made is the usual case.
    pub const NoPrincipal: Kind<AuthZ, Argued> = Kind::__define();
    /// No kind fits: a standing risk, named as one.
    pub const AcceptedRisk: Kind<AuthZ, Risk> = Kind::__define();
}

/// Replay-resistance concern: bytes are authentic but might be a stale snapshot the
/// source served instead of the latest version.
///
/// **Only open this where a STORE served the value.** The question presupposes one:
/// something retained an earlier version and could hand it back instead of the
/// current one. Reading from the host's session store is the case it exists for, and
/// the CAS on `expected_version` is its `Fresh`.
///
/// A value arriving on a live stream has no version to be stale from — a re-sent
/// request is a different input, not an old one, and whether the peer invented it is
/// [`Asserted`]'s question. There is deliberately NO kind meaning "nothing was ever
/// open here": if that is the honest answer, the mistake was putting `Replay` in the
/// scope, and a legal-looking way to close it would only hide the mistake. A vacuous
/// axis is worse than a missing one, because it teaches the next reader that the
/// list is decoration.
pub struct Replay;

impl InboundConcern for Replay {}

#[allow(non_upper_case_globals)]
impl Replay {
    /// A freshness mechanism runs: a monotonic counter, a CAS on an expected
    /// version, a nonce this side chose.
    pub const Fresh: Kind<Replay, Argued> = Kind::__define();
    /// Acting on a stale value and acting on the current one have the same effect,
    /// so the distinction cannot be observed.
    pub const Idempotent: Kind<Replay, Argued> = Kind::__define();
    /// A stale value costs availability or UX and cannot cost confidentiality or
    /// integrity, and the reason says which.
    pub const Harmless: Kind<Replay, Argued> = Kind::__define();
    /// No kind fits: a standing risk, named as one.
    pub const AcceptedRisk: Kind<Replay, Risk> = Kind::__define();
}

/// Provenance concern: the value was produced by code executing
/// adversary-supplied input, and is therefore the peer's own word rather
/// than a function of anything this side or the applicant established.
///
/// Nothing here is forged — the peer is our own measured image, reached
/// over mutual RA-TLS against a pinned measurement. Nothing here is
/// derived from anything we know, either. That is the whole axis: the
/// other four ask who sent it, whether they may, whether it is fresh and
/// whether it leaks outward; none asks what it is a function of.
///
/// "The peer is attested" is NOT an answer. It is true of every value on this
/// axis, and it is the reasoning four separate 2026-09 defects were made of.
///
/// Inbound-only: releasing TO such a peer is a release decision, which
/// [`Exposed`](crate::Exposed) already names.
pub struct Asserted;

impl InboundConcern for Asserted {}

#[allow(non_upper_case_globals)]
impl Asserted {
    /// This side computes the value from inputs it holds.
    pub const ReDerived: Kind<Asserted, Work> = Kind::__define();
    /// Checked against something a DIFFERENT party established: the applicant's
    /// echoed digest, bytes this side pulled and digest-verified.
    pub const Bound: Kind<Asserted, Work> = Kind::__define();
    /// The entire range is harmless (a fixed-cardinality enum).
    pub const Bounded: Kind<Asserted, Argued> = Kind::__define();
    /// Re-exposed only to the party whose own code authored it, or to the
    /// applicant, who is its sole auditor.
    pub const Contained: Kind<Asserted, Argued> = Kind::__define();
    /// No kind fits: a standing risk, named as one.
    pub const AcceptedRisk: Kind<Asserted, Risk> = Kind::__define();
}

/// Covert-channel concern: outbound data might carry policy-controlled bandwidth
/// disguised as legitimate structure — field order, count, length, content.
///
/// **"It is encrypted" is NOT an answer.** The observer counts bytes it cannot
/// read; confidentiality of content says nothing about a length. That is precisely
/// how moving execution into its own CVM reopened the state-size channel the seal
/// padding exists to close — the bytes stayed sealed the whole time.
///
/// Outbound-only axis: inbound data is not a covert-channel concern because this
/// side is not the encoder. `Exposed<T, S, B>` is where `Covert` appears in `S`.
pub struct Covert;

impl OutboundConcern for Covert {}

#[allow(non_upper_case_globals)]
impl Covert {
    /// The encoding is made independent of the content: constant-size framing, a
    /// fixed order, a shuffle, a scrub. The work is done, not promised.
    pub const Transformed: Kind<Covert, Work> = Kind::__define();
    /// The whole range is small enough that the bandwidth is negligible, and the
    /// reason says how small (a fixed-cardinality enum).
    pub const Bounded: Kind<Covert, Argued> = Kind::__define();
    /// No party with something to leak picked this value: a TEE-minted random id,
    /// a constant of the measured image.
    pub const NotChosen: Kind<Covert, Argued> = Kind::__define();
    /// The observer holds the value, or its size, by a path it controls anyway.
    /// The host performing the OCI pull is the example.
    pub const AlreadyHeld: Kind<Covert, Argued> = Kind::__define();
    /// No kind fits: a standing risk, named as one.
    pub const AcceptedRisk: Kind<Covert, Risk> = Kind::__define();
}
