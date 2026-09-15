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
//! write the discharge you would have to write under the nearest existing marker,
//! and see whether it would pass review while leaving the defect in. `Asserted`
//! was added on exactly that ground; `trust_unchecked::<AuthN>(reason!("RA-TLS
//! against a pinned measurement"))` is true, passes review, and ships every one
//! of the four defects it exists to catch.
//!
//! A marker whose discharges all read alike across its call sites is not pulling
//! its weight: it has become a sentence people write rather than a question they
//! answer. So every marker here carries a documented ENUMERATION of its legal
//! discharges, and a named NON-discharge: the true-sounding sentence that would
//! close it while leaving the defect in. That is what lets a review ask "which of
//! the four?" and treat a reason naming none as a finding rather than a matter of
//! taste — a reason is not refuted by argument, it is refuted by a list it fails to
//! be on.
//!
//! Every non-discharge below was taken from a defect this repository actually
//! shipped, not invented as an illustration.
//!
//! **A reason may also name NO kind, and say so.** That is the honest answer when
//! a value genuinely has no discharge available on an axis, and it applies to
//! every marker here — [`Asserted`] carries the worked example because that is
//! where the case first arose, but nothing about it is particular to that one.
//! Such a site is a standing ACCEPTED RISK: it should surface on every audit,
//! because it is still open. What is never allowed is inventing a kind to close
//! it, and the reason is the same each time — the sentence that would do it ("the
//! damage is bounded", "the peer is attested") fits every value ever shipped, so
//! admitting it hollows out the list for all the values it does not fit.
//!
//! Direction is part of a marker's meaning. `Covert` is outbound-only because
//! this side is not the encoder on the way in; `Asserted` is inbound-only because
//! releasing TO such a peer is a release decision the outbound wrapper already
//! names. A marker that appeared in both scopes would be answering two different
//! questions under one name.

/// Authenticity concern: bytes might have been fabricated or substituted by an
/// untrusted source.
///
/// Cleared by demonstrating exactly ONE of:
///   1. VERIFIED — a cryptographic check over the bytes themselves: an AEAD open
///      under a key the other side cannot hold, a signature, a digest match against
///      a value established elsewhere.
///   2. IDENTIFIED — the channel binds the producer to ONE specific party and that
///      binding is checked: mutual RA-TLS against a PINNED measurement.
///   3. SELF-PRODUCED — the value never left this side; it is being re-read, not
///      received.
///   4. INDIFFERENT — the whole range is safe to act on, so who produced it cannot
///      matter (a fixed-cardinality enum with every variant handled).
///
/// **"The peer completed a handshake" is NOT a discharge.** Kind 2 requires a pin.
/// Where a leg accepts any attested guest — which the fleet leaves must, since
/// pinning api would be circular — a completed handshake proves a genuine SNP guest
/// and not a particular one, so it is true of every caller including a hostile one.
/// That sentence is what the L1 cache-poisoning defect was made of.
pub struct AuthN;

/// Authorization concern: the principal who made this request might not be allowed
/// to reach this resource. Never a cryptographic property — it is settled at the
/// application layer or by the shape of the namespace.
///
/// Cleared by demonstrating exactly ONE of:
///   1. MATCHED — a predicate compares the authenticated principal against the
///      resource's owner.
///   2. SCOPED — the resource NAME is derived from the principal, so reaching
///      another's is not expressible. `storage::scope::Name` and the executor's
///      per-caller L1 partition are this kind.
///   3. NO-SECRET — the release decision is empty because the recipient learns
///      nothing it did not already hold: a pure function of what it just sent, or a
///      value it supplied.
///   4. NO-PRINCIPAL — there is no principal on this path to authorize. A return
///      value on a call this side made is the usual case.
///
/// **"The caller is inside the fleet" is NOT a discharge.** Membership is not
/// permission: it is the same sentence for every member, and a leg that pins nobody
/// cannot even establish membership in a useful sense. Kind 2 is what replaced
/// exactly that reasoning after it failed.
pub struct AuthZ;

/// Replay-resistance concern: bytes are authentic but might be a stale snapshot the
/// source served instead of the latest version.
///
/// Cleared by demonstrating exactly ONE of:
///   1. FRESH — a freshness mechanism ran: a monotonic counter, a CAS on an expected
///      version, a nonce this side chose.
///   2. IDEMPOTENT — acting on a stale value and acting on the current one have the
///      same effect, so the distinction cannot be observed.
///   3. HARMLESS — a stale value costs availability or UX and cannot cost
///      confidentiality or integrity, and the reason says which.
///
/// **Only open this where a STORE served the value.** The question presupposes one:
/// something retained an earlier version and could hand it back instead of the
/// current one. Reading from the host's session store is the case it exists for, and
/// the CAS on `expected_version` is its kind 1.
///
/// A value arriving on a live stream has no version to be stale from — a re-sent
/// request is a different input, not an old one, and whether the peer invented it is
/// [`Asserted`]'s question. There is deliberately NO discharge kind meaning "nothing
/// was ever open here": if that is the honest answer, the mistake was putting
/// `Replay` in the scope, and a legal-looking way to close it would only hide the
/// mistake. A vacuous axis is worse than a missing one, because it teaches the next
/// reader that the list is decoration.
pub struct Replay;

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
/// Cleared by demonstrating exactly ONE of:
///   1. RE-DERIVED — this side computes the value from inputs it holds.
///   2. BOUND — checked against something a DIFFERENT party established
///      (the applicant's echoed digest; bytes this side pulled and
///      digest-verified).
///   3. BOUNDED — the entire range is harmless (a fixed-cardinality enum).
///   4. CONTAINED — re-exposed only to the party whose own code authored
///      it, or to the applicant, who is its sole auditor.
///
/// "The peer is attested" is NOT a discharge. It is true of every value
/// on this axis, and it is the reasoning four separate 2026-09 defects
/// were made of. A reason that names none of the four kinds above is a
/// finding, not a matter of taste.
///
/// **And sometimes none of them fits.** A value can genuinely have no discharge —
/// nothing to re-derive it from, no second party to bind it against, a range that
/// is not harmless, and an audience that is not its author. When that happens the
/// honest reason names no kind and says so. Such a site is a standing ACCEPTED
/// RISK: it should surface on every audit, because it is still open. Do not close
/// it by inventing a fifth kind — "the damage is bounded" fits every value ever
/// shipped, and admitting it would hollow out the four.
///
/// Inbound-only: releasing TO such a peer is a release decision, which
/// [`Exposed`](crate::Exposed) already names.
pub struct Asserted;

/// Covert-channel concern: outbound data might carry policy-controlled bandwidth
/// disguised as legitimate structure — field order, count, length, content.
///
/// Cleared by demonstrating exactly ONE of:
///   1. TRANSFORMED — the encoding is made independent of the content: constant-size
///      framing, a fixed order, a shuffle, a scrub. The work is done, not promised.
///   2. BOUNDED — the whole range is small enough that the bandwidth is negligible,
///      and the reason says how small (a fixed-cardinality enum).
///   3. NOT-CHOSEN — no party with something to leak picked this value: a TEE-minted
///      random id, a constant of the measured image.
///   4. ALREADY-HELD — the observer holds the value, or its size, by a path it
///      controls anyway. The host performing the OCI pull is the example.
///
/// **"It is encrypted" is NOT a discharge.** The observer counts bytes it cannot
/// read; confidentiality of content says nothing about a length. That is precisely
/// how moving execution into its own CVM reopened the state-size channel the seal
/// padding exists to close — the bytes stayed sealed the whole time.
///
/// Outbound-only axis: inbound data is not a covert-channel concern because this
/// side is not the encoder. `Exposed<T, S>` is where `Covert` appears in `S`.
pub struct Covert;
