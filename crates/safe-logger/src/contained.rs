//! The posture for a process that may not speak to the host.
//!
//! Its counterpart is [`crate::install`], which is behind the `device` feature.
//! This one is not, and that asymmetry is the crate's whole shape: saying
//! nothing outward needs no outward tier compiled, so a package that only ever
//! calls this can leave the feature off and lose the ability to write an
//! [`crate::info!`] at all.

/// Stand the channel up for a process that MAY NOT speak to the host: the slot
/// is claimed, `debug!` reaches stderr, and there is no outward tier.
///
/// For the disposable per-round children. They hold the round's applicant
/// plaintext in the one address space where adversary-chosen code runs, and
/// their whole containment assumes the wasm sandbox may fail — disposable
/// process, cleared environment, nulled stdio, an egress seccomp filter. A
/// device would put the log channel's safety back on "the sandbox holds", which
/// is the assumption everything around it refuses to make. The vouch discipline
/// does not help there either: `SafeToLog` and [`crate::reason!`] are
/// compile-time, and escaped native code does not call the macros — it calls
/// `write`.
///
/// So this is not `install` minus a step. It is the other posture, named, and
/// the difference a reader should see at the call site.
///
/// What it buys over calling nothing at all is the slot: `log::set_logger`
/// succeeds once, and a process that never claims it leaves it open for a
/// dependency to fill with something that writes to stdout. `debug!` is not the
/// reason — it needs no installer, because it calls its sink directly rather
/// than through `log`'s gate. Where it lands is unchanged either way: spawned,
/// the supervisor's `/dev/null`; run from a terminal, the terminal.
///
/// [`crate::DEVICE_KEY`] is not consulted — not even to fail loudly if it is
/// set. A process that has decided it may not speak should not change its mind
/// because of an environment variable, and the supervisor clears the environment
/// anyway.
///
/// # What the two builds of this function differ on
///
/// Without the `device` feature — the posture the child packages build with —
/// there is no outward tier in the binary, so this claims the slot, reads the
/// threshold, and is done. That is the guarantee worth having, because it is
/// made by the compiler rather than by this function.
///
/// With the feature on, the same call additionally sets a flag that makes an
/// outward line be DROPPED rather than sent somewhere else — see `device::emit`.
/// That case exists because features unify across a
/// cargo invocation: a whole-workspace build turns the feature on for everything
/// in it, so a child compiled that way does have the tier, and had better not
/// use it. The image builds each package on its own, where the compiler's answer
/// is the one that applies.
pub fn install_contained() {
    #[cfg(feature = "device")]
    crate::device::mark_contained();

    crate::logger::claim_the_global_slot();
    crate::logger::set_threshold_from_config();
}
