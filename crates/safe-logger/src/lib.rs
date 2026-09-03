//! The one channel a role binary may say anything on. The host reads it, so a
//! line here has left the TEE — which is what the crate is named for: every
//! value on it is one someone marked [`safe`].
//!
//! It is the same crossing the wire perimeter governs, and it borrows that
//! perimeter's token: every value carries a written [`reason!`], and so does
//! every line. What the measured image buys is that a reviewer can read every
//! [`info!`] site in it and know the complete set of things that can ever be
//! printed.
//!
//! ```text
//!   macros.rs     info! warn! error!  →  device, every argument SafeToLog
//!                 debug! trace!       →  stderr, not compiled in production
//!   vouch.rs      who says a value may be disclosed, and how
//!   logger.rs     how a line is rendered, the slot claim, the threshold
//!   contained.rs  the posture for a process that may not speak
//!   mode/         who holds the slot — the ONE thing the two builds differ on
//!                   production.rs  a no-op: a dependency's records are dropped
//!                   debug.rs       DebugLogger: they go to stderr instead
//!   device.rs     the descriptor, and the only place bytes go out of it
//!   panic.rs      what a crash says, and how much of it
//! ```
//!
//! # Who may speak at all
//!
//! The outward half — [`info!`], [`warn!`], [`error!`], [`error_and_panic!`],
//! [`install`], [`install_panic`], the descriptor and the sink that writes to it
//! — is behind the `device` cargo feature, and the feature is off unless a
//! package asks for it. [`install_contained`], [`debug!`] and the vouch types
//! are not: saying nothing outward needs no outward tier compiled.
//!
//! So a package's manifest is where "may this binary talk to the host?" is
//! answered, in one line a reviewer can grep for, and the compiler enforces the
//! answer — an [`info!`] in a package that did not ask is
//! `cannot find macro `info` in crate `safe_logger``. The two disposable
//! children are the packages that do not ask.
//!
//! It holds per cargo INVOCATION, which is the unit features unify over. Each
//! guest binary is built by its own `cargo build -p`, so there the answer is the
//! manifest's. A whole-workspace build turns the feature on for everything in
//! it, because api asked for it — convenient for `cargo test`, and not a claim
//! about anything that ships.
//!
//! # The invariant underneath
//!
//! By default a guest emits nothing. A `println!` from any crate in the tree, a
//! panic payload and output from C underneath all go to fds 1 and 2, and in the
//! production image nothing on those reaches the host. Only code that opens the
//! log device itself does, and that is this crate.
//!
//! Two mechanisms could be producing that silence, and which one it is has not
//! been settled by a boot. `console=null` on the measured command line points
//! `/dev/console` at a console that discards — but the initramfs archive
//! carries no `/dev/console` node (see image/initramfs), and the `devtmpfs`
//! supplying one is mounted by a `::sysinit:` line. That line runs before
//! `::wait:/bin/app`, so the node exists by then; whether busybox init hands the
//! application THAT console or a descriptor it settled on earlier, before the
//! mount, depends on when busybox opens it.
//!
//! Both discard: the null console by design, and init's fallback — a read-only
//! descriptor — by returning `EBADF`, which Rust's stdio reports as success. So
//! the invariant holds either way and nothing here rests on the answer. What
//! does rest on it is whether [`debug!`] is visible in the `debug` image, whose
//! command line puts a real console on the port. Until someone boots one and
//! looks, treat that as unverified.
//!
//! # Why nothing unvouched is forwarded
//!
//! An earlier shape redirected fds 1 and 2 into a pipe and forwarded what
//! arrived, on the argument that before a role begins serving there is nothing
//! applicant-derived in the process for a stray line to carry. That is a claim
//! about the whole process rather than about the line, and claims like it decay
//! without anyone noticing: it made roughly twenty `eprintln!` sites in the
//! applicant path — several carrying a session id and an error chain from
//! running the consumer's policy — safe only because one flag was set in one
//! place, invisible from the sites it was protecting.
//!
//! Whether text may be disclosed is known only to whoever wrote it. So the
//! reason travels with the line or the line does not travel. Everything else
//! keeps going to the descriptor that discards it, which is where it already
//! went.
//!
//! The cost is real and is paid deliberately: a dependency that fails loudly on
//! stderr says nothing here. Where the message matters, the site emits an
//! [`info!`] itself.
//!
//! # Three barriers
//!
//! **The global slot.** `rustls`, `wasmtime` and `tracing` are already in this
//! tree and already call the `log` facade. Today those calls die because nobody
//! has registered a logger — which is not a property, only a fact about the
//! current code. [`install`] fills the slot, and `log::set_logger` succeeds
//! exactly once. See `logger::claim_the_global_slot`.
//!
//! What fills it is the build's choice, and `mode/` is the only place that
//! `#[cfg]` appears: a no-op in production, so a dependency's records are
//! dropped before they can reach a device the host reads — and [`DebugLogger`]
//! otherwise, so they are printed to stderr instead. The `debug` image already
//! carries the whole kernel log and this crate's own unvouched `debug!` lines,
//! so `rustls` explaining a failed handshake there is not a new category; it is
//! why someone booted that image. [`LEVEL_KEY`] is the tap.
//!
//! What the macros write to is two `log::Log` impls they name directly, and a
//! dependency's record cannot arrive at the DEVICE one by any route. That it
//! cannot be registered is structural rather than a matter of ordering: its
//! field is private, and the only constructor claims the slot before it hands
//! back a value, so a sink is in hand only after registration has already become
//! impossible. See `logger::DeviceLogger`.
//!
//! The stderr sink carries the same discipline for the same reason, but a
//! smaller consequence: in a `debug` build it is what the slot was filled WITH,
//! so a dependency's records do arrive there. That is the paragraph above, not a
//! hole in this one — stderr is not a wire the host reads.
//!
//! Each renders `[timestamp LEVEL] message` itself and shares no state with the
//! other, which is why neither is a logging crate underneath.
//!
//! **The type.** An argument that is not [`SafeToLog`] does not compile, and the
//! only way to make one at a site is [`safe`], which demands a [`reason!`].
//!
//! **The span.** A name captured inside the format string does not compile
//! either — not because anything here inspects the string, but because it never
//! gets the chance to resolve. The macros hand `format_args!` the literal
//! through `concat!`, which produces a NEW literal carrying the macro's span
//! rather than the caller's. An inline capture resolves names in the span it
//! sits in, so `"peer={peer}"` looks for `peer` where this crate is written,
//! does not find it, and rustc says so:
//!
//! ```text
//!     error: there is no argument named `peer`
//! ```
//!
//! Every form of capture goes the same way — `{peer}`, and the `$`-named counts
//! `{:w$}`, `{:.p$}`, `{:>w$}` that are easy to forget are captures at all.
//! Positional `{}`, `{:>8}`, `{:.3}`, `{:?}` and `{{` are untouched.
//!
//! That replaced a hand-written const fn which scanned the literal, and the
//! replacement is worth recording because the const fn was WRONG: it read one
//! byte after `{`, took everything past a `:` for a format spec, and so allowed
//! `{:w$}` to put a runtime `usize` on the port as a pad width. A review caught
//! it by compiling. The lesson is not that the scanner needed another case — it
//! is that a hand-written parser of someone else's grammar is the wrong thing
//! to rest a guarantee on when the compiler already resolves those names itself.
//!
//! Between the three, writing an [`info!`] that discloses something takes doing
//! it on purpose, and no default has to be remembered. What cannot be vouched
//! for goes to [`debug!`], which never leaves the TEE — same visibility as
//! hiding it would give, one mechanism instead of two, and a production line
//! that reads as a sentence rather than as a row of redactions.
//!
//! Not "no path exists", though — read that sentence strictly and it is wrong.
//! `DeviceLogger` and its `claim` are `pub`, and cannot be anything else: a
//! `#[macro_export]` expansion names them from the caller's crate, so
//! `pub(crate)` is `E0603` at every external [`info!`] (`log` has the same shape
//! for the same reason, in `__private_api`). Any crate in this workspace can
//! write `DeviceLogger::claim().log(&record)` and put an arbitrary string on the
//! port.
//!
//! That is deliberate, and it is the line worth being precise about: the
//! barriers stop the person WRITING an [`info!`] from making a mistake. They do
//! not stop someone who has decided to write to the port, and in Rust nothing
//! could — the paths a macro names are paths a human can name. What the
//! constructor discipline does stop is the difference that matters: not one
//! deliberate line, but a plausible-looking `set_logger` turning the device into
//! the sink every crate in the tree writes to.
//!
//! For the deliberate-line case the guard is a grep, and the anchor is quiet:
//! `DeviceLogger` has no reason to appear outside this crate at all.
//!
//! # Who the adversary is
//!
//! Not whoever wrote the role. The launch measurement is one hash over firmware,
//! kernel, initramfs — which carries the role binary — and the command line, so
//! there is no seam along which a host edits the application and leaves the rest
//! alone. A host that changed this code is running an image nobody's attestation
//! check accepts, and a host nobody checks does not need a covert channel: it
//! can put a console back on the command line and print whatever it likes.
//!
//! So the discipline here defends against exactly one party — the consumer's
//! policy, which is adversary-chosen wasm executing inside the measured image
//! without changing it — and against ourselves writing a careless line. Those
//! want different things: the first is a real channel to reason about and lands
//! on the role that runs the policy (see [`install_panic`]); the second is what
//! the reason on each [`info!`] is for, and it is a review aid, not a control.

mod contained;
#[cfg(feature = "device")]
mod device;
mod logger;
mod macros;
mod mode;
#[cfg(feature = "device")]
mod panic;
mod vouch;

pub use enclavid_boundary::{Reason, reason};

pub use contained::install_contained;

/// Whether this build of the crate carries the outward half.
///
/// The `device` feature is what a package asks for when it may speak to the
/// host, and not asking is how the disposable children stay silent. But cargo
/// features UNIFY across an invocation, so the answer is a property of the whole
/// build rather than of one manifest: a dependency edge nobody looked at can
/// turn it on for everything, and the child that was supposed to be silent
/// quietly gains an [`info!`].
///
/// This is that answer, readable from the caller's own source — see
/// [`assert_contained!`], which is how a child states its posture as something
/// the compiler checks rather than something its manifest implies.
pub const OUTWARD_TIER: bool = cfg!(feature = "device");

/// Refuse to compile if this build carries the outward half.
///
/// For the disposable children. Their manifests do not ask for `device`, and
/// that is the intent; this is what makes it a guarantee. Feature unification
/// means the intent can be defeated from a distance — some dependency, or a
/// dependency of a dependency, asking for the outward half on its own account —
/// and the failure would be silent, because nothing breaks when a binary merely
/// GAINS the ability to write to the log device. It breaks later, when someone
/// writes an `info!` in a process that holds a round's applicant plaintext in
/// the one address space where adversary-chosen code runs.
///
/// Put it at module scope, beside the `install_contained` call it corroborates.
///
/// ```ignore
/// safe_logger::assert_contained!();
/// ```
///
/// When it fires, `cargo tree -e features -i safe-logger` names the edge that
/// turned the feature on.
#[macro_export]
macro_rules! assert_contained {
    () => {
        const _: () = assert!(
            !$crate::OUTWARD_TIER,
            "this build of safe-logger carries the outward half, and this binary is one \
             that must not: something in its dependency graph asked for the `device` \
             feature, and cargo unified it in. Find the edge with \
             `cargo tree -e features -i safe-logger`."
        );
    };
}
pub use logger::{LEVEL_KEY, Level};
pub use vouch::{Safe, SafeToLog, safe};

#[cfg(feature = "device")]
pub use device::{DEVICE_KEY, install};
#[cfg(feature = "device")]
pub use panic::install_panic;

// Reached only from the macro expansions. `__log` is the `log` crate itself:
// the expansions land in the caller's crate, where the name `log` need not
// exist, so they reach it through this path instead.
#[doc(hidden)]
pub use log as __log;
#[cfg(feature = "device")]
#[doc(hidden)]
pub use logger::DeviceLogger;
#[cfg(feature = "debug")]
#[doc(hidden)]
pub use mode::{__log_private, DebugLogger};
#[doc(hidden)]
pub use vouch::vouched;
