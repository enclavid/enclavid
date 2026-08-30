//! The one channel a role binary may say anything on, and everything on it is
//! public.
//!
//! A guest's serial port is read by the host, so a line written here has left
//! the TEE. That is the same crossing the wire perimeter governs, so it uses the
//! same vocabulary: a line is an [`Exposed`] value and reaches the port only
//! once its concerns are closed with a written [`reason!`]. What the measured
//! image buys is that a reviewer can read every [`log!`] site in it and know the
//! complete set of things that can ever be printed.
//!
//! # The invariant underneath
//!
//! By default a guest emits nothing. `console=null` on the measured command line
//! points `/dev/console` — which PID 1 hands the application as fds 0, 1 and 2 —
//! at a console that discards. So `println!` from any crate in the tree, a
//! panic payload, and output from C libraries all go nowhere. Only code that
//! opens the device itself reaches the host, and that is this module.
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
//! keeps going to the discarding console, which is where it already went.
//!
//! The cost is real and is paid deliberately: a dependency that fails loudly on
//! stderr says nothing here. Where the message matters, the site emits a
//! [`log!`] itself.
//!
//! # Who the adversary is
//!
//! Not whoever wrote the role. The launch measurement is one hash over firmware,
//! kernel, initramfs — which carries the role binary — and the command line, so
//! there is no seam along which a host edits the application and leaves the rest
//! alone. A host that changed this code is running an image nobody's attestation
//! check accepts, and a host nobody checks does not need a covert channel: it can
//! put a console back on the command line and print whatever it likes.
//!
//! So the discipline here defends against exactly one party — the consumer's
//! policy, which is adversary-chosen wasm executing inside the measured image
//! without changing it — and against ourselves writing a careless line. Those
//! want different things: the first is a real channel to reason about and lands
//! on the role that runs the policy (see [`install_panic`]); the second is what
//! the reason on each [`log!`] is for, and it is a review aid, not a control.

use std::fmt::Arguments;
use std::sync::OnceLock;

pub use enclavid_boundary::{Covert, Exposed, Reason, reason};

/// Config key naming the device to write to. Absent means no output — the
/// ordinary case off a guest, where stderr already goes somewhere a developer
/// can read.
pub const DEVICE_KEY: &str = "ENCLAVID_LOG_DEVICE";

/// The release point for this channel — the counterpart of
/// `hatch_client::boundary::outbound` for the port instead of the wire. Grep it
/// to find where lines are minted; grep [`log!`] to find every one of them.
///
/// The scope is `(Covert,)` and the two axes the wire carries are absent rather
/// than vouched away, because neither is a question here:
///
/// * Confidentiality to the intended recipient — there is none, by design. The
///   host is the recipient and reads plaintext. A per-line vouch would assert
///   something untrue.
/// * Authorization to release — settled by the channel existing. The port is
///   there to be read; nothing about one line changes that.
///
/// What is left is the only thing that varies from site to site: whether what is
/// said depends on anything the applicant or the policy influenced. That
/// includes whether the line APPEARS at all — a constant string emitted once per
/// plugin call still reports which plugins ran.
pub fn line(args: Arguments<'_>) -> Exposed<Arguments<'_>, (Covert,)> {
    Exposed::new(args)
}

/// What a severity prefix renders as. A LABEL, not a level: nothing filters on
/// it, nothing routes on it, and there is no threshold to set. It exists so a
/// human reading the port can find trouble without reading every line.
///
/// Ordinary lines carry no prefix at all, so anything prefixed is by definition
/// something that went wrong — cheaper to scan than a column of `INFO`.
///
/// Colour only under `debug`, which is the build where a human is watching a
/// terminal. A production port is read into a file or a collector, and escape
/// bytes there are litter. `isatty` cannot decide this for us: the descriptor is
/// a serial device, so it is a terminal whatever the host does with the other
/// end.
#[doc(hidden)]
pub mod prefix {
    #[cfg(feature = "debug")]
    pub const WARN: &str = "\x1b[33mWARN\x1b[0m ";
    #[cfg(feature = "debug")]
    pub const ERROR: &str = "\x1b[31mERROR\x1b[0m ";

    #[cfg(not(feature = "debug"))]
    pub const WARN: &str = "WARN ";
    #[cfg(not(feature = "debug"))]
    pub const ERROR: &str = "ERROR ";
}

/// Put one fully vouched line in front of the host.
///
/// With no [`DEVICE_KEY`] there is no device, and the line goes to stderr
/// instead of being dropped. That is not a second channel — it is the same
/// destination the port already is on the two builds that have no device named:
/// a developer's terminal, and the `debug` image, whose `console=ttyS0` puts
/// stderr on the very same port. On a production guest the device is always
/// named, so the fallback never runs; and were it somehow missing, stderr there
/// is `ttynull` and the line still goes nowhere.
pub fn emit(line: Exposed<Arguments<'_>, ()>) {
    let args = line.into_inner();
    match SINK.get() {
        Some(sink) => sink.line(args),
        None => eprintln!("{args}"),
    }
}

/// Log one line to the host, with the reason it carries no hidden bandwidth.
///
/// Expands to a [`line`] mint, a `vouch_unchecked::<Covert>` with the given
/// reason, and [`emit`]. The vouch is inside the macro so the ordinary case
/// stays one readable line and so `format_args!` keeps borrowing within a single
/// expression; the cost is that this site does not answer a
/// `vouch_unchecked::<` grep, which is why `log!` is listed beside it in the
/// perimeter's reviewer guide.
///
/// [`warn!`] and [`error!`] are this with a prefix. They behave identically —
/// same channel, same reason requirement — and the difference is the word, for
/// whoever reads the port. The prefix adds no bandwidth: it is fixed per site,
/// so it says nothing the line's presence did not already say.
#[macro_export]
macro_rules! log {
    ($reason:expr, $($arg:tt)*) => {{
        $crate::emit(
            $crate::line(format_args!($($arg)*))
                .vouch_unchecked::<$crate::Covert, _>($reason),
        );
    }};
}

/// [`log!`], marked as something that went wrong but is being handled.
#[macro_export]
macro_rules! warn {
    ($reason:expr, $($arg:tt)*) => {
        $crate::log!($reason, "{}{}", $crate::prefix::WARN, format_args!($($arg)*))
    };
}

/// [`log!`], marked as something that went wrong and is not being handled.
#[macro_export]
macro_rules! error {
    ($reason:expr, $($arg:tt)*) => {
        $crate::log!($reason, "{}{}", $crate::prefix::ERROR, format_args!($($arg)*))
    };
}

/// Say something on the way to a developer, never to the host.
///
/// Goes to stderr, which a production guest points at a discarding console — and
/// under a build without `debug` the call is not compiled at all, so the strings
/// are not in the binary and nothing runs. That second half is why this needs no
/// reason: there is nothing to disclose, by construction rather than by a
/// console setting being right.
///
/// The distinction from a bare `eprintln!` is not where it goes — that is
/// identical — but that this is ours and enumerable. Turning the `debug` build
/// on shows what we chose to say; `eprintln!` in the tree is whatever every
/// dependency chose to say.
#[cfg(feature = "debug")]
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => { eprintln!($($arg)*) };
}

#[cfg(not(feature = "debug"))]
#[macro_export]
macro_rules! debug {
    // Dead by the language rather than by the optimiser: `if false` is a
    // constant condition, so the branch never runs in any profile. It is kept
    // instead of expanding to nothing so that a binding used only by a `debug!`
    // still counts as used — without it every such site raises an
    // unused-variable warning in the measured build, and thirteen of those hide
    // the one that matters.
    //
    // Two separate guarantees, worth not conflating. That nothing RUNS is the
    // language's: a constant condition, in any profile, whatever the optimiser
    // decides. That the format string is not in the binary is the optimiser's —
    // measured on a release build, the literal is dropped as unreferenced. The
    // first is what the measured image rests on; the second is a bonus, and
    // would cost nothing if it ever stopped holding, since the image is
    // reproducible from public source and its literals are readable anyway.
    ($($arg:tt)*) => {{
        if false {
            let _ = format_args!($($arg)*);
        }
    }};
}

static SINK: OnceLock<Sink> = OnceLock::new();

#[cfg(target_os = "linux")]
mod imp {
    use super::{DEVICE_KEY, SINK, Sink};
    use std::fmt::Arguments;

    /// Open the channel.
    ///
    /// Call it first in `main`, before anything that could want to say
    /// something. Absent [`DEVICE_KEY`] leaves the process exactly as it was —
    /// that is a developer's box, where stderr is already readable.
    ///
    /// A device that is named but cannot be opened ends the process. There is no
    /// sensible way to report that failure, which is precisely why it must not
    /// be survivable: a role that was told to be observable and is not would run
    /// silently, and that is the state this whole module exists to remove.
    pub fn install() {
        let Ok(device) = std::env::var(DEVICE_KEY) else {
            return;
        };
        let fd = unsafe {
            libc::open(
                std::ffi::CString::new(device)
                    .expect("device path")
                    .as_ptr(),
                // O_NOCTTY: a serial port is a terminal, and a session leader
                // that opens one without this adopts it as its controlling
                // terminal. That would give the far end — the host — a way to
                // deliver SIGINT/SIGQUIT/SIGHUP into this process group, turning
                // a write-only disclosure into something with a direction back.
                libc::O_WRONLY | libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            // Before the sink exists there is nowhere to say why.
            std::process::exit(70);
        }
        let _ = SINK.set(Sink { fd });
    }

    /// Report panics on the channel, with or without naming where.
    ///
    /// A panic's default hook writes to stderr, which on a guest is the
    /// discarding console, so without this a crash is silent. The payload never
    /// travels either way: `unwrap` on an arbitrary error formats that error,
    /// and what an error quotes is not knowable from here.
    ///
    /// `with_location` decides between `panic at <file>:<line>` and a bare
    /// `panicked`, and the split follows who can steer the choice of site.
    ///
    /// `file:line` is a constant of the measured image, so the strings are fixed
    /// and public; what a reader learns is WHICH of them was reached, and that
    /// is selected by control flow. In a role whose code is the measured code —
    /// api, storage, the compile worker — the only party that could aim that
    /// selection at a secret is whoever wrote the role, and rewriting the role
    /// changes the measurement. There the location is free and worth having.
    ///
    /// The execution worker is the exception and the reason this is a parameter:
    /// it runs the consumer's policy, adversary-chosen wasm that executes inside
    /// the measured image without altering it. A site reached because of what
    /// the policy did is a site the policy chose. It passes `false`.
    ///
    /// Separate from [`install`] so each name is true, and safe to forget: a
    /// role that omits this call says less, never more.
    pub fn install_panic(with_location: bool) {
        std::panic::set_hook(Box::new(move |info| {
            // Not `log!`: the reason for a panic report is written once, here,
            // rather than at a site that by definition nobody chose.
            let vouched = |args: Arguments<'_>| {
                super::emit(
                    super::line(args).vouch_unchecked::<super::Covert, _>(super::reason!(
                        "either a constant or a source location fixed by the measured image; \
                     which one is reached is control flow, and only code inside the \
                     measurement can aim that — except in the role running the consumer's \
                     policy, which passes with_location = false"
                    )),
                )
            };
            if !with_location {
                vouched(format_args!("panicked"));
                return;
            }
            let at = info
                .location()
                .map(|l| format!("{}:{}", l.file(), l.line()))
                .unwrap_or_else(|| "unknown".to_string());
            vouched(format_args!("panic at {at}"));
        }));
    }

    impl Sink {
        pub(super) fn line(&self, args: Arguments<'_>) {
            let text = format!("{args}\n");
            // Non-blocking, and a short write is not retried. A full sink must
            // never stall the role — losing lines under pressure is the cheaper
            // failure.
            unsafe {
                libc::write(self.fd, text.as_ptr() as *const libc::c_void, text.len());
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    /// Off Linux there is no guest and no device: leave the process alone so a
    /// developer keeps their terminal.
    pub fn install() {}

    /// Likewise — the default hook already prints where a developer can read it.
    pub fn install_panic(_with_location: bool) {}
}

pub use imp::{install, install_panic};

struct Sink {
    #[cfg(target_os = "linux")]
    fd: std::os::fd::RawFd,
}

#[cfg(not(target_os = "linux"))]
impl Sink {
    fn line(&self, _args: Arguments<'_>) {}
}

// SAFETY: the descriptor is opened once and only ever written to.
unsafe impl Send for Sink {}
unsafe impl Sync for Sink {}
