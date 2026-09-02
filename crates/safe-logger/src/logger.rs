//! How a line is rendered, the taking of the global slot, and the threshold.
//!
//! [`DeviceLogger`] is here, behind the `device` feature, because it is the sink
//! the host reads. Its counterpart — the stderr sink that only a `debug` build
//! has — lives in [`crate::mode`], together with the no-op that stands in its
//! place otherwise, because that pair is the only thing a production build and a
//! `debug` build disagree about.
//!
//! The sinks are two channels and not two severities. Both are `log::Log` impls
//! the macros name directly, so writing an [`info!`](crate::info) or a
//! [`debug!`](crate::debug) is how a line from THIS crate picks its channel.
//! Nothing else can reach the device sink at all. The stderr one is different,
//! and deliberately: in a `debug` build it also HOLDS the global slot, so a
//! dependency's records land there — see [`crate::mode`], which is the point of
//! that build.
//!
//! What is left ungated here is what a contained process still needs: the slot
//! claim and the threshold. [`render`] sits with the sinks instead, compiled
//! only when one of them exists.

#[cfg(any(feature = "device", feature = "debug"))]
use std::fmt::Arguments;
use std::sync::Once;

#[cfg(feature = "device")]
use log::Log;

pub use log::Level;

/// Config key naming the lowest level that still gets printed — `off`, `error`,
/// `warn`, `info`, `debug` or `trace`, in any case. Absent means `trace`: say
/// everything.
///
/// Availability tuning, so it lives in config rather than in the source. It
/// cannot widen what a line may contain — every value on the channel is vouched
/// for whatever the threshold is — it can only decide how many of them survive.
///
/// Ungated, unlike [`crate::DEVICE_KEY`]: both postures set a threshold, because
/// both hold the global slot and `log`'s gate applies to whatever a dependency
/// sends through it.
pub const LEVEL_KEY: &str = "ENCLAVID_LOG_LEVEL";

/// The build fails if anything in the tree disables levels at compile time.
///
/// `log`'s `release_max_level_*` cargo features fold [`log::STATIC_MAX_LEVEL`]
/// down, and the macros test against it. Cargo features are additive and
/// resolved workspace-wide, so a dependency enabling one would silently delete
/// every `info!` from a release binary — and the guest images are release
/// builds. The failure would be a measured image that says nothing, found only
/// by booting one and noticing. This turns it into a build error in the crate
/// that cares.
const _: () = assert!(
    matches!(log::STATIC_MAX_LEVEL, log::LevelFilter::Trace),
    "a crate in this tree enabled log/release_max_level_*, which would delete \
     log lines from the measured binary"
);

/// One line, rendered.
///
/// ```text
/// [2026-08-31T10:17:16.661Z INFO ] api: listening on 8443
/// ```
///
/// A timestamp, a level word padded to five, and the message. Nothing else — no
/// module path, no target, no `file:line`, though the record now carries all
/// three correctly. Leaving them unprinted is deliberate: `install_panic` lets a
/// role withhold `file:line` — the execution worker does, because it runs the
/// consumer's wasm — and an ordinary line that carried it anyway would quietly
/// contradict that.
///
/// The level is a LABEL here and not a threshold: which macro was written
/// already decided which channel the line goes to.
///
/// `{:.3}` asks `jiff` for millisecond precision. `Timestamp::now` is plain UTC
/// — no timezone database, nothing read from the filesystem, nothing that can
/// block — which is why `jiff` is taken with `default-features = false`.
///
/// Compiled only when a sink exists to render for. With neither feature — which
/// is what a production disposable child is — nothing in the binary can produce
/// a line at all, and this says so rather than sitting there unused.
#[cfg(any(feature = "device", feature = "debug"))]
pub(crate) fn render(level: Level, args: Arguments<'_>) -> String {
    format!("[{:.3} {level:<5}] {args}\n", jiff::Timestamp::now())
}

/// The sink for the device the host reads.
///
/// Behind the `device` feature with everything else that can reach a descriptor.
/// A package that did not ask for it has no way to name this type, so the
/// paragraph below about `pub` being unavoidable is bounded by the manifest: it
/// is only reachable from a package that wrote the feature down.
///
/// # Why holding one proves the global slot is taken
///
/// The field is private, so [`claim`](DeviceLogger::claim) is the only way to
/// reach one — and it takes the global logger slot with a no-op first. "A
/// `DeviceLogger` is in hand" therefore implies "the slot is occupied", so
/// `log::set_logger(DeviceLogger::claim())` can only ever return `Err`. It
/// type-checks, since `claim` hands back the `&'static` that `set_logger` wants;
/// it just cannot succeed, because the argument could not have been evaluated
/// without closing the door first.
///
/// That matters because this type is `pub`, and cannot be anything else — a
/// `#[macro_export]` expansion names it from the caller's crate. Without the
/// constructor, one plausible-looking line, `log::set_logger(&DeviceLogger)`,
/// would turn the device into the sink every crate in the tree writes to, and
/// the only thing stopping it would be that `install` happens to run first.
/// This replaces that ordering claim with a structural one.
///
/// # Why it renders the line itself
///
/// The line is built whole into a fresh `String`, then handed to
/// [`crate::device::emit`], which takes a lock around a single `write` and
/// nothing else. Two properties follow, and each is a defect avoided rather
/// than a preference:
///
/// * **The sinks share nothing.** `env_logger`, which used to be both, renders
///   into a scratch buffer held in a `thread_local!` declared inside
///   `Logger::log` — one per thread for the whole process, shared by every
///   instance — and clears it only on the normal return path. Two instances on
///   one thread therefore share a container while choosing their destination
///   per call: an unwind out of a `Display` leaves the private tier's bytes in
///   the buffer, and the next line here sends the whole buffer to the host.
///   Allocating per line costs a `malloc` and removes the container.
/// * **No foreign code runs while anything is held.** The `Display` impls of
///   the arguments run inside `format!`, before any lock exists. A panic there
///   loses one line and touches nothing else. The lock is held across a `write`
///   that cannot panic, so it can never be poisoned — which is the failure
///   `simplelog` has, formatting under its writer lock.
///
/// Nothing is reimplemented to get this. `jiff` formats the time, `log::Level`
/// formats the word, `format!` does the layout, `write` writes.
#[cfg(feature = "device")]
#[doc(hidden)]
pub struct DeviceLogger(());

#[cfg(feature = "device")]
impl DeviceLogger {
    /// The only way to reach one. Takes the global slot first — see the type.
    ///
    /// One `static` rather than a value per call, though the difference is
    /// nominal: the type is zero-sized, so constructing it emits no
    /// instructions and the reference is the larger of the two.
    #[doc(hidden)]
    pub fn claim() -> &'static Self {
        static LOGGER: DeviceLogger = DeviceLogger(());

        claim_the_global_slot();
        &LOGGER
    }
}

#[cfg(feature = "device")]
impl Log for DeviceLogger {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        crate::device::emit(render(record.level(), *record.args()).as_bytes());
    }

    fn flush(&self) {}
}

/// Take the one global logger slot, so that nothing else ever can.
///
/// `rustls`, `wasmtime` and `tracing` are in this tree and already call the
/// `log` facade. Their records die today because nobody has registered a logger
/// — which is not a property, only a fact about the current code.
/// `log::set_logger` succeeds exactly once (a `compare_exchange` from
/// `UNINITIALIZED`) and every later caller gets `Err(SetLoggerError)`. Filling
/// the slot turns "nobody has" into "nobody can": no crate, and no careless
/// future line here, can put something that writes to stdout there — and in the
/// `debug` image stdout is the port.
///
/// **What fills it depends on the build, and that is the point.** See
/// [`crate::mode`], which is the only place that `#[cfg]` appears: a production
/// build drops a dependency's records, a `debug` build prints them to stderr.
/// `ENCLAVID_LOG_LEVEL` is the tap — see [`set_threshold_from_config`] — and
/// that is the reason the knob is worth having at all.
///
/// The mismatched pairing stays safe: a `debug` binary booted with a production
/// command line writes those records to stderr, which `console=null` discards,
/// while this crate's own vouched lines still go to the named device.
///
/// Called from four places, and the `Once` is why that is cheap: both installers
/// at boot ([`crate::install`] and [`crate::install_contained`]), so the slot is
/// denied even in a role that never logs, and each sink's `claim`, so it is
/// denied even if a process reordered its installer away from the first line of
/// `main` — or never called one.
///
/// The result is deliberately ignored: a second call means someone else got
/// there first, and there is nothing useful to do about it — least of all
/// print, on a channel this function exists to protect. What that costs is
/// bounded by the constructor discipline above: whoever won the race, it was
/// not one of this crate's sinks, because neither can exist until after this
/// has run.
///
/// Only the slot. The threshold that decides whether a line survives is a
/// separate concern and a separate call — see [`set_threshold_from_config`].
pub(crate) fn claim_the_global_slot() {
    static ONCE: Once = Once::new();

    ONCE.call_once(|| {
        let _ = log::set_logger(crate::mode::slot_holder());
    });
}

/// Open `log`'s own level gate, which is shut until someone opens it.
///
/// Not a threshold of ours: the macros expand to `log::log!`, which tests
/// `lvl <= max_level()` before reaching either sink, and `MAX_LOG_LEVEL_FILTER`
/// starts at `Off`. Without this call the crate prints nothing at all.
///
/// It is read from the config the guest was launched with, which for a role is
/// the measured kernel command line — so the posture is part of the hash and a
/// verifier can see it. That is the difference from `RUST_LOG`, which this crate
/// deliberately ignores: one is attested configuration, the other is a string
/// the host may set at run time.
///
/// Absent means [`log::LevelFilter::Trace`] — say everything. Named but
/// unparseable ends the process, the same answer [`crate::install`] gives to a
/// device it was told to open and could not: a role told to be observable in a
/// particular way, and not being, is the state this crate exists to remove.
///
/// Any crate may write the same global afterwards. Doing so can silence this
/// channel; it cannot put anything on it.
///
/// Opening the gate is not free, and the cost lands on everyone else: `log`'s
/// `__private_api::log_impl` does not consult `Log::enabled`, so a dependency's
/// `log::trace!` builds a `Record` and makes one indirect call into whatever
/// holds the slot rather than short-circuiting on the integer compare. `rustls`
/// on every handshake and `wasmtime` while compiling are the ones that do it
/// here. The message is never formatted — `format_args!` is lazy and the
/// `Arguments` is only stored — so it is a few stack stores and a discarded
/// call, tens to hundreds of times per session.
pub(crate) fn set_threshold_from_config() {
    let level = match std::env::var(LEVEL_KEY) {
        Ok(named) => match named.parse() {
            Ok(level) => level,
            // Before the device is open there is nowhere to say why, and after
            // it is open this line might be the one the threshold suppressed.
            Err(_) => std::process::exit(70),
        },
        Err(_) => log::LevelFilter::Trace,
    };

    log::set_max_level(level);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape of a line is ours, so it is worth pinning.
    #[test]
    fn a_line_is_a_timestamp_a_padded_level_and_the_message() {
        let line = render(Level::Info, format_args!("api: listening on {}", 8443));

        assert!(line.starts_with('['), "{line:?}");
        assert!(
            line.ends_with(" INFO ] api: listening on 8443\n"),
            "{line:?}"
        );
        assert_eq!(line.matches('\n').count(), 1, "{line:?}");
        // No module path, no target, no file:line — see `render`.
        assert!(!line.contains("safe_logger"), "{line:?}");

        assert!(render(Level::Error, format_args!("x")).contains(" ERROR] "));
    }

    /// The regression test for the defect that took the sinks off `env_logger`:
    /// a `Display` that unwinds must leave no bytes anywhere. It cannot, because
    /// the panic escapes before a line exists to be written — there is no
    /// buffer holding a half-rendered line for a later write to pick up.
    #[test]
    fn a_panicking_display_never_produces_a_line() {
        struct Boom;

        impl std::fmt::Display for Boom {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("SESSION-abc123")?;
                panic!("a Display impl that unwinds mid-render");
            }
        }

        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let rendered = std::panic::catch_unwind(|| render(Level::Debug, format_args!("{Boom}")));
        std::panic::set_hook(previous);

        assert!(rendered.is_err(), "render returned instead of unwinding");
    }

    /// Reaching a sink proves the slot is gone, so the device can never become
    /// the logger every crate in the tree writes to. Written the shortest way it
    /// could be written by mistake — `claim` returns the `&'static` that
    /// `set_logger` takes, so this compiles and must still fail.
    #[cfg(feature = "device")]
    #[test]
    fn a_sink_cannot_be_registered() {
        assert!(
            log::set_logger(DeviceLogger::claim()).is_err(),
            "the slot was still free once a DeviceLogger was in hand"
        );
    }
}
