//! The `debug` build: records go to stderr, and the whole dependency tree is
//! let through.

use log::Log;

use crate::logger::{claim_the_global_slot, render};

/// The sink for stderr, which never leaves the TEE. What `debug!` expands to,
/// and — in this build — what holds the global slot.
///
/// Holding the slot is why `rustls` and `wasmtime` become visible here. The
/// `debug` image already carries the whole kernel log and this crate's own
/// unvouched `debug!` lines, so a dependency explaining a failed handshake is
/// not a new category on that wire; it is the diagnostic someone booted the
/// image to read. `ENCLAVID_LOG_LEVEL` is the tap.
///
/// Same constructor discipline as `DeviceLogger`, but not for the same reason,
/// and the difference is worth stating so nobody reads more into it. Registering
/// THIS sink is a smaller mistake: it writes to stderr, and stderr never reaches
/// the production device — there `ENCLAVID_LOG_DEVICE` is named and the device
/// module writes to the descriptor instead. What the claim is
/// really for is the general property rather than this type: the slot must be
/// denied to EVERYONE, and a build that only ever calls `debug!` and never
/// `install` would otherwise leave it open for something that writes to stdout —
/// which in this image is the port.
///
/// `stderr()` serialises its own writes, so unlike the device this needs no lock
/// of its own. It appends `file:line`, which the device sink does not: nothing
/// here leaves the TEE, and a developer reading a `debug!` wants to know where it
/// came from. A foreign record brings its own, so the line names the dependency's
/// source file rather than ours.
#[doc(hidden)]
pub struct DebugLogger(());

impl DebugLogger {
    /// The only way to reach one. Takes the global slot first.
    #[doc(hidden)]
    pub fn claim() -> &'static Self {
        static LOGGER: DebugLogger = DebugLogger(());

        claim_the_global_slot();
        &LOGGER
    }
}

impl Log for DebugLogger {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        use std::io::Write;

        let mut line = render(record.level(), *record.args());
        if let (Some(file), Some(number)) = (record.file(), record.line()) {
            line.pop();
            line.push_str(&format!("   ({file}:{number})\n"));
        }
        let _ = std::io::stderr().write_all(line.as_bytes());
    }

    fn flush(&self) {}
}

/// What fills the global slot in this build.
///
/// Reached as a `static` rather than through [`DebugLogger::claim`], which would
/// call back into `claim_the_global_slot` and re-enter its `Once`.
pub(crate) fn slot_holder() -> &'static dyn Log {
    static SLOT: DebugLogger = DebugLogger(());

    &SLOT
}

/// What `debug!` and `trace!` expand to.
///
/// A direct call rather than `log::log!`, so it works in a process that never
/// installed anything — see the macro for why that matters. `file` and `line`
/// come from the call site, which is where the macro expanded.
#[doc(hidden)]
pub fn __log_private(level: log::Level, args: std::fmt::Arguments<'_>, file: &str, line: u32) {
    DebugLogger::claim().log(
        &log::Record::builder()
            .level(level)
            .args(args)
            .file(Some(file))
            .line(Some(line))
            .build(),
    );
}
