//! The measured build: whatever reaches the global slot is dropped there.

use log::Log;

/// Accepts every record the `log` facade hands it and drops the lot.
///
/// This is the barrier, not a placeholder. `rustls`, `wasmtime` and `tracing`
/// all call the facade; without something in the slot their records would die
/// only because nobody had registered a logger, which is a fact about today's
/// dependency list rather than a property. With this in it, no crate — and no
/// careless future line in this one — can put something there that writes to a
/// descriptor the host reads.
struct NoopLogger;

impl Log for NoopLogger {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        false
    }

    fn log(&self, _: &log::Record<'_>) {}

    fn flush(&self) {}
}

/// What fills the global slot in this build.
pub(crate) fn slot_holder() -> &'static dyn Log {
    static SLOT: NoopLogger = NoopLogger;

    &SLOT
}
