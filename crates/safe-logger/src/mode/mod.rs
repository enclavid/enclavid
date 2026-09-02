//! The one thing the two builds disagree about: who holds the global `log`
//! slot, and what happens to the records that arrive there.
//!
//! Everything else in the crate is the same either way — the device sink, the
//! rendering, the vouch discipline. Keeping the difference in one module means
//! the `#[cfg]` that decides it appears once, here, instead of scattered through
//! the code it changes.
//!
//! * `production` — a no-op holds the slot, and a dependency's records are
//!   dropped before they can reach a device the host reads.
//! * `debug` — [`DebugLogger`] holds it, and they are printed to stderr, which
//!   is what that image is booted for.
//!
//! A sub-module rather than two files at the crate root, because `debug` there
//! would sit beside the `debug!` macro. They live in different namespaces and
//! the compiler would not mind, but a reader would.

#[cfg(feature = "debug")]
mod debug;
#[cfg(not(feature = "debug"))]
mod production;

#[cfg(feature = "debug")]
pub use debug::__log_private;
#[cfg(feature = "debug")]
pub use debug::DebugLogger;
#[cfg(feature = "debug")]
pub(crate) use debug::slot_holder;
#[cfg(not(feature = "debug"))]
pub(crate) use production::slot_holder;
