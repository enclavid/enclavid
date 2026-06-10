//! Call interception + replay machinery.
//!
//! Two halves working together:
//!
//!   * [`shim`] — a thin wrapper around `wasmtime::component::Linker`
//!     that injects intercept logic around every host function
//!     registration. `bindgen!` generates host imports against this
//!     shim (via the `wasmtime_crate: crate::intercept::shim`
//!     directive), so all typed host calls are wrapped without any
//!     downstream code changes.
//!
//!   * [`replay`] — the per-run journal of host calls. Each typed call
//!     is keyed by `(fn_name, args_hash)` and either replayed from a
//!     cached `Completed` event or executed live and journaled. The
//!     shim consults [`replay::Replay::next`] before invoking the
//!     user-supplied closure and [`replay::Replay::write`] after.
//!
//! Both halves operate on [`crate::state::HostState`] — `Replay` is a
//! field of `HostState`, and the shim's accessor closure returns a
//! borrowed view of (`Replay`, pending disclosures, listener) from it.

pub mod replay;
pub mod shim;
