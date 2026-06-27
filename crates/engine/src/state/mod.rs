//! wasmtime `Store<T>` data layer.
//!
//! Each component running under the engine — the policy and every
//! plugin it composes with — lives in its own wasmtime `Store`. The
//! `T` placed inside that Store is the only state wasm host calls and
//! the runtime composer can reach. Two flavours exist:
//!
//!   * [`host::HostState`] for the policy reducer. Carries the static
//!     `context.props`, the per-component `enclavid:embedded/*`
//!     registry, memory limits, and the composer proxy table. The
//!     `context.props` `Host` impl and the empty pure-types `Host`
//!     impls live in [`host`]; the embedded-resolver `Host` impls live
//!     in [`crate::embedded::host`].
//!
//!   * [`plugin::PluginHostState`] for each plugin component. Minimal:
//!     the composer proxy table, memory limits, and the shared embedded
//!     registry feeding the slot-bound resolve closures.
//!
//! [`host::RunInputs`] is the per-run input bag the api crate hands to
//! [`Runner::run`](crate::Runner::run) — distinct from "WIT resources"
//! by name so the two concepts don't collide in reading.

pub(crate) mod host;
pub(crate) mod plugin;

pub use host::{HostState, RunInputs};
pub use plugin::PluginHostState;
