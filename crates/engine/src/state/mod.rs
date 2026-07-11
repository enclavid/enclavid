//! wasmtime `Store<T>` data layer.
//!
//! The policy reducer runs in a wasmtime `Store<HostState>`. The `T`
//! placed inside that Store is the only state wasm host calls can
//! reach. [`host::HostState`] carries the static `context.props`, the
//! per-component `enclavid:embedded/*` registry, and memory limits.
//! The `context.props` `Host` impl and the empty pure-types `Host`
//! impls live in [`host`]; the embedded-resolver `Host` impls live in
//! [`crate::embedded::host`].
//!
//! [`host::RunInputs`] is the per-run input bag the api crate hands to
//! [`Runner::run`](crate::Runner::run) — distinct from "WIT resources"
//! by name so the two concepts don't collide in reading.

pub(crate) mod host;
pub(crate) mod kv;

pub use host::{HostState, RunInputs};
