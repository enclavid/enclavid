//! wasmtime `Store<T>` data layer.
//!
//! Each component running under the engine — the policy and every
//! plugin it composes with — lives in its own wasmtime `Store`. The
//! `T` placed inside that Store is the only state wasm host calls and
//! the runtime composer can reach. Two flavours exist:
//!
//!   * [`host::HostState`] for the policy. Carries the replay log,
//!     pending disclosures, the session listener, the registered
//!     text-ref set, memory limits, and the composer proxy table.
//!     Bindgen-generated `Host` trait impls live in
//!     [`crate::host`] and operate on this type.
//!
//!   * [`plugin::PluginHostState`] for each plugin component. Minimal:
//!     only the composer proxy table and memory limits. Plugins are
//!     pure compute and import zero host functions, so there is no
//!     surface for replay or listener interaction inside their Stores.
//!
//! [`host::RunInputs`] is the per-run input bag the api crate hands
//! to [`HostState::new`](host::HostState::new) — distinct from "WIT
//! resources" by name so the two concepts don't collide in reading.

pub(crate) mod host;
pub(crate) mod plugin;

pub use host::{HostState, RunInputs};
pub use plugin::PluginHostState;
