//! `rpc` — intra-fleet RPC substrate: remote trait calls (remoc `rtc`) over
//! any `AsyncRead + AsyncWrite` byte stream — a host vsock relay today, an
//! RA-TLS tunnel over that relay later. The transport is abstract (remoc's
//! [`Connect::io`](remoc::Connect::io) frames + multiplexes over the raw
//! stream), so the same service definitions work at every stage of the CVM
//! split. CBOR codec ([`remoc::codec::Ciborium`]) keeps the named-field schema
//! evolution `broker-protocol` already relies on across independently-deployed
//! nodes.
//!
//! Chosen over a thin hand-rolled protocol and over tarpc — see the
//! `project_fleet_rpc_substrate` memory: remoc's marginal footprint over the
//! existing tree is one runtime crate, it is no-OpenTelemetry / ciborium /
//! tokio-native, and its native mid-call callbacks (a callback client passed as
//! a method argument, multiplexed by chmux) are exactly what the execute
//! boundary needs without a hand-rolled request-id duplex.
//!
//! ## Two features, one contract
//!
//! The contract is split under two cargo features so a single-role worker
//! links only its half (least-knowledge for its measured image):
//!
//!   * `compile` → `CompilerService` + `CompileError`; the worker fuses +
//!     Cranelift-compiles into a `CompiledBundle`.
//!   * `execute` → `ExecutorService` + `CallbackService` + the execute wire
//!     types (`RunRequest`, `RunReply`, `RunStatus`, `Prop`, `ExecError`,
//!     `CallbackError`); pulls `broker-client`.
//!
//! The compiled artifact ([`CompiledBundle`] / [`CatalogEntry`]) is SHARED: it
//! is the compile OUTPUT and the execute priming INPUT (and the api L2 cache
//! entry), so it lives ungated in `bundle` and both features name it. Both
//! features pull `engine-types` — the compile side for `PluginInstance`, the
//! execute side for the composition catalogs it rebuilds the embedded registry
//! from. Neither pulls Cranelift.
//!
//! `remoc` (the rtc substrate) is pulled by either feature. A compile-worker
//! (or the orchestrator's compile client) builds
//! `--no-default-features --features compile`; an execution-worker uses
//! `execute`. `default = [compile, execute]` keeps both halves compiled +
//! tested in whole-workspace builds (unification there is harmless).
//!
//! Adversarial-peer hardening lives in the connection [`remoc::Cfg`] (pin
//! `chmux::Cfg` limits: `max_ports`, `max_data_size` — RAISE from the 512 KiB
//! default for the compile boundary, cwasm bundles are ~10–15 MiB —
//! `max_received_ports`, `connection_timeout`) plus per-service handler
//! validation (hash-bound media loads, bounded session-change).

// The compiled artifact — shared by BOTH boundaries (compile output, execute
// prime input, api L2 cache entry).
#[cfg(any(feature = "compile", feature = "execute"))]
mod bundle;
#[cfg(any(feature = "compile", feature = "execute"))]
pub use bundle::*;

#[cfg(feature = "compile")]
mod compile;
#[cfg(feature = "compile")]
pub use compile::*;

#[cfg(feature = "execute")]
mod execute;
#[cfg(feature = "execute")]
pub use execute::*;

/// The remoc connection config both fleet peers build from. Raises
/// `max_data_size` from chmux's 512 KiB default: compiled `cwasm` bundles
/// run ~10–15 MiB, so the default would reject a compile reply outright.
/// Centralized so orchestrator + workers agree on the limits — part of the
/// adversarial-peer hardening surface (see the crate doc). `remoc::Cfg` is a
/// re-export of `chmux::Cfg`, so the field is flat.
#[cfg(any(feature = "compile", feature = "execute"))]
pub fn connection_cfg() -> remoc::Cfg {
    let mut cfg = remoc::Cfg::default();
    cfg.max_data_size = 64 * 1024 * 1024;
    cfg
}
