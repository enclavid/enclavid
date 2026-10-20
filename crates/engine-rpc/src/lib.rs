//! `engine-rpc` — the ENGINE fleet's compile/execute RPC contract: remote trait
//! calls (remoc `rtc`) between the orchestrator and the compile/execution
//! workers, over any `AsyncRead + AsyncWrite` byte stream — a host vsock relay
//! today, an RA-TLS tunnel over that relay later. It is engine-only: the hatch
//! has a contract of its own, `hatch-rpc`, on the same substrate — remoc is
//! the boundary where both ends are our own attested Rust CVMs; what the
//! operator implements, its hooks, is plain HTTP. The transport is abstract
//! (remoc's [`Connect::io`](remoc::Connect::io) frames + multiplexes over the raw
//! stream), so the same service definitions work at every stage of the CVM
//! split. CBOR codec ([`remoc::codec::Ciborium`]) keeps the named-field schema
//! evolution the fleet relies on across independently-deployed nodes.
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
//!   * `compile` → `RemoteCompiler` + `CompileError`; the worker fuses +
//!     Cranelift-compiles into a `CompiledBundle`.
//!   * `execute` → `RemoteExecutor` + `RemoteCallbacks` + the execute wire
//!     types (`RunRequest`, `RunReply`, `RunStatus`, `ExecError`,
//!     `CallbackError`) + `BundleStream` — the bundle a `run_with_bundle`
//!     carries, streamed beside the request; pulls `session-types` and
//!     `fleet-stream`.
//!
//! The compiled artifact ([`CompiledBundle`] / [`CatalogEntry`]) is SHARED: it
//! is the compile OUTPUT, the api L2 cache entry, and what the execute door
//! installs on a worker after a cache miss, so it lives ungated in `bundle` and
//! both features name it. Both features pull `engine-types` — the compile side
//! for `PluginInstance`, the execute side for the composition catalogs it
//! rebuilds the embedded registry from. Neither pulls Cranelift.
//!
//! `remoc` (the rtc substrate) and `enclavid-boundary` (the concern vocabulary
//! the doors are written in) are pulled by either feature. A compile-worker
//! (or the orchestrator's compile client) builds
//! `--no-default-features --features compile`; an execution-worker uses
//! `execute`. `default = [compile, execute]` keeps both halves compiled +
//! tested in whole-workspace builds (unification there is harmless).
//!
//! The vocabulary is deliberately NOT a third axis. It was one, and the axis
//! bought nothing: the crate is a dependency-free leaf already linked by every
//! image through the logger, so the only thing selecting it decided was whether
//! a leg had a door at all — and a door that can be compiled away is not one.
//! What a hop may carry, and the words that say so, arrive together.
//!
//! Adversarial-peer hardening lives in the connection [`remoc::Cfg`] (pin
//! `chmux::Cfg` limits: `max_ports`, `max_received_ports`, `chunk_size`,
//! `connection_timeout`; `max_data_size` is raised too, but it is not a size
//! limit — the per-item cap is remoc's) plus per-service handler validation
//! (hash-bound media loads, bounded session-change, bundle streams held to
//! their header).

// The compiled artifact — shared by BOTH boundaries (compile output, api L2
// cache entry, what the execute door streams to a worker on a miss).
#[cfg(any(feature = "compile", feature = "execute"))]
mod bundle;
#[cfg(any(feature = "compile", feature = "execute"))]
pub use bundle::*;

#[cfg(feature = "compile")]
mod compile;
// EXPLICIT, not a glob, for the same reason the execute half is: neither
// `RemoteCompilerClient` nor its server half is re-exported, so no crate outside
// this one can name the generated client for the api hop — let alone call it — and
// none can serve the RAW contract either. Both ends reach the hop through `leg`,
// each at the end its role declares: `RemoteCompilerCalls` / `RemoteCompilerServes`
// are what an end declares, and `RemoteCompilerAt` the contract as its server sees
// it there.
#[cfg(feature = "compile")]
pub use compile::{
    Artifact, COMPILE_STREAM_DEADLINE, COMPILE_STREAM_IDLE, CompileError, CompileFault,
    CompileReply, CompileRequest, CompileSource, InterfaceName, MAX_COMPONENTS_BYTES, PluginLength,
    RemoteCompilerAt, RemoteCompilerCalls, RemoteCompilerServes,
};

// The two names a cache slot is addressed by, as types that carry their own
// shape check. Both cross the execute hop, and only it.
#[cfg(feature = "execute")]
mod keys;
#[cfg(feature = "execute")]
pub use keys::{CompatToken, CompositionKey, KeyError};

#[cfg(feature = "execute")]
mod execute;
// EXPLICIT, not a glob, and that is the point — in BOTH directions. Outbound,
// `RemoteExecutorClient` and its server half are absent, so no crate outside
// this one can name the generated client for this hop, let alone call it.
// Inbound, `RemoteCallbacksServerShared` is absent too, so nobody outside can
// serve the RAW callback contract: the only way to answer these callbacks is to
// implement `RemoteCallbacksAt` at a declared end and hand it to the door.
// And `RemoteCallbacksClient` is absent, so the role that calls them back has
// only `Callbacks` at its end to call them through. A wrapper a caller opts into
// is a habit; a wrapper with no unwrapped alternative is a boundary.
//
// `*Calls` / `*Serves` are what an end of this hop declares, and `*Serve` the
// contract as its server sees it at that end — all three written by
// `#[protocol]` from the contract itself, so a method added to it reaches them
// without anyone remembering to.
#[cfg(feature = "execute")]
pub use execute::{
    ByteBuf, CallbackError, Committed, ExecError, MediaBytes, MediaHash, PrepareOutcome,
    PrepareReply, PrepareRequest, Preparing, PropsRead, RemoteCallbacks, RemoteCallbacksAt,
    RemoteCallbacksCalls, RemoteCallbacksServes, RemoteChild, RemoteChildCallbacks,
    RemoteChildCallbacksClient, RemoteChildCallbacksServerShared, RemoteChildClient,
    RemoteChildServerShared, RemoteExecutorAt, RemoteExecutorCalls, RemoteExecutorServes,
    RoundProps, RunOutcome, RunReply, RunRequest, RunStatus,
};

// Both ends of the execute hop, and the doors on the calling end.
#[cfg(any(feature = "compile", feature = "execute"))]
mod leg;
#[cfg(feature = "execute")]
pub use leg::{
    Callbacks, DEFAULT_CALLBACK_REQUEST_BUFFER, ExecutorLeg, Preparation, connect_executor,
    serve_executor,
};
#[cfg(feature = "compile")]
pub use leg::{CompilerLeg, connect_compiler, serve_compiler};
#[cfg(any(feature = "compile", feature = "execute"))]
pub use leg::{DEFAULT_REQUEST_BUFFER, LegError};

// The bundle a `run_with_bundle` carries, streamed beside the request so the
// request stays one bounded item. Built only by the door; read only through
// `BundleStream::receive`.
#[cfg(feature = "execute")]
mod stream;
#[cfg(feature = "execute")]
pub use stream::{
    BundleError, BundleSource, BundleStream, DEFAULT_BUNDLE_STREAM_DEADLINE,
    DEFAULT_BUNDLE_STREAM_IDLE,
};

// Constant-size framing for the execute leg's policy-controlled lengths.
#[cfg(feature = "execute")]
mod padded;
#[cfg(feature = "execute")]
pub use padded::{FrameError, Framed, Padded};

/// The remoc connection config both ends of an engine leg build from, and what a
/// role sets of it — shared with the storage tier's legs (see `fleet_stream`).
#[cfg(any(feature = "compile", feature = "execute"))]
pub use fleet_stream::{LegSettings, connection_cfg};
