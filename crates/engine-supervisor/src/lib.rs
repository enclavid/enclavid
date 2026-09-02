//! `engine-supervisor` — disposable per-request child-process isolation for the
//! engine fleet's workers.
//!
//! A worker SUPERVISOR (execution-worker / compile-worker) uses a [`ChildPool`]
//! to run ONE unit of untrusted work — a reducer round, or a Cranelift compile —
//! in a fresh disposable CHILD PROCESS, then discard it. So a compromise of the
//! untrusted work (a wasmtime sandbox escape, or a Cranelift bug tripped by
//! crafted input) is confined to that one throwaway process behind an OS
//! address-space boundary, with no cross-request persistence.
//!
//! ## Two halves, and the feature between them
//!
//! Both sides of the socketpair are written here, so the fiddly,
//! security-load-bearing plumbing exists ONCE and every worker rides it. But the
//! two sides are not for the same reader, so they are separate modules and the
//! parent one is behind the `parent` feature (default-on; the child packages take
//! `default-features = false`).
//!
//! `parent` — spawn, harden, bound, kill, reap:
//!   * [`ChildPool::run`] — acquire a concurrency permit, spawn a fresh child,
//!     hand its service client to the caller's closure, drive it under a
//!     wall-clock DEADLINE (a wedged child can't leak its permit forever), then
//!     kill + reap.
//!   * [`spawn_and_connect`] — socketpair + `Command` + fd handoff on the child's
//!     fd 0 + remoc handshake. `Stdio::from` closes the supervisor's copy of the
//!     child end, so the child's death EOFs the socket promptly. It also installs
//!     any caller-supplied fds at deterministic numbers ([`FIRST_INHERITED_FD`]..),
//!     CLOEXEC-cleared so ONLY they survive exec — the capability-scoped handoff the
//!     executor uses to give a child a read-only fd to just ITS cwasm memfd.
//!   * [`assert_ptrace_hardened`] — the boot-time floor under sibling isolation.
//!
//! Unfeatured — the child side:
//!   * [`adopt_fd0`] / [`serve_child`] — adopt the inherited socket, remoc-serve
//!     one service, exit when the supervisor drops its client.
//!
//! The gate is a feature and not merely a module boundary because of what it
//! carries: `tokio/process`, `libc` and `safe-logger` hang off the parent half.
//! The first of those is the interesting one — it makes tokio's runtime start a
//! signal driver, and that driver is why a disposable child, which spawns
//! nothing, used to open a `socketpair` on its way up. A shipped child now
//! starts no such driver, which is what let that syscall back onto the egress
//! denylist.
//!
//! The DOMAIN stays in each worker: which service the child serves, any mid-call
//! callbacks (executor only), and any bundle cache. This crate is a domain-
//! agnostic leaf — tokio, remoc, libc and `safe-logger`, never `engine-rpc` /
//! `engine-types`, so the orchestrator (api) does not link it. `safe-logger` is
//! there for one reason: [`assert_ptrace_hardened`] is a load-bearing boot check
//! and both of its outcomes have to reach an operator, which on a guest neither
//! stderr nor a panic payload does.
//!
//! Fresh `exec` (not `fork`) per request is deliberate: it was measured at ~7.7 ms
//! warm, and the round's real cost sat in transport tuning, not spawn — so a
//! warm-CoW fork-zygote (with its `pidfd` / `close_range` / single-threaded-clone
//! hazards) is not worth its unsafe here.

mod child;
pub use child::{adopt_fd0, serve_child};

#[cfg(feature = "parent")]
mod parent;
#[cfg(feature = "parent")]
pub use parent::spawn_and_connect;
#[cfg(feature = "parent")]
pub use parent::{
    ChildPool, FIRST_INHERITED_FD, Hardening, SupervisorError, assert_ptrace_hardened,
};

/// The remoc connection config the child hop uses. Raises `max_data_size` from
/// chmux's 512 KiB default: a compile RETURNS its `cwasm` over this connection,
/// ~10-15 MiB, which the default would reject outright. (The execute side no
/// longer sends one the other way — `prime` carries a path to an inherited fd, so
/// the bytes never cross. The engine RPC contract raises the same limit on the
/// api hop; this crate is a leaf and can't name that constant, so it keeps its
/// own — the transport tuning for the child hop.)
// `remoc::Cfg` is `#[non_exhaustive]`, so a struct literal (`Cfg { .., ..default }`)
// can't be built from here — the mutate-after-default is the only option.
#[allow(clippy::field_reassign_with_default)]
fn connection_cfg() -> remoc::Cfg {
    let mut cfg = remoc::Cfg::default();
    cfg.max_data_size = 64 * 1024 * 1024;
    // Flush immediately: chmux's default 20 ms `flush_delay` (a throughput
    // coalescing timer) adds ~20 ms per SEND direction to our latency-bound
    // request/response RPC — measured ~40 ms/round-trip. Each side flushes its own
    // sends, so BOTH this (child-serve) side and the engine-rpc (api/supervisor)
    // side must set it. Nothing to coalesce: our writes are whole RPC frames.
    cfg.flush_delay = std::time::Duration::ZERO;
    // Pin the peer-driven port limits well below chmux's defaults (16384 ports /
    // 128 received). The child is UNTRUSTED once its wasm/Cranelift is escaped, and
    // it drives its own end of this socketpair — the default would let a compromised
    // child open thousands of ports to exhaust supervisor memory. Our RPC uses only
    // a handful of concurrent channels (base + prime/run + a few callbacks), so 256
    // is generous headroom while bounding the exhaustion surface.
    cfg.max_ports = 256;
    cfg.max_received_ports = 64;
    cfg
}
