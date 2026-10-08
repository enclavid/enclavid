//! `engine-supervisor` — disposable per-request child-process isolation for the
//! engine fleet's workers.
//!
//! A worker SUPERVISOR (execution-worker / compile-worker) uses a [`ChildRunner`]
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
//! parent ones are behind the `parent` feature (default-on; the child packages
//! take `default-features = false`).
//!
//! `parent` — spawn, harden, bound, kill, release:
//!   * [`ChildRunner`] — admit a request, spawn its child under the syscall
//!     filters, drive the caller's closure under the request's deadline, and
//!     kill the child as the call ends, giving its slot back once it is gone.
//!   * [`Cgroups`] — the kernel's hold on the children's memory, built at boot:
//!     all of them to one total, each to its own max, each in a group and under
//!     an identity of its own.
//!   * [`spawn_and_connect`] — one child on its socketpair, with the caller's
//!     descriptor at [`INHERITED_FD`], for a bench or a test.
//!   * [`require_ptrace_scope`], [`require_fd_budget`], [`physical_memory`] —
//!     what a supervisor checks and measures at boot.
//!
//! Unfeatured — the child side:
//!   * [`adopt_fd0`] / [`serve_child`] — adopt the inherited socket, remoc-serve
//!     one service, exit when the supervisor drops its client.
//!
//! The gate is a feature and not merely a module boundary because of what it
//! carries: `tokio/process`, `libc` and `safe-logger` hang off the parent half.
//! The first makes tokio's runtime start a signal driver, which opens a
//! `socketpair` — a syscall the child's allowlist does not have. A child built
//! without the feature starts none.
//!
//! The domain stays in each worker: which service the child serves, any mid-call
//! callbacks, any bundle cache. This crate is a domain-agnostic leaf — never
//! `engine-rpc` or `engine-types` — so the orchestrator (api) does not link it.
//!
//! A fresh `exec` per request rather than a fork of a warm process: spawning
//! measured ~7.7 ms warm, and a fork-zygote's `pidfd` / `close_range` /
//! single-threaded-clone hazards are not worth that.

// Every `unsafe` block here sits between fork and exec or in a forked test
// probe, where what makes it sound is not obvious from the call alone.
#![warn(clippy::undocumented_unsafe_blocks)]

mod channel;
mod child;
pub use child::{ServeError, adopt_fd0, serve_child};

#[cfg(feature = "parent")]
mod cgroup;
#[cfg(feature = "parent")]
mod preconditions;
#[cfg(feature = "parent")]
mod runner;
#[cfg(all(feature = "parent", target_os = "linux"))]
mod seccomp;
#[cfg(feature = "parent")]
mod spawn;

#[cfg(feature = "parent")]
pub use cgroup::{Cgroups, ChildLimits, DEFAULT_CHILD_MAX_TASKS, ExitCause};
#[cfg(feature = "parent")]
pub use preconditions::{physical_memory, require_fd_budget, require_ptrace_scope};
#[cfg(feature = "parent")]
pub use runner::{ChildRunner, ChildTimes, Exit, RunnerConfig, SupervisorError};
#[cfg(feature = "parent")]
pub use spawn::{INHERITED_FD, SpawnError, spawn_and_connect};
