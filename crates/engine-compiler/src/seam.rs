//! The supervisor↔child seam — this role's own internal hop, not a fleet leg.
//!
//! `compile-worker` is a SUPERVISOR: it holds no Cranelift of its own and runs no
//! codegen. Per compile it spawns a fresh disposable `engine-compiler-child`
//! process over a unix socketpair, drives exactly one call through it, and discards
//! it. This trait is that call.
//!
//! ## Why it lives here and not in `engine-rpc`
//!
//! `engine-rpc` is the FLEET contract: what crosses between CVMs, where the other
//! end is a peer this role does not identify. This hop is neither. It is a
//! socketpair between two processes the supervisor itself forked, inside one CVM,
//! and it exists only because this role chose to isolate its codegen in a separate
//! address space. api will never speak it and has no business linking its
//! definition — the crate that owns both ends of a hop is the crate that should
//! describe it.
//!
//! That also settles a mechanical problem. `#[remoc::rtc::remote]` generates a
//! client type per trait; while one trait served both hops, its client could not be
//! withheld from `engine-rpc`'s public surface, so the api hop could never have the
//! wall the execute leg's `ExecutorServiceClient` has. Two traits in two crates,
//! each where it belongs, and the wall becomes possible.
//!
//! ## What is deliberately absent
//!
//! No framing, and no boundary markers. Both are answers to questions this hop does
//! not raise: the host that splices — and counts — the bytes on a fleet leg is not
//! on a socketpair, and there is no third party who could be on the far end, so
//! there is nothing to judge about who sent what.
//!
//! The seam is not therefore *trusted*. It is adversarial in the child→supervisor
//! direction, because a child whose Cranelift has been escaped drives its own end —
//! which is why `engine_supervisor` pins chmux's peer-driven port limits far below
//! their defaults, and why the child is spawned under a deadline, an address-space
//! rlimit and an egress seccomp filter. Caps that trap, in the position this role
//! actually occupies.

use engine_rpc::{CompileError, CompileRequest, CompiledBundle};

/// One compile, driven in a disposable child.
///
/// Identical in shape to `engine_rpc::CompilerService` today, and expected to
/// diverge as the api hop takes on what this one does not need — the way the
/// execute leg's `ExecutorService` and `ChildService` already differ in their
/// arguments, their envelopes and their framing. If the two ever settle into
/// permanent agreement, the split was wrong and they should be merged back.
#[remoc::rtc::remote]
pub trait CompileChildService {
    /// `req` rather than two bare arguments, and for the same reason the api hop
    /// uses one: `CompileRequest::policy` is `serde_bytes`, so a multi-MiB component
    /// crosses as ONE CBOR byte string instead of an array of integers. That costs
    /// roughly twice the bytes and hundreds of milliseconds when it is got wrong —
    /// a lesson this tree has already paid for twice, on `CompiledBundle::cwasm` and
    /// on `PluginInstance::wasm`.
    async fn compile(&self, req: CompileRequest) -> Result<CompiledBundle, CompileError>;
}
