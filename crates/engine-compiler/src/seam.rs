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
//! their defaults, and why the child is spawned under a deadline, a memory max of
//! its own, an identity of its own and an egress seccomp filter. Caps that trap,
//! in the position this role actually occupies.

use serde::{Deserialize, Serialize};

use engine_rpc::{CompileError, CompileRequest, MAX_CWASM_BYTES};
use fleet_stream::BlobHeader;

/// What a compile child gives back: the metadata, encoded as the execute hop
/// streams it, and the cwasm's length and digest.
///
/// The cwasm itself is not here. The child writes it to the file the supervisor
/// handed it at `engine_supervisor::INHERITED_FD`, which outlives the child: the
/// child is gone as soon as it has answered, and its cwasm streams on to api from
/// the supervisor. The pages are the child's, written by it and charged to its
/// memory group, so they count against the compiles' total until they are gone.
///
/// `deny_unknown_fields`: an unknown field is a child speaking a contract this
/// supervisor does not have.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildCompiled {
    #[serde(with = "serde_bytes")]
    pub meta: Vec<u8>,
    pub cwasm: BlobHeader<MAX_CWASM_BYTES>,
}

/// One compile, driven in a disposable child.
///
/// The request is the api hop's own — the components streaming beside it, which
/// the supervisor relays — and the answer is not: the cwasm is in the file the
/// child was handed rather than in a stream beside the reply, since the child
/// does not outlive the call.
#[remoc::rtc::remote]
pub trait CompileChildService {
    async fn compile(&self, req: CompileRequest) -> Result<ChildCompiled, CompileError>;
}
