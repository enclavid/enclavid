//! Hook fired once per `handle` round, after the policy reducer returns,
//! carrying the new session state and, on the round that finishes, the
//! policy's decision.
//!
//! It reports NOTHING about what the round disclosed or captured. Those
//! belong to the orchestrator, which derives the disclosure from the prompt it
//! rendered and the event it built, and holds the captures it sent — this
//! process runs the policy, so anything it claimed about an applicant's consent
//! would have to be re-derived there anyway.
//!
//! The runtime's I/O layer (typically the api crate) implements
//! `SessionListener` to persist the round. Persist is the caller's job — engine
//! treats this as a neutral session-changed notification and stays free
//! of `SessionStore` / AEAD-key knowledge.
//!
//! Atomicity: the state and the decision for the same round are delivered
//! together in one hook invocation, so a sane listener commits them in one
//! transaction — and a round that finished is committed as finished, whatever
//! becomes of the reply that reports it.
//!
//! Returning Err aborts the run; engine surfaces the error to its
//! caller (api), which maps to 5xx.

use std::future::Future;
use std::pin::Pin;

use hatch_client::{Decision, SessionState};

/// Delivered to the listener once per `handle` round: the post-round state
/// snapshot and, if the round finished, its decision.
///
/// Neither the round's disclosure nor its captures are here, deliberately. The
/// orchestrator holds both already — it derives the disclosure from the prompt it
/// rendered and the event it built, and the captured frames are the ones it read
/// off `/input` and sent this side. This process executes adversary-supplied
/// code, so anything it reported about either would have to be re-derived there,
/// which makes reporting it worse than useless: it invites being believed.
///
/// The decision is different in kind: it is the policy's to make, so the word of
/// the process running the policy is the only word there is about it.
pub struct SessionChange<'a> {
    pub state: &'a SessionState,
    /// The policy's verdict when the round finished, `None` on every other
    /// round. Committed in the same write as the state, so a session whose
    /// state has finished never reads as still running.
    pub decision: Option<Decision>,
}

/// Trait fired once per `handle` round. Returns a boxed future
/// rather than `async fn` so the trait stays object-safe — engine holds
/// `Arc<dyn SessionListener>` and dispatches dynamically.
///
/// Error type is `wasmtime::Result` because the call originates from
/// inside a wasmtime host fn body and any failure has to surface as a
/// trap to terminate the run cleanly. Re-exported as
/// `engine_executor::RunResult` so listener implementers don't pull
/// in wasmtime as a direct dependency.
pub trait SessionListener: Send + Sync {
    fn on_session_change<'a>(
        &'a self,
        change: SessionChange<'a>,
    ) -> Pin<Box<dyn Future<Output = wasmtime::Result<()>> + Send + 'a>>;
}
