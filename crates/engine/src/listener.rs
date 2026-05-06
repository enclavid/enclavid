//! Hook fired after each successfully-committed CallEvent in the
//! engine's replay log.
//!
//! The runtime's I/O layer (typically the api crate) implements
//! `SessionListener` to persist the new state plus any side-effect
//! outputs (disclosure records) emitted in this call's body. Persist
//! is the caller's job — engine treats this as a neutral
//! session-changed notification and stays free of `SessionStore` /
//! AEAD-key knowledge.
//!
//! Atomicity: state and disclosures emitted within the same call are
//! delivered together in one hook invocation, so a sane listener
//! commits them in one transaction. A crash between calls leaves the
//! replay log on the host consistent with the last hook acknowledged
//! Ok — the next run replays from there and re-emits any work past it.
//!
//! Returning Err aborts the run; engine surfaces the error to its
//! caller (api), which maps to 5xx. The next attempt replays from the
//! last call the listener acknowledged.

use std::future::Future;
use std::pin::Pin;

use enclavid_host_bridge::{DisplayField, SessionState};

/// Structured disclosure record emitted by a single successful
/// `prompt_disclosure` call. Engine emits proto-typed fields; the
/// listener (api crate) is responsible for converting to its public
/// JSON wire format and sealing to the consumer recipient. Keeping
/// the engine output structured (not pre-serialized) firewalls the
/// engine from public API shape decisions.
pub struct ConsentDisclosure {
    pub fields: Vec<DisplayField>,
}

/// Bundle delivered to the listener for a single committed CallEvent.
/// `state` is the post-commit snapshot; `disclosures` are any
/// disclosure records emitted in the body of this call (empty unless
/// the call was a successful `prompt_disclosure`). Bundled together
/// because a sane listener commits them in one atomic transaction.
pub struct SessionChange<'a> {
    pub state: &'a SessionState,
    pub disclosures: &'a [ConsentDisclosure],
}

/// Trait fired after every committed CallEvent. Returns a boxed future
/// rather than `async fn` so the trait stays object-safe — engine holds
/// `Arc<dyn SessionListener>` and dispatches dynamically.
///
/// Error type is `wasmtime::Result` because the call originates from
/// inside a wasmtime host fn body and any failure has to surface as a
/// trap to terminate the run cleanly. Re-exported as
/// `enclavid_engine::RunResult` so listener implementers don't pull
/// in wasmtime as a direct dependency.
pub trait SessionListener: Send + Sync {
    fn on_session_change<'a>(
        &'a self,
        change: SessionChange<'a>,
    ) -> Pin<Box<dyn Future<Output = wasmtime::Result<()>> + Send + 'a>>;
}
