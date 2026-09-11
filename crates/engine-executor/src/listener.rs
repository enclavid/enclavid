//! Hook fired once per `handle` round, after the policy reducer returns,
//! carrying the new session state and any media the round captured.
//!
//! It reports NOTHING about what the round disclosed. That decision belongs to
//! the orchestrator, which makes it from the prompt it rendered and the event it
//! built — this process runs the policy, so anything it claimed about an
//! applicant's consent would have to be re-derived there anyway.
//!
//! The runtime's I/O layer (typically the api crate) implements
//! `SessionListener` to persist the round. Persist is the caller's job — engine
//! treats this as a neutral session-changed notification and stays free
//! of `SessionStore` / AEAD-key knowledge.
//!
//! Atomicity: state and media for the same round are delivered together in one
//! hook invocation, so a sane listener commits them in one transaction.
//!
//! Returning Err aborts the run; engine surfaces the error to its
//! caller (api), which maps to 5xx.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use hatch_client::SessionState;

/// The applicant media captured THIS round (present only on a media
/// round), staged for the listener to seal into the host blob store. Every
/// captured frame is stored unconditionally — "always store" — so the
/// listener commits these blobs in the SAME transaction as the reducer
/// `state`. Each entry is `(blob_hash, bytes)`: the 32-byte BLAKE3 content
/// key and the raw frame; `bytes` is `Arc`-shared with the run's frame
/// resources so nothing is copied to reach the seal.
pub struct CapturedMedia {
    pub blobs: Vec<([u8; 32], Arc<Vec<u8>>)>,
}

/// Bundle delivered to the listener once per `handle` round. `state` is
/// the post-round snapshot; `media` is present only on a media round — the
/// captured frames to seal into the blob store. Bundled together because a sane
/// listener commits them in one atomic transaction.
///
/// What the round disclosed is NOT here, deliberately. The orchestrator decides
/// that from the prompt it rendered and the event it built, before this side
/// runs — this process executes adversary-supplied code, so anything it asserted
/// about an applicant's consent would have to be re-derived there anyway.
pub struct SessionChange<'a> {
    pub state: &'a SessionState,
    pub media: Option<&'a CapturedMedia>,
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
