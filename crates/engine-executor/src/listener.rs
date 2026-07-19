//! Hook fired once per `handle` round, after the policy reducer
//! returns, carrying the new session state plus any disclosure the
//! runtime sealed this round (non-empty only when a consent-disclosure
//! prompt was accepted).
//!
//! The runtime's I/O layer (typically the api crate) implements
//! `SessionListener` to persist the new state plus any side-effect
//! outputs (disclosure records). Persist is the caller's job — engine
//! treats this as a neutral session-changed notification and stays free
//! of `SessionStore` / AEAD-key knowledge.
//!
//! Atomicity: state and disclosures for the same round are delivered
//! together in one hook invocation, so a sane listener commits them in
//! one transaction.
//!
//! Returning Err aborts the run; engine surfaces the error to its
//! caller (api), which maps to 5xx.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use broker_client::{DisplayField, SessionState};

/// Structured disclosure record the runtime seals when a
/// consent-disclosure prompt is accepted. Engine emits structured
/// fields; the listener (api crate) is responsible for converting to
/// its public JSON wire format and sealing to the consumer recipient.
/// Keeping the engine output structured (not pre-serialized) firewalls
/// the engine from public API shape decisions.
pub struct ConsentDisclosure {
    pub fields: Vec<DisplayField>,
}

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
/// the post-round snapshot; `disclosures` is non-empty only when this
/// round accepted a consent-disclosure prompt — the consented fields
/// the runtime is sealing to the consumer; `media` is present only on a
/// media round — the captured frames to seal into the blob store. Bundled
/// together because a sane listener commits them in one atomic transaction.
pub struct SessionChange<'a> {
    pub state: &'a SessionState,
    pub disclosures: &'a [ConsentDisclosure],
    pub media: Option<&'a CapturedMedia>,
}

/// Trait fired once per `handle` round. Returns a boxed future
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
