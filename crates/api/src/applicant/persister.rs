//! `SessionListener` impl that seals + persists per-call CallEvent commits
//! to the host-side `SessionStore`. Engine fires `on_session_change` after
//! each committed CallEvent; we age-encrypt any disclosures emitted in
//! that call's body to the client recipient pubkey, then translate
//! state + sealed disclosures into a single atomic Write RPC.
//!
//! Atomicity is the whole point: state mutation (consent accepted) and
//! the disclosure entry that records what was shared land in one host
//! transaction. A crash between calls leaves the host's replay log
//! consistent with the last successfully-acknowledged event; the next
//! attempt replays from there and re-emits any work past it.
//!
//! Why encryption lives here, not in engine: state and metadata are
//! already sealed transparently inside host-bridge (`SetState` /
//! `SetMetadata` AEAD with `tee_key`/`applicant_key`). Disclosures use
//! a different scheme (age to the consumer's `client_disclosure_pubkey`)
//! but the architectural slot is the same — the api layer owns "I/O +
//! encryption keys", engine stays pure logic.
//!
//! Note: `client_disclosure_pubkey` ≠ `K_client`. The former is a
//! public age recipient for outbound disclosure ciphertexts; the
//! latter is the policy-decryption secret used at /connect to pull
//! and decrypt the policy artifact. Different keys, different
//! directions, different blast radii.
//!
//! Lifetime: one persister per `Runner::run` call. Owns session-id,
//! the applicant key (state's inner AEAD layer), the client
//! disclosure pubkey (disclosure age recipient), and a mutable copy
//! of session metadata (so we can update `disclosure_count`
//! atomically with each persist). Cheap to construct; engine drops
//! it when the run finishes.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::Mutex;

use axum::http::StatusCode;

use enclavid_engine::{
    ConsentDisclosure, RunError, RunResult, RunStatus, SessionChange, SessionListener,
};
use enclavid_host_bridge::{
    AppendDisclosure, AuthN, Replay, SessionMetadata, SessionStatus, SessionStore, SetMetadata,
    SetState, SetStatus, WriteField, reason, seal_to_recipient,
};

use crate::disclosure_hash;
use crate::dto::{self, DisclosureEnvelope, ENVELOPE_VERSION};

pub(super) struct SessionPersister {
    pub session_store: Arc<SessionStore>,
    pub session_id: String,
    pub applicant_key: Vec<u8>,
    /// Age recipient string (`age1...`) for disclosure entries.
    /// Pulled from session metadata at run start; provided by the
    /// platform consumer when creating the session, so the consumer
    /// holds the matching private key. Distinct from `K_client`
    /// (the policy-decryption secret) — see module-level docs.
    pub client_disclosure_pubkey: String,
    /// Session version we expect on the host. Initialized from the
    /// read that precedes the run; updated after each successful
    /// `write` so subsequent writes within the same run don't
    /// re-read. A concurrent run pushes the version past us; our
    /// next write fails with `VersionMismatch` and the run aborts
    /// cleanly — replay from the latest persisted state on retry.
    pub current_version: AtomicU64,
    /// Mutable copy of session metadata. We update
    /// `disclosure_count` and the running `disclosure_hash` chain
    /// whenever the engine emits disclosures and rewrite metadata
    /// atomically alongside the state + append ops. Other metadata
    /// fields stay constant across the session lifetime; this is
    /// purely a bookkeeping wrapper.
    pub metadata: Mutex<SessionMetadata>,
}

impl SessionListener for SessionPersister {
    fn on_session_change<'a>(
        &'a self,
        change: SessionChange<'a>,
    ) -> Pin<Box<dyn Future<Output = RunResult<()>> + Send + 'a>> {
        Box::pin(async move {
            // Convert each engine-emitted disclosure record to the
            // public JSON envelope (api owns the wire format) and
            // age-seal to the client's recipient. The host stores
            // opaque bytes; only the platform consumer (who provided
            // the recipient at session creation) can open. JSON-encode
            // or seal failures map to a run-level error — same path
            // as a transport failure on the persist itself.
            let sealed: Vec<Vec<u8>> = change
                .disclosures
                .iter()
                .map(|d| seal_disclosure(d, &self.client_disclosure_pubkey, &self.session_id))
                .collect::<Result<Vec<_>, _>>()?;

            let appends: Vec<AppendDisclosure> =
                sealed.into_iter().map(AppendDisclosure).collect();

            // Bookkeeping: bump disclosure_count atomically with the
            // append. Holding the metadata mutex across the write
            // serializes any concurrent on_session_change calls
            // within the same run (engine already serializes hooks
            // sequentially, so contention here is theoretical).
            let mut metadata_guard = self.metadata.lock().await;
            let set_state = SetState {
                state: change.state,
                applicant_key: &self.applicant_key,
            };
            let mut ops: Vec<&dyn WriteField> = Vec::with_capacity(2 + appends.len());
            ops.push(&set_state);

            // Only re-write metadata when there's something to
            // increment. Most CallEvent commits don't emit
            // disclosures (only successful `prompt_disclosure` does),
            // so the common path is just SetState — keeps the wire
            // payload small. When disclosures are present we extend
            // the running `disclosure_hash` chain so the host-served
            // list can be cryptographically checked at read time.
            let set_metadata_holder;
            if !appends.is_empty() {
                metadata_guard.disclosure_count += appends.len() as u64;
                for a in &appends {
                    metadata_guard.disclosure_hash =
                        disclosure_hash::append(&metadata_guard.disclosure_hash, &a.0);
                }
                set_metadata_holder = SetMetadata(&metadata_guard);
                ops.push(&set_metadata_holder);
            }
            ops.extend(appends.iter().map(|a| a as &dyn WriteField));

            let expected = self.current_version.load(Ordering::SeqCst);
            let new_version = self
                .session_store
                .write(&self.session_id, Some(expected), &ops)
                .await
                .map_err(|e| RunError::msg(format!("persist failed: {e}")))?
                .trust_unchecked::<AuthN, _>(reason!(r#"
Version is a CAS token only. A lying host either fails the next
write (DoS) or stomps a concurrent winner (UX regression). No
data leak path.
                "#))
                .trust_unchecked::<Replay, _>(reason!(r#"
Staleness on the chained version manifests as next-write CAS
mismatch; persister returns Err and the run aborts cleanly.
                "#))
                .into_inner();
            self.current_version.store(new_version, Ordering::SeqCst);
            Ok(())
        })
    }
}

impl SessionPersister {
    /// Atomically transition the session to Completed after the runner
    /// returns `RunStatus::Completed`. Updates `metadata.status`
    /// (TEE-trusted, AEAD-bound) and `BlobField::Status` (host-facing
    /// TTL hint) in one Write RPC. No-op for Suspended runs — the
    /// session continues into the next /input round.
    ///
    /// Idempotent under crash recovery: if a previous run already
    /// finalized but the response was lost, replay re-runs the policy
    /// (which fast-paths to `RunStatus::Completed`), and this method
    /// re-applies the same status flip — the host's CAS accepts it
    /// because `current_version` reflects the version after that
    /// previous finalize.
    ///
    /// Failed / Expired transitions are intentionally NOT handled
    /// here. Engine errors stay as Running (operationally retried);
    /// TTL is host-side via `BlobField::Status` plaintext, never
    /// propagated to TEE-trusted metadata.
    pub(super) async fn finalize(&self, run_status: &RunStatus) -> Result<(), StatusCode> {
        if !matches!(run_status, RunStatus::Completed(_)) {
            return Ok(());
        }
        let mut metadata = self.metadata.lock().await;
        metadata.status = SessionStatus::Completed as i32;
        let expected = self.current_version.load(Ordering::SeqCst);
        let new_version = self
            .session_store
            .write(
                &self.session_id,
                Some(expected),
                &[
                    &SetMetadata(&metadata) as &dyn WriteField,
                    &SetStatus(SessionStatus::Completed),
                ],
            )
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .trust_unchecked::<AuthN, _>(reason!(r#"
Version is a CAS token only — same containment as in
on_session_change.
            "#))
            .trust_unchecked::<Replay, _>(reason!(r#"
Staleness on the chained version manifests as VersionMismatch
on this write; the handler returns 500 and the client retries
against fresh state. Replay-side rerun re-emits the same
status flip, idempotently.
            "#))
            .into_inner();
        self.current_version.store(new_version, Ordering::SeqCst);
        Ok(())
    }
}

/// Serialize one engine disclosure record into the public JSON
/// envelope and age-seal to the consumer recipient. The two failure
/// modes (encode + seal) collapse into one `RunError` — the run
/// retries from the last persisted state on the next attempt.
///
/// `session_id` is embedded in the envelope as defense-in-depth:
/// metadata-level `disclosure_hash` already binds the per-session
/// list to its session, but a redundant in-envelope copy means a
/// consumer that receives a disclosure out-of-band (e.g. via a
/// future webhook payload) can also self-verify the binding.
fn seal_disclosure(
    d: &ConsentDisclosure,
    recipient: &str,
    session_id: &str,
) -> RunResult<Vec<u8>> {
    let envelope = DisclosureEnvelope {
        version: ENVELOPE_VERSION,
        session_id: session_id.to_string(),
        fields: d.fields.iter().map(dto::DisplayField::from).collect(),
    };
    let json = serde_json::to_vec(&envelope)
        .map_err(|e| RunError::msg(format!("disclosure JSON encode: {e}")))?;
    seal_to_recipient(&json, recipient)
        .map_err(|e| RunError::msg(format!("disclosure seal failed: {e}")))
}
