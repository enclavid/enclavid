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
//! a different scheme (age to `client_pk`) but the architectural slot
//! is the same — the api layer owns "I/O + encryption keys", engine
//! stays pure logic.
//!
//! Lifetime: one persister per `Runner::run` call. Owns session-id,
//! the applicant key (state's inner AEAD layer), and the client
//! disclosure pubkey (disclosure age recipient). Cheap to construct;
//! engine drops it when the run finishes.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use enclavid_engine::{RunError, RunResult, SessionChange, SessionListener};
use enclavid_host_bridge::{
    AppendDisclosure, AuthN, Replay, SessionStore, SetState, WriteField, reason,
    seal_to_recipient,
};

pub(super) struct SessionPersister {
    pub session_store: Arc<SessionStore>,
    pub session_id: String,
    pub applicant_key: Vec<u8>,
    /// Age recipient string (`age1...`) for disclosure entries.
    /// Pulled from session metadata at run start; provided by the
    /// platform consumer when creating the session, so the consumer
    /// holds the matching private key.
    pub client_pk: String,
    /// Session version we expect on the host. Initialized from the
    /// read that precedes the run; updated after each successful
    /// `write` so subsequent writes within the same run don't
    /// re-read. A concurrent run pushes the version past us; our
    /// next write fails with `VersionMismatch` and the run aborts
    /// cleanly — replay from the latest persisted state on retry.
    pub current_version: AtomicU64,
}

impl SessionListener for SessionPersister {
    fn on_session_change<'a>(
        &'a self,
        change: SessionChange<'a>,
    ) -> Pin<Box<dyn Future<Output = RunResult<()>> + Send + 'a>> {
        Box::pin(async move {
            // age-seal each plaintext payload to the client's
            // disclosure recipient. The host stores opaque bytes;
            // only the platform consumer (who provided the recipient
            // at session creation) can open. Sealing failures map to
            // a run-level error — same path as a transport failure on
            // the persist itself.
            let sealed: Vec<Vec<u8>> = change
                .disclosures
                .iter()
                .map(|payload| seal_to_recipient(payload, &self.client_pk))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| RunError::msg(format!("disclosure seal failed: {e}")))?;

            // Bridge field markers borrow into our locals; we materialize
            // both vectors first so the slice we pass to `write` can hold
            // borrows without lifetime gymnastics.
            let set_state = SetState {
                state: change.state,
                applicant_key: &self.applicant_key,
            };
            let appends: Vec<AppendDisclosure> =
                sealed.into_iter().map(AppendDisclosure).collect();
            let mut ops: Vec<&dyn WriteField> = Vec::with_capacity(1 + appends.len());
            ops.push(&set_state);
            ops.extend(appends.iter().map(|a| a as &dyn WriteField));

            // Persister is single-threaded within a run (engine
            // serializes hooks), so the ordering here is purely
            // formal. Atomic chosen over Mutex for zero allocation.
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
