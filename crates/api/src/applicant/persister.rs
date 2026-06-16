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
//! already sealed transparently inside broker-client (`SetState` /
//! `SetMetadata` AEAD with `tee_seal_key`/`applicant_session_token`). Disclosures use
//! a different scheme (age to the consumer's `client_disclosure_pubkey`)
//! but the architectural slot is the same — the api layer owns "I/O +
//! encryption keys", engine stays pure logic.
//!
//! `client_disclosure_pubkey` is a public age recipient for outbound
//! disclosure ciphertexts only — the consumer holds the matching
//! secret. This persister is concerned with the disclosure flow; the
//! policy artifact path is independent.
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
use broker_client::{
    AppendDisclosure, AuthN, AuthZ, Covert, Replay, SessionMetadata, SessionStatus, SessionStore,
    SetMetadata, SetState, SetStatus, WriteField, boundary, reason, seal_to_recipient,
};

use crate::disclosure_hash;
use crate::dto::{self, DisclosureEnvelope, ENVELOPE_VERSION};
use crate::shuffle::ShuffleKey;

pub(super) struct SessionPersister {
    pub session_store: Arc<SessionStore>,
    pub session_id: String,
    pub applicant_session_token: Vec<u8>,
    /// Age recipient string (`age1...`) for disclosure entries.
    /// Pulled from session metadata at run start; provided by the
    /// platform consumer when creating the session, so the consumer
    /// holds the matching private key.
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
    /// Composition-wide embedded registry. Consulted when sealing
    /// disclosure envelopes to project slot-tagged
    /// `disclosure-field-ref`s back to the raw machine identifiers
    /// the consumer SDK dispatches on.
    pub embedded: Arc<enclavid_engine::EmbeddedRegistry>,
    /// Process-lifetime shuffle key, used to permute `DisplayField`
    /// order inside disclosure envelopes before they're sealed to
    /// the consumer. Lives here (and not in engine) because the
    /// covert-channel target is the consumer-bound envelope only —
    /// the applicant-bound consent screen renders policy order
    /// unchanged for UX consistency. See `crate::shuffle` for the
    /// HKDF derivation chain and threat model.
    pub shuffle_key: Arc<ShuffleKey>,
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
            // Seed the per-envelope shuffle from the running
            // disclosure_count BEFORE this batch — distinct envelopes
            // within the session get independent permutations, and
            // the same envelope reproduces bit-for-bit on replay.
            // metadata is single-writer (engine serializes
            // `on_session_change` hooks) so a brief lock is enough.
            let starting_disclosure_index =
                { self.metadata.lock().await.disclosure_count };
            let appends: Vec<AppendDisclosure> = change
                .disclosures
                .iter()
                .enumerate()
                .map(|(i, d)| -> RunResult<AppendDisclosure> {
                    let sealed = boundary::outbound::to_host(d, reason!(r#"
Engine-emitted ConsentDisclosure destined for ListField::Disclosure
append. All three outbound concerns open at boundary entry: Covert
closed by HKDF'd ChaCha20 field-shuffle below; AuthZ closed via
engine consent-gate rationale (vouch_unchecked); AuthN closed by
age-seal to client_disclosure_pubkey below.
                    "#))
                    .vouch::<Covert, _, _, _, _>(|d| -> RunResult<Vec<u8>> {
                        shuffle_to_envelope_bytes(
                            d,
                            &self.session_id,
                            starting_disclosure_index + i as u64,
                            &self.shuffle_key,
                            &self.embedded,
                        )
                    })?
                    .vouch_unchecked::<AuthZ, _>(reason!(r#"
Disclosure events reach this hook only after engine's
`prompt_disclosure` returned `accepted=true` — engine never emits
unconsented disclosures (see engine's prompt_disclosure host fn).
The consent decision is the applicant's; api persister only
serializes the post-consent record.
                    "#))
                    .vouch::<AuthN, _, _, _, _>(|bytes| -> RunResult<Vec<u8>> {
                        seal_to_recipient(&bytes, &self.client_disclosure_pubkey)
                            .map_err(|e| RunError::msg(format!("disclosure seal failed: {e}")))
                    })?;
                    Ok(AppendDisclosure(sealed))
                })
                .collect::<RunResult<Vec<_>>>()?;

            // Bookkeeping: bump disclosure_count atomically with the
            // append. Holding the metadata mutex across the write
            // serializes any concurrent on_session_change calls
            // within the same run (engine already serializes hooks
            // sequentially, so contention here is theoretical).
            let mut metadata_guard = self.metadata.lock().await;
            let set_state = SetState {
                state: boundary::outbound::to_host(change.state, reason!(r#"
SessionState replay-log snapshot from the engine, destined for
BlobField::State. AuthN closed inside broker-client by the double
AEAD-seal (inner under applicant_session_token, outer under
tee_seal_key). AuthZ + Covert vouched below.
                "#))
                .vouch_unchecked::<AuthZ, _>(reason!(r#"
Inner-AEAD'd to applicant_session_token, which the applicant
presents on /connect and /input to read the same state back. Any
party without the token cannot decrypt — receipt of ciphertext is
not access. AuthZ implicit in key possession.
                "#))
                .vouch_unchecked::<Covert, _>(reason!(r#"
State sealed under tee_seal_key (outer) + applicant_session_token
(inner) — plaintext invisible to both host and consumer. Audit-
honest caveat: ciphertext size IS observable to the host. Policy
can encode bits into the replay log by varying its host-fn call
count / arg sizes within a round, creating a covert side-channel
under host-consumer collusion. Bandwidth is bounded above by per-
round wasmtime fuel caps (engine limits how much policy code runs
before yielding). Risk minimal: the channel requires host
compromise (an honest host doesn't relay sizes to the consumer)
and the bits-per-session ceiling is fuel-bound.
                "#)),
                applicant_session_token: &self.applicant_session_token,
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
                    // `as_inner` is the borrow analog of `into_inner`
                    // — read-only access to fully-vouched bytes, used
                    // here to extend the integrity-chain hash before
                    // the same bytes get released to wire by
                    // `WriteField::build_op`.
                    metadata_guard.disclosure_hash =
                        disclosure_hash::append(&metadata_guard.disclosure_hash, a.0.as_inner());
                }
                set_metadata_holder = SetMetadata(
                    boundary::outbound::to_host(&*metadata_guard, reason!(r#"
SessionMetadata rewrite from the engine persister — disclosure
chain bookkeeping (count + running hash) updated atomically
alongside the SetState op for this CallEvent commit. AuthN closed
inside broker-client by AEAD-seal under tee_seal_key.
                    "#))
                    .vouch_unchecked::<AuthZ, _>(reason!(r#"
Only the attested CVM holds tee_seal_key. Metadata is read by the
applicant API as opaque ciphertext on /connect; release is implicit
in key-possession.
                    "#))
                    .vouch_unchecked::<Covert, _>(reason!(r#"
Metadata sealed under tee_seal_key — plaintext invisible to both
host and consumer. Audit-honest caveat: ciphertext size and
write-presence are host-observable. Policy doesn't directly
mutate metadata, but it can influence whether this rewrite
happens at all (one bit per round: did the policy emit ≥1
disclosure?) and the disclosure_count delta (log2 K bits per
round where K is the fuel-bounded max disclosures per round).
Bandwidth tiny, only opens under host compromise, fuel-bound —
risk minimal, same containment shape as the SetState peel above.
                    "#))
                );
                ops.push(&set_metadata_holder);
            }
            ops.extend(appends.iter().map(|a| a as &dyn WriteField));

            let expected = self.current_version.load(Ordering::SeqCst);
            let new_version = self
                .session_store
                .write(&self.session_id, Some(expected), &ops)
                .await
                .map_err(|e| {
                    // Listener-side failures can be misclassified by
                    // the engine as "this host fn just suspended" if
                    // the replay log was committed before the listener
                    // ran (the suspension event is there, even though
                    // its persistence failed). The misclassification
                    // is recovered from on the next round, but only
                    // if the actual cause shows up in the logs —
                    // hence the explicit eprintln before the RunError
                    // string flows back through wasmtime.
                    eprintln!(
                        "persister.on_session_change: session_store.write \
                         failed for {} (expected version {expected}): {e}",
                        self.session_id,
                    );
                    RunError::msg(format!("persist failed: {e}"))
                })?
                .trust_unchecked::<AuthN, _>(reason!(r#"
Version is a CAS token only. A lying host either fails the next
write (DoS) or stomps a concurrent winner (UX regression). No
data leak path.
                "#))
                .trust_unchecked::<AuthZ, _>(reason!(r#"
Version counter is not an ownership signal — no access decision
hangs on its value; persister feeds it back as expected_version on
the next write.
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
        metadata.status = SessionStatus::Completed;
        let expected = self.current_version.load(Ordering::SeqCst);
        let set_metadata = SetMetadata(
            boundary::outbound::to_host(&*metadata, reason!(r#"
SessionMetadata write on finalize — flips metadata.status to
Completed atomically with the host-facing BlobField::Status flip
below. AuthN closed inside broker-client by AEAD-seal.
            "#))
            .vouch_unchecked::<AuthZ, _>(reason!(r#"
Sealed under tee_seal_key — only the attested CVM opens. Same
posture as on_session_change.
            "#))
            .vouch_unchecked::<Covert, _>(reason!(r#"
Metadata sealed under tee_seal_key — plaintext invisible to both
host and consumer. Audit-honest caveat: ciphertext size is host-
observable, but this finalize write only flips metadata.status to
a fixed enum value (Completed); no policy-controlled bandwidth in
the rewrite itself. The size delta over the prior write is
deterministic per status transition.
            "#))
        );
        let set_status = SetStatus(
            boundary::outbound::to_host(SessionStatus::Completed, reason!(r#"
SessionStatus host-facing flip on finalize (Completed). By-design
plaintext for host TTL / cleanup orchestration.
            "#))
            .vouch_unchecked::<AuthN, _>(reason!(r#"
By-design plaintext. Host needs the byte to manage TTL. No
applicant- or policy-specific data lands in the byte — only the
lifecycle marker is observable.
            "#))
            .vouch_unchecked::<AuthZ, _>(reason!(r#"
Lifecycle marker observable to host for orchestration is the
explicit contract.
            "#))
            .vouch_unchecked::<Covert, _>(reason!(r#"
Enum cardinality = 5; ~1 status write per session lifecycle
transition. Bounded by session-lifecycle schema.
            "#))
        );
        let new_version = self
            .session_store
            .write(
                &self.session_id,
                Some(expected),
                &[&set_metadata as &dyn WriteField, &set_status],
            )
            .await
            .map_err(|e| {
                eprintln!(
                    "persister.finalize: session_store.write failed for {} \
                     (expected version {expected}): {e}",
                    self.session_id,
                );
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .trust_unchecked::<AuthN, _>(reason!(r#"
Version is a CAS token only — same containment as in
on_session_change.
            "#))
            .trust_unchecked::<AuthZ, _>(reason!(r#"
Version counter is not an ownership signal — feed-forward to next
expected_version is the only consumer.
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

/// Build the JSON envelope plaintext for one engine disclosure,
/// with field order shuffled via a per-envelope HKDF'd ChaCha20
/// permutation. This step alone closes the `Covert` concern in the
/// outbound boundary chain — field order is the single covert
/// channel where policy-encoded bits could otherwise reach the
/// consumer. The subsequent `vouch::<AuthN>(seal_to_recipient)`
/// closes confidentiality.
///
/// `session_id` is embedded in the envelope as defense-in-depth:
/// metadata-level `disclosure_hash` already binds the per-session
/// list to its session, but a redundant in-envelope copy means a
/// consumer that receives a disclosure out-of-band (e.g. via a
/// future webhook payload) can also self-verify the binding.
///
/// Seed: [`ShuffleKey::derive_envelope_seed(session_id,
/// disclosure_index)`](ShuffleKey::derive_envelope_seed), bound to
/// `tee_seal_key` — host can't predict the permutation, consumer
/// can't reverse it. The consent-screen view (which the applicant
/// audits before consenting) renders in policy order separately
/// and is not a leak surface.
fn shuffle_to_envelope_bytes(
    d: &ConsentDisclosure,
    session_id: &str,
    disclosure_index: u64,
    shuffle_key: &ShuffleKey,
    embedded: &enclavid_engine::EmbeddedRegistry,
) -> RunResult<Vec<u8>> {
    use rand::SeedableRng;
    use rand::seq::SliceRandom;

    // Envelope carries `{ key, value }` only — no label. Consumer
    // dispatches by typed `key`; the per-session policy text
    // registry stays inside the TEE so its multi-language
    // translations never reach the consumer (closing the covert
    // channel where non-user-locale variants would otherwise
    // travel in `LocalizedText`). `key` is projected from its
    // slot-tagged ref to the raw machine identifier via the
    // composition's disclosure-fields store.
    let mut fields: Vec<_> = d
        .fields
        .iter()
        .map(|f| dto::display_field_from_proto(f, embedded))
        .collect();
    let seed = shuffle_key.derive_envelope_seed(session_id, disclosure_index);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    fields.shuffle(&mut rng);

    let envelope = DisclosureEnvelope {
        version: ENVELOPE_VERSION,
        session_id: session_id.to_string(),
        fields,
    };
    serde_json::to_vec(&envelope)
        .map_err(|e| RunError::msg(format!("disclosure JSON encode: {e}")))
}
