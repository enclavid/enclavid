//! `SessionListener` impl that seals + persists each reducer round's
//! result to the host-side `SessionStore`. Engine fires
//! `on_session_change` once per `handle` round; we age-encrypt any
//! disclosure the runtime sealed that round (non-empty only when a
//! consent-disclosure prompt was accepted) to the client recipient
//! pubkey, then translate state + sealed disclosures into a single
//! atomic Write RPC.
//!
//! Atomicity is the whole point: state mutation (consent accepted) and
//! the disclosure entry that records what was shared land in one host
//! transaction. A failed write fails the round under version-CAS; the
//! next attempt re-runs from the last persisted state.
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

use broker_client::{
    AppendDisclosure, AuthN, AuthZ, Covert, Replay, SessionMetadata, SessionStatus, SessionStore,
    SetMetadata, SetState, SetStatus, WriteField, boundary, reason,
};
use enclavid_crypto::seal_to_recipient;
use enclavid_engine::{
    ConsentDisclosure, RunError, RunResult, RunStatus, SessionChange, SessionListener,
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
            // Seal the engine-emitted disclosures into append ops. The
            // shuffle is seeded from the disclosure_count BEFORE this
            // batch (a brief metadata lock to read it), so distinct
            // envelopes get independent, replay-stable permutations.
            let starting_index = self.metadata.lock().await.disclosure_count;
            let appends = self.seal_disclosures(&change, starting_index)?;

            // Hold the metadata lock across the write: the state
            // mutation and the disclosure entry land in one atomic host
            // transaction. Engine serializes hooks, so contention is
            // theoretical.
            let mut metadata = self.metadata.lock().await;
            let set_state = self.build_state_op(&change);
            let mut ops: Vec<&dyn WriteField> = Vec::with_capacity(2 + appends.len());
            ops.push(&set_state);

            // Only rewrite metadata when this commit emitted a
            // disclosure — the common path is SetState-only, keeping the
            // wire payload small. When present, `build_metadata_op`
            // extends the running disclosure-hash chain so the host-
            // served list can be integrity-checked at read time.
            let set_metadata_holder;
            if !appends.is_empty() {
                set_metadata_holder = self.build_metadata_op(&mut metadata, &appends);
                ops.push(&set_metadata_holder);
            }
            ops.extend(appends.iter().map(|a| a as &dyn WriteField));

            self.commit_ops(&ops).await
        })
    }
}

impl SessionPersister {
    /// Seal each engine-emitted disclosure into an append op: shuffle
    /// the envelope (Covert), consent-gate (AuthZ), age-seal to the
    /// consumer recipient (AuthN). `starting_index` seeds the per-
    /// envelope shuffle so distinct envelopes get independent, replay-
    /// stable permutations. Returns owned, fully-vouched append ops.
    fn seal_disclosures(
        &self,
        change: &SessionChange<'_>,
        starting_index: u64,
    ) -> RunResult<Vec<AppendDisclosure>> {
        change
            .disclosures
            .iter()
            .enumerate()
            .map(|(i, d)| -> RunResult<AppendDisclosure> {
                let sealed = boundary::outbound::to_untrusted(d)
                    .vouch::<Covert, _, _, _, _>(|d| -> RunResult<Vec<u8>> {
                        shuffle_to_envelope_bytes(
                            d,
                            &self.session_id,
                            starting_index + i as u64,
                            &self.shuffle_key,
                        )
                    })?
                    .vouch_unchecked::<AuthZ, _>(reason!(
                        "engine fires this disclosure only after an accepted consent-disclosure \
                         prompt (show == seal, gated runtime-side); api only serializes the \
                         post-consent record"
                    ))
                    .vouch::<AuthN, _, _, _, _>(|bytes| -> RunResult<Vec<u8>> {
                        seal_to_recipient(&bytes, &self.client_disclosure_pubkey)
                            .map_err(|e| RunError::msg(format!("disclosure seal failed: {e}")))
                    })?;
                Ok(AppendDisclosure(sealed))
            })
            .collect()
    }

    /// Build the `SetState` op from the engine's replay-log snapshot.
    /// AuthN is closed inside broker-client by the double AEAD-seal
    /// (inner under `applicant_session_token`, outer under
    /// `tee_seal_key`); AuthZ/Covert vouched here.
    fn build_state_op<'a>(&'a self, change: &SessionChange<'a>) -> SetState<'a> {
        SetState {
            state: boundary::outbound::to_untrusted(change.state)
                .vouch_unchecked::<AuthZ, _>(reason!(
                    "inner-AEAD'd to applicant_session_token; receipt of ciphertext is not \
                     access — AuthZ implicit in key possession"
                ))
                .vouch_unchecked::<Covert, _>(reason!(
                    "sealed under tee_seal_key + applicant_session_token; caveat: ciphertext \
                     size host-observable, policy can encode bits via per-round host-fn \
                     call count, bounded by wasmtime fuel; host-compromise-gated"
                )),
            applicant_session_token: &self.applicant_session_token,
        }
    }

    /// Advance the disclosure bookkeeping (count + running hash chain)
    /// and build the `SetMetadata` op carrying the updated metadata.
    /// AuthN is closed inside broker-client by the AEAD-seal under
    /// `tee_seal_key`. Only called when this commit emitted disclosures.
    fn build_metadata_op<'m>(
        &self,
        metadata: &'m mut SessionMetadata,
        appends: &[AppendDisclosure],
    ) -> SetMetadata<'m> {
        metadata.disclosure_count += appends.len() as u64;
        for a in appends {
            // `as_inner` is the borrow analog of `into_inner` — read the
            // fully-vouched bytes to extend the integrity-chain hash
            // before the same bytes get released to wire by `build_op`.
            metadata.disclosure_hash =
                disclosure_hash::append(&metadata.disclosure_hash, a.0.as_inner());
        }
        SetMetadata(
            boundary::outbound::to_untrusted(&*metadata)
                .vouch_unchecked::<AuthZ, _>(reason!(
                    "only the attested CVM holds tee_seal_key; read as opaque ciphertext on \
                     /connect — release implicit in key-possession"
                ))
                .vouch_unchecked::<Covert, _>(reason!(
                    "sealed under tee_seal_key; caveat: ciphertext size + write-presence \
                     host-observable; policy influences whether/how much (≤log2 K bits/round, \
                     K fuel-bounded); host-compromise-gated"
                )),
        )
    }

    /// Vouch the write envelope (session id + version + op set) and
    /// commit it at the current expected version, advancing
    /// `current_version` on success. The version verdict is host-
    /// supplied (a CAS token only): a lying host self-limits to DoS / a
    /// stomped concurrent winner, with no data-leak path.
    async fn commit_ops(&self, ops: &[&dyn WriteField]) -> RunResult<()> {
        let expected = self.current_version.load(Ordering::SeqCst);
        let (session_id, expected_version) =
            boundary::outbound::to_untrusted((self.session_id.as_str(), Some(expected)))
                .vouch_unchecked::<AuthN, _>(reason!(
                    "session id + version: public host identifiers, not TEE secrets"
                ))
                .vouch_unchecked::<AuthZ, _>(reason!("fed back to the host that owns them"))
                .vouch_unchecked::<Covert, _>(reason!(
                    "fixed-shape UUID + host's own counter — no policy bandwidth"
                ))
                .distribute();
        let ops = boundary::outbound::to_untrusted(ops)
            .vouch_unchecked::<AuthN, _>(reason!(
                "recipe set; each field's content is sealed in its own build_op"
            ))
            .vouch_unchecked::<AuthZ, _>(reason!("each op writes its own session key"))
            .vouch_unchecked::<Covert, _>(reason!(
                "op count fuel-bounded; per-field covert closed in build_op"
            ));
        let new_version = self
            .session_store
            .write(session_id, expected_version, ops)
            .await
            .map_err(|e| {
                // eprintln before the error flows back through wasmtime:
                // a listener-side write failure surfaces to the engine as
                // a trap that aborts the round; the actual cause must show
                // up in the logs before it is reduced to a 5xx.
                eprintln!(
                    "persister.commit_ops: session_store.write failed for {} \
                     (expected version {expected}): {e}",
                    self.session_id,
                );
                RunError::msg(format!("persist failed: {e}"))
            })?
            .trust_unchecked::<AuthN, _>(reason!(
                "version is a CAS token only; a lying host self-limits to DoS / stomp, no leak"
            ))
            .trust_unchecked::<AuthZ, _>(reason!(
                "version is not an ownership signal — no access decision hangs on it"
            ))
            .trust_unchecked::<Replay, _>(reason!(
                "staleness surfaces as next-write CAS mismatch; the run aborts cleanly"
            ))
            .into_inner();
        self.current_version.store(new_version, Ordering::SeqCst);
        Ok(())
    }

    /// Atomically transition the session to Completed after the runner
    /// returns `RunStatus::Completed`. Updates `metadata.status`
    /// (TEE-trusted, AEAD-bound) and `BlobField::Status` (host-facing
    /// TTL hint) in one Write RPC. No-op while the run is still
    /// awaiting input — the session continues into the next /input round.
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
            boundary::outbound::to_untrusted(&*metadata)
                .vouch_unchecked::<AuthZ, _>(reason!("sealed under tee_seal_key — only the attested CVM opens"))
                .vouch_unchecked::<Covert, _>(reason!(
                    "finalize only flips status to a fixed enum; size delta deterministic per transition"
                )),
        );
        let set_status = SetStatus(
            boundary::outbound::to_untrusted(SessionStatus::Completed)
                .vouch_unchecked::<AuthN, _>(reason!(
                    "by-design plaintext: host needs the byte for TTL; only the lifecycle marker is observable"
                ))
                .vouch_unchecked::<AuthZ, _>(reason!("lifecycle marker observable to host is the explicit contract"))
                .vouch_unchecked::<Covert, _>(reason!("enum cardinality 5; ~1 status write per lifecycle transition")),
        );
        let (session_id, expected_version) =
            boundary::outbound::to_untrusted((self.session_id.as_str(), Some(expected)))
                .vouch_unchecked::<AuthN, _>(reason!(
                    "session id + version: public host identifiers, not TEE secrets"
                ))
                .vouch_unchecked::<AuthZ, _>(reason!("fed back to the host that owns them"))
                .vouch_unchecked::<Covert, _>(reason!(
                    "fixed-shape UUID + host's own counter — no policy bandwidth"
                ))
                .distribute();
        let fields: [&dyn WriteField; 2] = [&set_metadata, &set_status];
        let ops = boundary::outbound::to_untrusted(&fields[..])
            .vouch_unchecked::<AuthN, _>(reason!(
                "recipe set; each field's content is sealed in its own build_op"
            ))
            .vouch_unchecked::<AuthZ, _>(reason!("each op writes its own session key"))
            .vouch_unchecked::<Covert, _>(reason!("2 ops (metadata + status), fixed by finalize"));
        let new_version = self
            .session_store
            .write(session_id, expected_version, ops)
            .await
            .map_err(|e| {
                eprintln!(
                    "persister.finalize: session_store.write failed for {} \
                     (expected version {expected}): {e}",
                    self.session_id,
                );
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .trust_unchecked::<AuthN, _>(reason!("version is a CAS token only — no leak path"))
            .trust_unchecked::<AuthZ, _>(reason!("version is not an ownership signal"))
            .trust_unchecked::<Replay, _>(reason!(
                "staleness surfaces as VersionMismatch; handler returns 500, client retries"
            ))
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
) -> RunResult<Vec<u8>> {
    use rand::SeedableRng;
    use rand::seq::SliceRandom;

    // Envelope carries `{ key, value }` only — no label. The consumer
    // dispatches by the typed machine `key` (already resolved
    // engine-side); the label's translation set stays inside the TEE so
    // its non-user-locale variants never reach the consumer.
    let mut fields: Vec<_> = d
        .fields
        .iter()
        .map(dto::display_field_from_proto)
        .collect();
    let seed = shuffle_key.derive_envelope_seed(session_id, disclosure_index);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    fields.shuffle(&mut rng);

    let envelope = DisclosureEnvelope {
        version: ENVELOPE_VERSION,
        session_id: session_id.to_string(),
        fields,
    };
    serde_json::to_vec(&envelope).map_err(|e| RunError::msg(format!("disclosure JSON encode: {e}")))
}
