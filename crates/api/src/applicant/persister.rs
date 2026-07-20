//! Seals + persists each reducer round's result to the host-side
//! `SessionStore`. The keyless execution-worker calls back once per `handle`
//! round via `CallbackService::session_change` → [`SessionPersister::persist`];
//! we age-encrypt any disclosure the runtime sealed that round (non-empty only
//! when a consent-disclosure prompt was accepted) to the client recipient
//! pubkey, then translate state + sealed disclosures into a single atomic Write
//! RPC.
//!
//! Atomicity is the whole point: state mutation (consent accepted) and
//! the disclosure entry that records what was shared land in one host
//! transaction. A failed write fails the round under version-CAS; the
//! next attempt re-runs from the last persisted state.
//!
//! Why encryption lives here, not in the executor: state and metadata are
//! already sealed transparently inside broker-client (`SetState` /
//! `SetMetadata` AEAD with `tee_seal_key`/`applicant_session_token`). Disclosures use
//! a different scheme (age to the consumer's `client_disclosure_pubkey`)
//! but the architectural slot is the same — the orchestrator owns "I/O +
//! encryption keys" and the worker never holds either, staying keyless.
//!
//! `client_disclosure_pubkey` is a public age recipient for outbound
//! disclosure ciphertexts only — the consumer holds the matching
//! secret. This persister is concerned with the disclosure flow; the
//! policy artifact path is independent.
//!
//! Lifetime: one persister per run. Owns session-id, the applicant key (state's
//! inner AEAD layer), the client disclosure pubkey (disclosure age recipient),
//! and a mutable copy of session metadata (so we can update `disclosure_count`
//! atomically with each persist). Cheap to construct; dropped when the round's
//! `SessionRunCtx` finishes.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use tokio::sync::Mutex;

use axum::http::StatusCode;
use secrecy::{ExposeSecret, SecretBox};

use broker_client::{
    AppendDisclosure, AuthN, AuthZ, Covert, Replay, SessionMetadata, SessionState, SessionStatus,
    SessionStore, SetMedia, SetMetadata, SetState, SetStatus, WriteField, boundary, encode_padded,
    reason,
};
use enclavid_crypto::seal_to_recipient;
// Owned wire types — the keyless execution-worker sends these back over the
// `CallbackService`; `CallbackError` replaces the old wasmtime `RunError` as the
// persist error, keeping api free of the runtime.
use rpc::{CallbackError, ConsentDisclosure, RunStatus};

use crate::disclosure_hash;
use crate::dto::{self, DisclosureEnvelope, ENVELOPE_VERSION};
use crate::shuffle::ShuffleKey;

pub(super) struct SessionPersister {
    pub session_store: Arc<SessionStore>,
    pub session_id: String,
    /// WEAK handle to the applicant bearer — the inner AEAD layer's key,
    /// needed to SEAL state + media on each write. `Weak` (not owned): the
    /// per-round `SessionRunCtx` is the sole strong owner, so the persister
    /// borrows the token for the moment of a seal but never PINS the
    /// plaintext. Upgraded once per `persist`; a `None` means the
    /// run outlived its context (a lifetime bug) and fails the round.
    pub applicant_session_token: Weak<SecretBox<Vec<u8>>>,
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

impl SessionPersister {
    /// api side of the keyless executor's `CallbackService::session_change`:
    /// seal + persist one round's post-`state`, plus any consented `disclosures`
    /// (non-empty only on a consent-disclosure accept) and captured `media`
    /// (present only on a media round), in ONE atomic host transaction. The
    /// worker sent these over rpc as OWNED wire types, so — unlike the old
    /// borrowed-`SessionChange` listener — nothing here borrows the run; the
    /// seal key stays orchestrator-side. A failed write fails the round under
    /// version-CAS; the next attempt re-runs from the last persisted state.
    pub(super) async fn persist(
        &self,
        state: SessionState,
        disclosures: Vec<ConsentDisclosure>,
        media: Vec<([u8; 32], Vec<u8>)>,
    ) -> Result<(), CallbackError> {
        // Seal the consented disclosures into append ops. The shuffle is seeded
        // from the disclosure_count BEFORE this batch (a brief metadata lock to
        // read it), so distinct envelopes get independent, replay-stable
        // permutations.
        let starting_index = self.metadata.lock().await.disclosure_count;
        let appends = self.seal_disclosures(&disclosures, starting_index)?;

        // Borrow the applicant token from the per-round owner once for this
        // whole seal. The `SessionRunCtx` driving this run holds the sole strong
        // ref (bound across `executor.run().await`), so it is alive here; a
        // `None` means the run outlived its context — a lifetime bug that fails
        // the round. `token` stays alive for the whole block, so the `&[u8]` the
        // seal builders below borrow from it outlives them.
        let token = self.applicant_session_token.upgrade().ok_or_else(|| {
            CallbackError("persist: applicant token owner dropped (run outlived its context)".into())
        })?;
        let token_bytes = token.expose_secret().as_slice();

        // Hold the metadata lock across the write: the state mutation, the
        // disclosure entry, and the captured media all land in one atomic host
        // transaction. The run serializes callbacks, so contention is theoretical.
        let mut metadata = self.metadata.lock().await;
        let set_state = self.build_state_op(&state, token_bytes)?;
        // Seal every captured frame this round into the media store,
        // co-committed with the state (kept in a local so the `&dyn` refs below
        // outlive the write). `media_ops` owns its bytes, so reading `media`
        // again below is fine.
        let media_ops = self.build_media_ops(&media, token_bytes);
        // Record this round's captured blob hashes into metadata — the TEE-side
        // authoritative set the NEXT round's `from-blob-ref` gate reads. The
        // host already knows these hashes (they are the plaintext keys of its
        // own media writes), so carrying them sealed here leaks nothing new.
        if !media.is_empty() {
            metadata
                .captured_media
                .extend(media.iter().map(|(h, _)| h.to_vec()));
        }
        let mut ops: Vec<&dyn WriteField> =
            Vec::with_capacity(2 + appends.len() + media_ops.len());
        ops.push(&set_state);

        // Rewrite metadata when this commit emitted a disclosure (extends the
        // disclosure-hash chain) OR captured media (appends to the gate set).
        // Plain rounds stay SetState-only, keeping the payload small.
        let set_metadata_holder;
        if !appends.is_empty() || !media_ops.is_empty() {
            set_metadata_holder = self.build_metadata_op(&mut metadata, &appends);
            ops.push(&set_metadata_holder);
        }
        ops.extend(appends.iter().map(|a| a as &dyn WriteField));
        ops.extend(media_ops.iter().map(|m| m as &dyn WriteField));

        self.commit_ops(&ops).await
    }

    /// Seal each engine-emitted disclosure into an append op: shuffle
    /// the envelope (Covert), consent-gate (AuthZ), age-seal to the
    /// consumer recipient (AuthN). `starting_index` seeds the per-
    /// envelope shuffle so distinct envelopes get independent, replay-
    /// stable permutations. Returns owned, fully-vouched append ops.
    fn seal_disclosures(
        &self,
        disclosures: &[ConsentDisclosure],
        starting_index: u64,
    ) -> Result<Vec<AppendDisclosure>, CallbackError> {
        disclosures
            .iter()
            .enumerate()
            .map(|(i, d)| -> Result<AppendDisclosure, CallbackError> {
                let sealed = boundary::outbound::to_untrusted(d)
                    .vouch::<Covert, _, _, _, _>(|d| -> Result<Vec<u8>, CallbackError> {
                        shuffle_to_envelope_bytes(
                            d,
                            &self.session_id,
                            starting_index + i as u64,
                            &self.shuffle_key,
                        )
                    })?
                    .vouch_unchecked::<AuthZ, _>(reason!(
                        "the runtime seals this disclosure only after an accepted \
                         consent-disclosure prompt (show == seal, gated runtime-side); api only \
                         serializes the post-consent record"
                    ))
                    .vouch::<AuthN, _, _, _, _>(|bytes| -> Result<Vec<u8>, CallbackError> {
                        seal_to_recipient(&bytes, &self.client_disclosure_pubkey)
                            .map_err(|e| CallbackError(format!("disclosure seal failed: {e}")))
                    })?;
                Ok(AppendDisclosure(sealed))
            })
            .collect()
    }

    /// Build the `SetState` op from the engine's opaque state blob.
    /// AuthN is closed inside broker-client by the double AEAD-seal (inner
    /// under `applicant_session_token`, outer under `tee_seal_key`); AuthZ
    /// vouched here; Covert CLOSED here by `encode_padded`, which encodes the
    /// `SessionState` and pads it to a constant plaintext frame so the sealed
    /// ciphertext size is fixed. Fallible: an encoding over the frame traps.
    fn build_state_op<'a>(
        &self,
        state: &SessionState,
        token: &'a [u8],
    ) -> Result<SetState<'a>, CallbackError> {
        Ok(SetState {
            state: boundary::outbound::to_untrusted(state)
                .vouch_unchecked::<AuthZ, _>(reason!(
                    "inner-AEAD'd to applicant_session_token; receipt of ciphertext is not \
                     access — AuthZ implicit in key possession"
                ))
                .vouch::<Covert, _, _, _, _>(|state| -> Result<Vec<u8>, CallbackError> {
                    // Close the size covert channel BY DOING it here: encode +
                    // pad the WHOLE SessionState to a constant plaintext frame,
                    // so the sealed ciphertext is fixed-size regardless of the
                    // `state` and `current_prompt` content (both policy-
                    // controlled). Errors if the encoding exceeds the frame.
                    encode_padded(state).map_err(|e| CallbackError(format!("state pad: {e}")))
                })?,
            applicant_session_token: token,
        })
    }

    /// Build a `SetMedia` op per frame the runtime captured this round. Every
    /// capture is sealed unconditionally — "always store" — so the media path
    /// is uniform and write-presence carries no policy bandwidth. AuthN is
    /// closed inside broker-client by the double AEAD-seal (inner under
    /// `applicant_session_token`, outer under `tee_seal_key`, AAD =
    /// session_id||blob_hash); AuthZ + Covert vouched here. Covert is NOT
    /// padded (unlike state): the blob size is applicant-capture-driven and
    /// already host-observable via the `/input` body length, so it is not a
    /// new channel.
    fn build_media_ops<'a>(
        &self,
        media: &[([u8; 32], Vec<u8>)],
        token: &'a [u8],
    ) -> Vec<SetMedia<'a>> {
        media
            .iter()
            .map(|(hash, bytes)| SetMedia {
                blob_hash: *hash,
                bytes: boundary::outbound::to_untrusted(bytes.clone())
                    .vouch_unchecked::<AuthZ, _>(reason!(
                        "inner-AEAD'd to applicant_session_token; receipt of ciphertext is not \
                         access — AuthZ implicit in key possession"
                    ))
                    .vouch_unchecked::<Covert, _>(reason!(
                        "blob size is applicant-capture-driven — already host-observable at the \
                         /input body length, so not a NEW channel; every capture is stored \
                         unconditionally (always-store), so write-presence carries no policy bandwidth"
                    )),
                applicant_session_token: token,
            })
            .collect()
    }

    /// Advance the disclosure bookkeeping (count + running hash chain) and
    /// build the `SetMetadata` op carrying the updated metadata (disclosure
    /// chain AND the captured-media gate set, which the caller appended before
    /// this). AuthN is closed inside broker-client by the AEAD-seal under
    /// `tee_seal_key`. Called when this commit emitted disclosures or captured
    /// media; `appends` may be empty on a media-only round.
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
                     K fuel-bounded); host-compromise-gated. The captured-media gate hashes it \
                     now also carries are the host's OWN plaintext media-write keys — no new leak"
                )),
        )
    }

    /// Vouch the write envelope (session id + version + op set) and
    /// commit it at the current expected version, advancing
    /// `current_version` on success. The version verdict is host-
    /// supplied (a CAS token only): a lying host self-limits to DoS / a
    /// stomped concurrent winner, with no data-leak path.
    async fn commit_ops(&self, ops: &[&dyn WriteField]) -> Result<(), CallbackError> {
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
                // eprintln before the error flows back over the callback: a
                // persist-side write failure surfaces to the worker as a failed
                // `session_change`, which fails the run; the actual cause must
                // show up in the logs before it is reduced to a 5xx.
                eprintln!(
                    "persister.commit_ops: session_store.write failed for {} \
                     (expected version {expected}): {e}",
                    self.session_id,
                );
                CallbackError(format!("persist failed: {e}"))
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
) -> Result<Vec<u8>, CallbackError> {
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
    serde_json::to_vec(&envelope)
        .map_err(|e| CallbackError(format!("disclosure JSON encode: {e}")))
}
