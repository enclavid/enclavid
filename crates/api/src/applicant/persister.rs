//! Seals + persists each reducer round's result to the host-side
//! `SessionStore`. The keyless execution-worker calls back once per `handle`
//! round via `CallbackService::session_change` → [`SessionPersister::persist`];
//! we age-encrypt the disclosure THIS side recorded for the round (present only
//! when a consent-disclosure prompt was accepted) to the client recipient
//! pubkey, then translate state + sealed disclosure into a single atomic Write
//! RPC. The worker reports nothing about consent — see
//! [`SessionPersister::consented`].
//!
//! Atomicity is the whole point: state mutation (consent accepted) and
//! the disclosure entry that records what was shared land in one host
//! transaction. A failed write fails the round under version-CAS; the
//! next attempt re-runs from the last persisted state.
//!
//! Why encryption lives here, not in the executor: state and metadata are
//! already sealed transparently inside hatch-client (`SetState` /
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
//! Lifetime: one persister per round, built inside `SessionRunCtx::run` once
//! the round's consent is known. Owns session-id, the applicant key (state's
//! inner AEAD layer), the client disclosure pubkey (disclosure age recipient),
//! a mutable copy of session metadata (so we can update `disclosure_count`
//! atomically with each persist), and the round's consent. How long the
//! PERSISTER survives is partly the WORKER's choice — the callback client it was
//! handed carries an `Arc` — so the consent is tied to the round instead, by
//! a [`RoundConsent`] the round's own frame owns, of which this holds a `Weak` —
//! the same arrangement as the applicant token beside it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use tokio::sync::Mutex;

use axum::http::StatusCode;
use secrecy::{ExposeSecret, SecretBox};

use enclavid_boundary::{AuthN, AuthZ, Covert, Replay, reason};
use enclavid_crypto::seal_to_recipient;
use hatch_client::{
    AppendDisclosure, DisplayField, Event, Prompt, SessionMetadata, SessionState, SessionStatus,
    SessionStore, SetMedia, SetMetadata, SetState, WriteField, boundary, encode_padded,
};
// Owned wire types — the keyless execution-worker sends these back over the
// `CallbackService`; `CallbackError` replaces the old wasmtime `RunError` as the
// persist error, keeping api free of the runtime.
use engine_rpc::{CallbackError, RunStatus};

use crate::disclosure_commit;
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
    /// `disclosure_count` and the `disclosure_entry_hashes` set-commitment
    /// leaf list whenever a round seals a disclosure and rewrite metadata
    /// atomically alongside the state + append ops. Other metadata
    /// fields stay constant across the session lifetime; this is
    /// purely a bookkeeping wrapper.
    pub metadata: Mutex<SessionMetadata>,
    /// The fields this round may seal, decided by THIS side before the worker
    /// ran — from the pre-round `current_prompt` and the accepted event, the
    /// same pair `/input` already bound the applicant's echoed digest to.
    /// `None` on every round that is not an accepted consent.
    ///
    /// A constructor argument, not something a caller remembers to set: the
    /// value is the whole point of the persister existing, and a field that can
    /// be left unset is a product that silently stops disclosing.
    ///
    /// WEAK handle to what this round may seal — the same shape, and for the
    /// same reason, as `applicant_session_token` above: the round's frame is the
    /// sole strong owner, so these plaintext fields live exactly as long as the
    /// round and this side never pins them. A `None` from `upgrade` means the
    /// round is over and this callback is late.
    ///
    /// Held across a whole `persist` and cleared only once the write commits, so
    /// a second callback in the same round seals nothing, and a write that fails
    /// does not consume an acceptance the applicant already gave.
    consented: Weak<Mutex<Option<Vec<DisplayField>>>>,
    /// WEAK handle to the frames this round captured, on the same terms as
    /// `consented` above: the round's frame owns them, this side never pins
    /// them. No lock, unlike the consent, because nothing consumes it — sealing
    /// the same frame twice writes identical bytes under an identical content
    /// key. The gate-set extend below is the part that is NOT idempotent, and it
    /// dedups for that reason.
    captures: Weak<Vec<([u8; 32], Vec<u8>)>>,
    /// Process-lifetime shuffle key, used to permute `DisplayField`
    /// order inside disclosure envelopes before they're sealed to
    /// the consumer. Lives here (and not in engine) because the
    /// covert-channel target is the consumer-bound envelope only —
    /// the applicant-bound consent screen renders policy order
    /// unchanged for UX consistency. See `crate::shuffle` for the
    /// HKDF derivation chain and threat model.
    pub shuffle_key: Arc<ShuffleKey>,
}

/// The round's sole strong hold on what it may disclose. `run` binds one for the
/// life of the round; the persister keeps only a `Weak`, exactly as it does for
/// the applicant token.
///
/// Dropping it frees the applicant's plaintext fields on every exit the frame
/// has — the `?` paths and a panic included — with no destructor to write and no
/// call to remember. How long the PERSISTER lives is partly the worker's choice,
/// since the callback client it was handed carries an `Arc`; how long this lives
/// is not.
pub(super) type RoundConsent = Arc<Mutex<Option<Vec<DisplayField>>>>;

/// The round's sole strong hold on the frames it captured, held by the round's
/// own frame exactly as [`RoundConsent`] is.
pub(super) type RoundCaptures = Arc<Vec<([u8; 32], Vec<u8>)>>;

/// The frames this round captured, content-addressed on THIS side.
///
/// They are the applicant's own bytes, read off `/input` and sent to the worker
/// in this very event; the worker derives the same BLAKE3 over the same bytes
/// (`engine-executor`'s `runner::convert`). So there is nothing here to accept
/// from it — only something to recompute, which is the cheaper of the two and
/// the only one that means anything.
pub(super) fn round_captures(event: &Event) -> RoundCaptures {
    Arc::new(match event {
        Event::Media(result) => result
            .clip
            .frames
            .iter()
            .map(|frame| (blake3::hash(frame).into(), frame.clone()))
            .collect(),
        _ => Vec::new(),
    })
}

/// What this round may seal, decided from the round's own inputs.
///
/// Derived here rather than accepted ready-made: a caller that can hand over the
/// answer is a caller that can hand over the wrong one, and a `None` passed by
/// mistake is a product that silently stops disclosing — which no type catches
/// and no test short of a full round would either.
pub(super) fn round_consent(event: &Event, current_prompt: &Option<Prompt>) -> RoundConsent {
    Arc::new(Mutex::new(super::shared::consent_for_round(
        event,
        current_prompt,
    )))
}

impl SessionPersister {
    /// One persister per round, handed out as a [`RoundPersister`] so the
    /// round's consent cannot outlive the round — which is also why this is not
    /// a `new`: there is deliberately no way to obtain the bare persister.
    ///
    /// Borrows the round's [`RoundConsent`] rather than owning it: the caller's
    /// frame is the lifetime, this side keeps a `Weak`. Taking it by reference is
    /// also what makes the owner impossible to bind to `_` and lose — see the
    /// field.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn for_round(
        session_store: Arc<SessionStore>,
        session_id: String,
        applicant_session_token: Weak<SecretBox<Vec<u8>>>,
        client_disclosure_pubkey: String,
        version: u64,
        metadata: SessionMetadata,
        consent: &RoundConsent,
        captures: &RoundCaptures,
        shuffle_key: Arc<ShuffleKey>,
    ) -> Arc<Self> {
        Arc::new(Self {
            session_store,
            session_id,
            applicant_session_token,
            client_disclosure_pubkey,
            current_version: AtomicU64::new(version),
            metadata: Mutex::new(metadata),
            consented: Arc::downgrade(consent),
            captures: Arc::downgrade(captures),
            shuffle_key,
        })
    }

    /// api side of the keyless executor's `CallbackService::session_change`:
    /// seal + persist one round's post-`state`, together with the consent and the
    /// captures THIS side recorded for the round, in ONE atomic host transaction.
    /// Only `state` arrives over rpc; the other two are `Weak` upgrades of values
    /// the round's own frame owns, because the worker has nothing to say about
    /// either. The seal key stays orchestrator-side. A failed write fails the
    /// round under version-CAS; the next attempt re-runs from the last persisted
    /// state.
    ///
    /// What the round consented to is NOT a parameter: see
    /// [`SessionPersister::consented`].
    pub(super) async fn persist(&self, state: SessionState) -> Result<(), CallbackError> {
        // Serialize the whole critical section on the metadata guard, taken
        // before the acceptance is claimed: a second callback in the same round
        // waits here rather than interleaving with this one.
        let mut metadata = self.metadata.lock().await;

        // What gets sealed is what THIS side derived before the round. The
        // worker is the one process here that executes adversary-supplied code,
        // so a disclosure it asserted would be no evidence that an applicant ever
        // accepted a screen — which is why it no longer carries one. Ours is
        // evidence: `/input` refused the accept unless the applicant's echoed
        // digest matched this same `current_prompt`.
        // Both round-scoped and owned by the same frame, so they expire together:
        // a `None` from either means this callback outlived its round.
        let consent = self.consented.upgrade().ok_or_else(|| {
            CallbackError("persist: the round's consent outlived its context".into())
        })?;
        let media = self.captures.upgrade().ok_or_else(|| {
            CallbackError("persist: the round's captures outlived their context".into())
        })?;
        let mut consented = consent.lock().await;
        let to_seal: &[Vec<DisplayField>] = consented.as_slice();

        // The shuffle is seeded from the disclosure_count BEFORE this batch, so
        // distinct envelopes get independent, replay-stable permutations.
        let starting_index = metadata.disclosure_count;
        let appends = self.seal_disclosures(to_seal, starting_index)?;

        // Borrow the applicant token from the per-round owner once for this
        // whole seal. The `SessionRunCtx` driving this run holds the sole strong
        // ref (bound across `executor.run().await`), so it is alive here; a
        // `None` means the run outlived its context — a lifetime bug that fails
        // the round. `token` stays alive for the whole block, so the `&[u8]` the
        // seal builders below borrow from it outlives them.
        let token = self.applicant_session_token.upgrade().ok_or_else(|| {
            CallbackError(
                "persist: applicant token owner dropped (run outlived its context)".into(),
            )
        })?;
        let token_bytes = token.expose_secret().as_slice();

        // Everything below advances a WORKING COPY. This side's own metadata is
        // republished only once the host has the write, so a failure leaves us
        // exactly as the host is — nothing counted, no leaf hash for an entry
        // that was never appended. Counting on the way in meant a failed persist
        // and a later successful one in the same round left the chain short of
        // its own count, and the consumer's pull 500s on that mismatch forever.
        let mut working = metadata.clone();
        let commit = {
            let set_state = self.build_state_op(&state, token_bytes)?;
            // Seal every captured frame this round into the media store,
            // co-committed with the state (kept in a local so the `&dyn` refs
            // below outlive the write). `media_ops` owns its bytes, so reading
            // `media` again below is fine.
            let media_ops = self.build_media_ops(&media, token_bytes);
            // Record this round's captured blob hashes — the TEE-side
            // authoritative set the NEXT round's `from-blob-ref` gate reads, and
            // now api's own: `round_captures` computed them over the applicant's
            // frames, so a hash that later passes the gate is the hash of a frame
            // of this session.
            //
            // The host does NOT see these hashes: a media write is keyed by
            // `media_field_name`, an HKDF of `tee_seal_key` whose whole purpose is
            // that the raw content hash never leaves the TEE. What carrying them
            // in metadata costs the host is 32 B of growth per blob — the same
            // count it reads off the `SetMedia` ops in this very batch.
            //
            // Deduped: unlike a `SetMedia`, which upserts the same bytes under the
            // same key, extending this set twice would double-count a frame.
            for (hash, _) in media.iter() {
                let hash = hash.to_vec();
                if !working.captured_media.contains(&hash) {
                    working.captured_media.push(hash);
                }
            }
            let mut ops: Vec<&dyn WriteField> =
                Vec::with_capacity(2 + appends.len() + media_ops.len());
            ops.push(&set_state);

            // Rewrite metadata when this commit emitted a disclosure (extends the
            // disclosure-hash chain) OR captured media (appends to the gate set).
            // Plain rounds stay SetState-only, keeping the payload small.
            let set_metadata_holder;
            if !appends.is_empty() || !media_ops.is_empty() {
                set_metadata_holder = self.build_metadata_op(&mut working, &appends);
                ops.push(&set_metadata_holder);
            }
            ops.extend(appends.iter().map(|a| a as &dyn WriteField));
            ops.extend(media_ops.iter().map(|m| m as &dyn WriteField));

            self.commit_ops(&ops).await
        };
        commit?;

        // The host has it. Now, and only now, spend the acceptance and publish
        // the bookkeeping that describes what was written.
        *metadata = working;
        *consented = None;
        Ok(())
    }

    /// Seal the round's consented fields into an append op: shuffle the
    /// envelope (Covert), the applicant's own acceptance (AuthZ), age-seal to
    /// the consumer recipient (AuthN). `starting_index` seeds the per-envelope
    /// shuffle so distinct envelopes get independent, replay-stable
    /// permutations. Returns owned, fully-vouched append ops. At most one entry
    /// today — a round accepts at most one consent — but it stays a slice so the
    /// index arithmetic keeps working if that changes.
    fn seal_disclosures(
        &self,
        disclosures: &[Vec<DisplayField>],
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
                        "this side derived the envelope from the pre-round current_prompt on an \
                         accepted consent event, and /input had already refused that accept \
                         unless the applicant's echoed digest matched the same prompt — so this \
                         is the SET of fields the applicant was shown and accepted. Their \
                         CONTENTS are only as audited as they are legible: sanitize_string runs \
                         in the execution-worker, so a value can still carry what the screen did \
                         not render"
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
    /// AuthN is closed inside hatch-client by the double AEAD-seal (inner
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

    /// Build a `SetMedia` op per frame the APPLICANT captured this round and api
    /// recorded — every one of them, unconditionally ("always store"), so
    /// write-presence carries no policy bandwidth. That used to rest on the
    /// runtime reporting its captures honestly; the set is now api's own, so it
    /// rests on nothing. AuthN is closed inside hatch-client by the double
    /// AEAD-seal (inner under `applicant_session_token`, outer under
    /// `tee_seal_key`, AAD = session_id||blob_hash); AuthZ + Covert vouched here.
    /// Covert is NOT padded (unlike state): what a frame's length reveals is the
    /// applicant's own upload, partitioned, and there is no policy-controlled
    /// quantity left to pad.
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
                        "each op is one frame api itself read off /input and content-addressed \
                         here, so op COUNT and each op's LENGTH are functions of the applicant's \
                         upload alone — the per-frame partition of a body the host already \
                         watched arrive encrypted. The worker supplies no byte, no hash and no \
                         member, and a non-media round emits zero ops. Unpadded unlike state \
                         because no policy-controlled quantity is left to pad; residual is that \
                         the worker still chooses whether to call session_change at all"
                    )),
                applicant_session_token: token,
            })
            .collect()
    }

    /// Advance the disclosure bookkeeping (count + running hash chain) and
    /// build the `SetMetadata` op carrying the updated metadata (disclosure
    /// chain AND the captured-media gate set, which the caller appended before
    /// this). AuthN is closed inside hatch-client by the AEAD-seal under
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
            // fully-vouched ciphertext to append its per-entry leaf hash to the
            // set-commitment leaf list before the same bytes get released to wire
            // by `build_op`. Order of the list is irrelevant (commit() sorts).
            metadata
                .disclosure_entry_hashes
                .push(disclosure_commit::entry_hash(a.0.as_inner()));
        }
        SetMetadata(
            boundary::outbound::to_untrusted(&*metadata)
                .vouch_unchecked::<AuthZ, _>(reason!(
                    "only the attested CVM holds tee_seal_key; read as opaque ciphertext on \
                     /connect — release implicit in key-possession"
                ))
                .vouch_unchecked::<Covert, _>(reason!(
                    "sealed under tee_seal_key; caveat: ciphertext size + write-presence \
                     host-observable. Metadata now grows 32 B per disclosure (one leaf hash) = \
                     a deterministic function of the disclosure count M, which the host ALREADY \
                     observes via each ListAppend — zero marginal covert bits, and the emission- \
                     ORDER channel (log2 M!) is REMOVED (set commitment sorts). Residual write- \
                     presence is host-compromise-gated, as before. The captured-media gate hashes \
                     also carried are NOT host-visible — a media write is keyed by an HKDF of \
                     tee_seal_key so the raw hash never leaves the TEE — but they grow this blob \
                     by 32 B per frame, a count the host reads off the SetMedia ops in this same \
                     batch anyway"
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
                // The cause, on the inward tier, before the error flows back over
                // the callback: a persist-side write failure surfaces to the
                // worker as a failed `session_change`, which fails the run, and
                // what actually went wrong would otherwise be reduced to a 5xx.
                safe_logger::debug!(
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
    /// TTL is enforced inside the storage-CVM off the per-session
    /// deadline (no host-visible status byte).
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
        let fields: [&dyn WriteField; 1] = [&set_metadata];
        let ops = boundary::outbound::to_untrusted(&fields[..])
            .vouch_unchecked::<AuthN, _>(reason!(
                "recipe set; each field's content is sealed in its own build_op"
            ))
            .vouch_unchecked::<AuthZ, _>(reason!("each op writes its own session key"))
            .vouch_unchecked::<Covert, _>(reason!("1 op (sealed metadata), fixed by finalize"));
        let new_version = self
            .session_store
            .write(session_id, expected_version, ops)
            .await
            .map_err(|e| {
                safe_logger::debug!(
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

/// Build the padded JSON envelope plaintext for one engine disclosure.
/// Closes the `Covert` concern in the outbound boundary chain on BOTH of
/// its axes: field ORDER is shuffled via a per-envelope HKDF'd ChaCha20
/// permutation (so policy-encoded bits can't reach the consumer through
/// ordering), and the envelope is padded to a constant SIZE
/// ([`pad_envelope`]) so the host-observable age-ciphertext length can't
/// relay the policy-controlled field byte-lengths. The subsequent
/// `vouch::<AuthN>(seal_to_recipient)` closes confidentiality.
///
/// `session_id` is embedded in the envelope as defense-in-depth:
/// the metadata-level set commitment already binds the per-session
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
    fields: &[DisplayField],
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
    let mut fields: Vec<_> = fields.iter().map(dto::display_field_from_proto).collect();
    let seed = shuffle_key.derive_envelope_seed(session_id, disclosure_index);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    fields.shuffle(&mut rng);

    let envelope = DisclosureEnvelope {
        version: ENVELOPE_VERSION,
        session_id: session_id.to_string(),
        fields,
    };
    let mut bytes = serde_json::to_vec(&envelope)
        .map_err(|e| CallbackError(format!("disclosure JSON encode: {e}")))?;
    // Close the SIZE covert channel: pad to a constant plaintext frame so the
    // plaintext handed to age is a fixed length regardless of the policy-controlled
    // field values. An un-padded entry relays value byte-length ~1:1 into the
    // ciphertext length a colluding host reads (surviving the visual consent
    // audit); once the plaintext is pinned, the ciphertext length carries only
    // age's content-independent per-seal jitter. Mirrors state's `encode_padded`.
    pad_envelope(&mut bytes)?;
    Ok(bytes)
}

/// Constant plaintext size every disclosure envelope is padded to before it is
/// age-sealed. The sealed PLAINTEXT is then a fixed length regardless of the
/// policy's field values, so the host-observable ciphertext length carries no
/// policy content — age adds only content-independent per-seal header jitter on
/// top (its ciphertext length tracks plaintext LENGTH, never content). The
/// disclosure counterpart to state's `SEALED_STATE_PLAINTEXT_BYTES`. Must exceed
/// the largest legitimate envelope: `MAX_CONSENT_FIELDS` (20) fields ×
/// `MAX_VALUE_LENGTH` (4096-byte) values, JSON-escaped (~2× worst case for a value
/// of quotes/backslashes; control chars are stripped upstream by `sanitize`), plus
/// the machine keys and JSON structure — ≈166 KiB. 256 KiB is comfortable headroom.
/// Raising the consent caps raises this frame (and each entry's seal cost) in
/// lockstep, exactly like state; an envelope over the frame traps the seal
/// (fail-safe).
const SEALED_DISCLOSURE_PLAINTEXT_BYTES: usize = 256 * 1024;

/// Pad a serialized disclosure envelope to [`SEALED_DISCLOSURE_PLAINTEXT_BYTES`]
/// with trailing ASCII spaces. Trailing whitespace is ignored by every conformant
/// JSON parser (RFC 8259: a JSON text is `ws value ws`), so the consumer decrypts
/// and parses the envelope unchanged — no wire-format change, no envelope-schema
/// field, no SDK change. Errors if the envelope already exceeds the frame.
fn pad_envelope(bytes: &mut Vec<u8>) -> Result<(), CallbackError> {
    if bytes.len() > SEALED_DISCLOSURE_PLAINTEXT_BYTES {
        return Err(CallbackError(format!(
            "disclosure envelope is {} bytes, over the {SEALED_DISCLOSURE_PLAINTEXT_BYTES}-byte \
             sealed-disclosure frame",
            bytes.len(),
        )));
    }
    bytes.resize(SEALED_DISCLOSURE_PLAINTEXT_BYTES, b' ');
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hatch_client::{Clip, DisplayField, MediaResult};

    fn media_round(frames: Vec<&[u8]>) -> Event {
        Event::Media(MediaResult {
            slot: 0,
            clip: Clip {
                frames: frames.into_iter().map(<[u8]>::to_vec).collect(),
            },
        })
    }

    /// The whole point of the change: the pairs are a function of the applicant's
    /// own bytes, computed here. Nothing is accepted from the worker, so nothing
    /// is checked — but the derivation itself has to be right, because a later
    /// `from-blob-ref` resolves against exactly these hashes and the worker
    /// derives its own copy independently.
    #[test]
    fn captures_are_this_side_s_blake3_over_the_applicants_frames() {
        let frames: Vec<&[u8]> = vec![b"passport-frame-1", b"passport-frame-2"];
        let captured = round_captures(&media_round(frames.clone()));

        assert_eq!(captured.len(), 2, "every frame is recorded, in order");
        for (i, (hash, bytes)) in captured.iter().enumerate() {
            assert_eq!(bytes.as_slice(), frames[i], "the applicant's own bytes");
            assert_eq!(
                hash,
                blake3::hash(frames[i]).as_bytes(),
                "the content address the engine will independently derive",
            );
        }
    }

    /// A repeated frame keeps both entries: the seal upserts the same bytes under
    /// the same key, and the gate-set extend dedups on the way in.
    #[test]
    fn a_repeated_frame_is_recorded_twice_under_one_address() {
        let captured = round_captures(&media_round(vec![b"same", b"same"]));
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].0, captured[1].0);
    }

    /// Rounds that carry no capture seal no media — a consent accept must not
    /// write blobs, and the genesis round has none to write.
    #[test]
    fn a_round_without_a_capture_records_nothing() {
        assert!(round_captures(&Event::Start).is_empty());
        assert!(round_captures(&Event::ConsentDisclosure(true)).is_empty());
        assert!(round_captures(&media_round(vec![])).is_empty());
    }

    fn field(key: &str, value: &str) -> DisplayField {
        DisplayField {
            key: key.into(),
            label: Default::default(),
            value: value.into(),
        }
    }

    #[test]
    fn envelope_is_padded_to_a_constant_frame_and_still_parses() {
        let sk = ShuffleKey::from_tee_seal_key(&[7u8; 32]);
        let small = vec![field("first_name", "Al")];
        let big = vec![
            field("first_name", &"A".repeat(3000)),
            field("dob", "1990-01-01"),
        ];

        let a = shuffle_to_envelope_bytes(&small, "sid", 0, &sk).unwrap();
        let b = shuffle_to_envelope_bytes(&big, "sid", 1, &sk).unwrap();

        // Constant size regardless of content → the host sees no per-entry size
        // signal (the whole point of V10).
        assert_eq!(a.len(), SEALED_DISCLOSURE_PLAINTEXT_BYTES);
        assert_eq!(b.len(), SEALED_DISCLOSURE_PLAINTEXT_BYTES);

        // Trailing-space padding is ignored by a conformant JSON parser, so the
        // consumer parses the padded envelope with no SDK change.
        let v: serde_json::Value = serde_json::from_slice(&a).unwrap();
        assert_eq!(v["version"], ENVELOPE_VERSION);
        assert_eq!(v["session_id"], "sid");
        assert_eq!(v["fields"][0]["value"], "Al");
    }

    #[test]
    fn envelope_over_the_frame_traps() {
        // A pathological envelope past the frame fails the seal (fail-safe),
        // rather than silently leaking size by emitting a larger ciphertext.
        let sk = ShuffleKey::from_tee_seal_key(&[9u8; 32]);
        let huge = vec![field("k", &"x".repeat(SEALED_DISCLOSURE_PLAINTEXT_BYTES))];
        assert!(shuffle_to_envelope_bytes(&huge, "sid", 0, &sk).is_err());
    }
}
