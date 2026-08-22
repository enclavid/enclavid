//! Host media store the keyless execution-worker calls BACK for
//! `blob::from-blob-ref` (via `CallbackService::media_load`) — a **pull** over
//! the sealed hatch backing store, with a **gate** on the read key. It runs
//! orchestrator-side because it holds the seal key + applicant token the worker
//! must never see.
//!
//! `blob::from-blob-ref` mints a COLD handle (no load); the worker calls
//! [`load`](HatchMediaStore::load) LAZILY on the first `bytes()` read of that
//! handle, which forwards to this callback. This:
//!   1. **gates** an unknown hash — a ref not in the session's captured set is a
//!      fabricated key, refused here with no hatch read (the worker then traps,
//!      since `from-blob-ref` has no miss branch);
//!   2. **pulls** the sealed blob from the backing store
//!      ([`SessionStore::load_media`]), decrypts, and returns the bytes. The
//!      decrypted plaintext is a SINGLE transient handed to the caller — never
//!      retained api-side, so no cross-session decrypted-PII pool accumulates in
//!      the orchestrator heap.
//!
//! No api-side cache. An earlier cross-round pull-through `MediaCache` was
//! removed. Its covert-defence value was illusory against the adversary it
//! targeted: the host controls the L4 balancer, so a colluding host forces a
//! cache MISS every round (route each round to a cold instance) — it even WANTS
//! misses, since a hatch pull is the observable signal — while an honest host
//! never decodes anything. Meanwhile it was the ONLY long-lived decrypted-
//! biometric pool in the orchestrator (memory-hygiene finding M1). Removing it
//! makes the api stateless-for-correctness and closes M1; the marginal
//! cross-round re-pull it saved is bounded elsewhere (below). There is nothing
//! to zeroize on this side once the cache is gone: the plaintext is a single
//! moved transient, not a retained buffer.
//!
//! Covert-channel role (defence-in-depth; primary defence is attestation +
//! consent-gate). A colluding policy could encode data into the read KEY
//! (`blob_hash`, 32 B/call) or into the COUNT / pattern of reads (Morse). Both
//! are bounded TEE-side (host-routing-independent):
//!
//!   * **The read KEY** — killed by the captured-hash gate below: only real
//!     captures ever pull, whose hashes the host already logged at write; a
//!     fabricated hash returns `None` with no hatch read.
//!   * **The read COUNT / pattern** — bounded WITHIN a round by the worker's
//!     per-run memo (`RelayMediaStore` on the execution-worker: repeat reads of
//!     one blob emit ≤1 RPC), and ACROSS rounds by the applicant-driven round
//!     count — there is no policy `continue`, so each round needs an applicant
//!     `/input`; the policy cannot inflate rounds, only drag the applicant via
//!     retakes (UX-self-limiting). The practical residual is a few bytes,
//!     collusion-gated, the same class as APSI query counts.
//!
//! Tighter covert bounds (an RA-TLS storage-CVM to hide the read key + access
//! pattern from the host, then size-bucketing and traffic shaping) are a future
//! transport/service-layer phase that does NOT touch this call-site.

use std::collections::HashSet;
use std::sync::{Arc, Weak};

use hatch_client::{Replay, SessionStore, outbound_session_id, reason};
use engine_rpc::CallbackError;
use secrecy::{ExposeSecret, SecretBox};

pub(super) struct HatchMediaStore {
    pub session_store: Arc<SessionStore>,
    pub session_id: String,
    /// WEAK handle to the applicant bearer — the inner AEAD layer's key,
    /// needed to OPEN a sealed media blob on load. `Weak` (not owned): the
    /// per-round `SessionRunCtx` is the sole strong owner, so this store
    /// borrows the token in the moment (`upgrade` while the run is live) but
    /// can never PIN the plaintext — its lifetime is exactly the round. A
    /// `None` upgrade means the run outlived its context (a lifetime bug),
    /// surfaced as a trap.
    pub applicant_session_token: Weak<SecretBox<Vec<u8>>>,
    /// GATE — the session's captured blob hashes (from sealed metadata, prior
    /// rounds). A rehydrate for a hash NOT in here is a fabricated ref, refused
    /// in-TEE with no hatch read, so the plaintext read key can't carry data.
    pub captured: HashSet<[u8; 32]>,
}

impl HatchMediaStore {
    /// Rehydrate one stored blob by content hash — the api side of the keyless
    /// executor's `CallbackService::media_load`. Returns owned bytes for the
    /// wire (`None` = miss / gated), so the worker's `from-blob-ref` traps on a
    /// `None` exactly as the in-process store did. The seal key never leaves
    /// this side — the worker only ever receives the decrypted bytes it asked
    /// for by an already-captured hash. No caching: the decrypted plaintext is a
    /// single transient returned straight to the caller (no api-side pool → M1
    /// closed).
    pub(super) async fn load(
        &self,
        blob_hash: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, CallbackError> {
        // 1. Gate — an unknown hash is a fabricated ref: refuse with no hatch
        //    read. The worker traps on the `None` (from-blob-ref has no miss branch).
        if !self.captured.contains(blob_hash) {
            return Ok(None);
        }
        // 2. Pull + decrypt on serve. Borrow the token from the per-round owner
        //    for the moment of the open; a `None` upgrade means the run outlived
        //    its context. Nothing is retained: the decrypted blob is returned
        //    straight to the wire, so no decrypted-PII pool lives api-side.
        //    Cross-round re-reads simply re-pull (the worker's per-run memo
        //    dedups repeats within a round).
        let token = self.applicant_session_token.upgrade().ok_or_else(|| {
            CallbackError(
                "media load: applicant token owner dropped (run outlived its context)".into(),
            )
        })?;
        let id = outbound_session_id(&self.session_id);
        let loaded = self
            .session_store
            .load_media(id, blob_hash, token.expose_secret())
            .await
            .map_err(|e| CallbackError(format!("media load failed: {e}")))?
            .trust_unchecked::<Replay, _>(reason!(
                "media blob is content-addressed by BLAKE3; a stale or reordered read \
                 can only return identical bytes"
            ))
            .into_inner();
        Ok(loaded)
    }
}
