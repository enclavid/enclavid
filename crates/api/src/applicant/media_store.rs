//! Host media store the keyless execution-worker calls BACK for
//! `blob::from-blob-ref` (via `RemoteCallbacks::media_load`) — a **pull** over
//! the sealed hatch backing store, with a **gate** on the read key. It runs
//! orchestrator-side because it holds the seal key + the session's data key the
//! worker must never see.
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
//!     captures ever pull, and "real" now means api computed the hash itself over
//!     an applicant frame, not that the worker named it. A fabricated hash
//!     returns `None` with no hatch read. (The host never sees these hashes: a
//!     media write is keyed by an HKDF of `tee_seal_key`, so the raw content
//!     address stays in the TEE.)
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

use enclavid_boundary::Asserted;
use enclavid_boundary::{Exposed, Replay, reason};
use engine_rpc::{CallbackError, MediaBytes, MediaHash};
use storage_client::SessionStore;

use crate::boundary::ExecutionWorker;
use crate::executor::outbound_blob;

use super::callbacks::FromWorker;
use storage_client::DataKeys;

pub(super) struct HatchMediaStore {
    pub session_store: Arc<SessionStore>,
    pub session_id: String,
    /// WEAK handle to the session's data keys — the inner AEAD layer's keys,
    /// one of which OPENS a sealed media blob on load: the one the session
    /// sealed under as the blob was captured. `Weak` (not owned): the
    /// per-round `SessionRunCtx` is the sole strong owner, so this store
    /// borrows the keys in the moment (`upgrade` while the run is live) but
    /// can never PIN the plaintext — its lifetime is exactly the round. A
    /// `None` upgrade means the run outlived its context (a lifetime bug),
    /// surfaced as a trap.
    pub data_keys: Weak<DataKeys>,
    /// GATE — the session's captured blob hashes (from sealed metadata, prior
    /// rounds). A rehydrate for a hash NOT in here is a fabricated ref, refused
    /// in-TEE with no hatch read, so the plaintext read key can't carry data.
    pub captured: HashSet<[u8; 32]>,
}

impl HatchMediaStore {
    /// Rehydrate one stored blob by content hash — the api side of the keyless
    /// executor's `RemoteCallbacks::media_load`. Returns owned bytes for the
    /// wire (`None` = miss / gated), so the worker's `from-blob-ref` traps on a
    /// `None` exactly as the in-process store did. The seal key never leaves
    /// this side — the worker only ever receives the decrypted bytes it asked
    /// for by an already-captured hash. No caching: the decrypted plaintext is a
    /// single transient returned straight to the caller (no api-side pool → M1
    /// closed).
    pub(super) async fn load(
        &self,
        blob_hash: FromWorker<MediaHash>,
    ) -> Result<Exposed<Option<MediaBytes>, (), ExecutionWorker>, CallbackError> {
        // 1. Gate — an unknown hash is a fabricated ref: refuse with no hatch
        //    read. The worker traps on the `None` (from-blob-ref has no miss branch).
        //
        //    BOUND, and the gate is written AS the discharge rather than beside
        //    it: the hash is checked against a set a different party established,
        //    and that kind is work, so the closure cannot be dropped for a
        //    sentence. That buys legibility, not a guarantee — `|h| Ok(h)` would
        //    still type-check. Making the gate load-bearing needs the shape
        //    `storage::scope::Name` uses: a type whose only constructor is the
        //    check. `captured` is a snapshot taken
        //    in the extractor before this round, and this round's own frames are
        //    minted warm engine-side and never come back through here — so what
        //    this serves is always an EARLIER round's blob of THIS session.
        //
        //    Two mechanisms contain it, and neither is "the peer is attested":
        //    the set admits only what this session already stored, and the blob
        //    opens only under this session's data keys with AAD
        //    `session_id‖blob_hash`, so a hash that collides across sessions
        //    still yields nothing.
        //
        //    What the set is worth is settled where it is WRITTEN, and it is no
        //    longer the worker's ledger: `persister::persist` extends it from
        //    `round_captures` — blake3 over the frames api itself read off
        //    `/input` — and `session_change` has no parameter left to report
        //    through. So a hash that passes here is the hash of an applicant
        //    frame of THIS session, and BOUND means what it says rather than
        //    "given a ledger the peer wrote".
        let Ok(blob_hash) = blob_hash.trust_with(Asserted::Bound, |MediaHash(hash)| {
            if self.captured.contains(&hash) {
                Ok(hash)
            } else {
                Err(())
            }
        }) else {
            // A refusal is a release too, and it says one bit: that hash is not one
            // of this session's. The policy chose the hash, so it already knows.
            return Ok(outbound_blob(None));
        };
        let blob_hash = blob_hash.into_inner();
        // 2. Pull + decrypt on serve. Borrow the data keys from the per-round
        //    owner for the moment of the open; a `None` upgrade means the run
        //    outlived its context. Nothing is retained: the decrypted blob is
        //    returned straight to the wire, so no decrypted-PII pool lives
        //    api-side. Cross-round re-reads simply re-pull (the worker's per-run
        //    memo dedups repeats within a round).
        let keys = self.data_keys.upgrade().ok_or_else(|| {
            safe_logger::debug!("media load: data keys owner dropped (run outlived its context)");
            CallbackError
        })?;
        let loaded = self
            .session_store
            .load_media(&self.session_id, &blob_hash, &keys)
            .await
            .map_err(|e| {
                safe_logger::debug!("media load failed: {e}");
                CallbackError
            })?
            .trust(reason!(
                Replay::Idempotent,
                "api is the only writer here and writes bytes only under their own \
                 blake3, so a stale or reordered read returns the one plaintext that \
                 hashes to this key — the applicant's frame itself; the AAD \
                 session_id||blob_hash stops the host relabelling another blob under \
                 it. Recomputing blake3 over what came back would make this a check \
                 rather than a sentence, and is now both cheap and meaningful"
            ))
            .into_inner();
        Ok(outbound_blob(loaded))
    }
}
