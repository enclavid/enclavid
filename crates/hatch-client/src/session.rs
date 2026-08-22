//! Domain-level session storage client.
//!
//! Talks to the hatch session-store endpoints. Each per-session field
//! (`status`, `metadata`, `state`, `disclosure`) lives in its own
//! sub-module — read marker, write marker, encode/decode logic
//! co-located by domain so adding a new field is a single new file.
//! The shared trait machinery (`ReadField` / `WriteField` /
//! `ReadTuple` + macro) lives in `core`.
//!
//! Use sites:
//! ```ignore
//! // Read returns (typed_fields, version). Pass the version back
//! // to the next write to detect concurrent modifications.
//! let ((status, metadata), version) = session_store
//!     .read(&id, (Status, Metadata))
//!     .await?
//!     .trust_unchecked();
//!
//! // Write at the expected version; returns the post-write version.
//! let new_v = session_store.write(&id, Some(version), &[
//!     &SetMetadata(&metadata),
//!     &SetStatus(SessionStatus::Running),
//! ]).await?.trust_unchecked();
//!
//! // /create writes with `None` (session must not exist yet):
//! session_store.write(&id, None, &[&SetMetadata(&m), &SetStatus(...)]).await?;
//! ```
//!
//! Tuple arities up to 16 supported via macro-unrolled trait impls.
//! Each call site picks the fields it needs; wire transfer is
//! proportional (status-only read = 1-byte payload, no metadata
//! baggage).

mod core;
mod disclosure;
mod media;
mod metadata;
mod principal;
mod state;
mod status;

pub use self::core::{ReadField, ReadTuple, WriteField};
pub use disclosure::{AppendDisclosure, Disclosure};
pub use media::SetMedia;
pub use metadata::{Metadata, SetMetadata};
pub use principal::SetPrincipal;
pub use state::{SEALED_STATE_PLAINTEXT_BYTES, SetState, State, encode_padded};
pub use status::{SetStatus, Status};

use std::sync::Arc;

use secrecy::{ExposeSecret, SecretBox};

use hatch_protocol::{FieldSelector, Op, ReadRequest, Slot, WriteRequest};

use enclavid_crypto::aead;

use crate::backend::SessionBackend;
use crate::boundary::{AuthN, AuthZ, Replay, Untrusted};
use crate::error::BridgeError;
use crate::{Exposed, boundary};

/// Per-call encryption context. Carries the TEE-side key plus the
/// session_id used as AAD, so a ciphertext copied between sessions
/// fails authentication.
pub struct Ctx<'a> {
    pub tee_seal_key: &'a [u8],
    pub session_id: &'a str,
}

impl Ctx<'_> {
    fn aad(&self) -> &[u8] {
        self.session_id.as_bytes()
    }
}

#[derive(Clone)]
pub struct SessionStore {
    /// Transport seam (hatch HTTP today, storage-CVM remoc tomorrow). All crypto
    /// stays HERE; the backend moves opaque DTOs. `Arc<dyn _>` keeps this store a
    /// concrete type so `Arc<SessionStore>` doesn't ripple generics through api.
    backend: Arc<dyn SessionBackend>,
    /// TEE-side AEAD master key used for METADATA and as the outer layer of
    /// STATE — the hardware-rooted crown jewel every session seal derives from.
    /// Phase A: caller injects (random or env-supplied placeholder).
    /// Phase B: derived from attestation report / KMS-bound material.
    /// `SecretBox` zeroizes it on drop and redacts it from any `Debug` — so the
    /// master never lands in a log, matching how the applicant token is held; the
    /// `Arc` keeps cloning the store cheap (the store derives `Clone`).
    tee_seal_key: Arc<SecretBox<[u8; 32]>>,
    /// ABSOLUTE session lifetime in seconds. `Some(t)` ⇒ the deadline is set ONCE
    /// at create to `created_at + t` and never refreshed — a fixed cap after which
    /// the storage-CVM sweeper GCs the session (abandoned or completed-and-pulled),
    /// enforced INSIDE the trust boundary (the plaintext host STATUS byte is gone).
    /// Sized so the consumer has time to pull disclosures post-completion. `None` =
    /// no expiry (the legacy hatch/Redis backend ignores the deadline regardless).
    ttl_secs: Option<u64>,
}

impl SessionStore {
    pub fn new(backend: Arc<dyn SessionBackend>, tee_seal_key: [u8; 32], ttl_secs: Option<u64>) -> Self {
        Self {
            backend,
            tee_seal_key: Arc::new(SecretBox::new(Box::new(tee_seal_key))),
            ttl_secs,
        }
    }

    pub(crate) fn tee_seal_key(&self) -> &[u8] {
        self.tee_seal_key.expose_secret().as_slice()
    }

    /// The absolute deadline (unix secs) for a session created NOW, or `None` when
    /// no TTL is configured. Computed TEE-side and passed inside the RA-TLS channel
    /// ONLY on the create write (see [`write`](Self::write)); subsequent writes
    /// pass `None` so the deadline is never moved.
    fn create_deadline(&self) -> Option<u64> {
        self.ttl_secs.map(|ttl| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            now.saturating_add(ttl)
        })
    }

    /// Read typed session fields in one batch. Returns
    /// `(fields, version)` where each field carries its own per-field
    /// scope and `version` is wrapped in `Untrusted<u64, (AuthN, AuthZ,
    /// Replay)>`. Pass `version` back to the next `write` to detect
    /// concurrent modifications. `version == 0` (after peel) means the
    /// session does not exist yet on the hatch.
    pub async fn read<T: ReadTuple>(
        &self,
        id: Exposed<&str>,
        fields: T,
    ) -> Result<(T::Output, Untrusted<u64, (AuthN, AuthZ, Replay)>), BridgeError> {
        // Type gate: the caller vouches the session id — TEE-minted, NOT
        // host-assigned (see `boundary::outbound::outbound_session_id`); a
        // locator the store gates nothing on. We thread the `Exposed`
        // into `fetch`/`read_raw`
        // (no early `into_inner`): the id is released at the wire (URL)
        // inside `read_raw`, and read back as AAD via `as_inner` in
        // `fetch` for decoding the result blobs.
        fields.fetch(self, id).await
    }

    /// Atomic write of any number of field ops in one transaction.
    /// `fields` is a heterogeneous slice of `&dyn WriteField`, mixing
    /// static markers (`SetState`, `SetMetadata`, `SetStatus`) with
    /// dynamic-buffer entries (`AppendDisclosure`). The hatch applies
    /// them atomically (single Lua EVAL) alongside the version check.
    ///
    /// `expected_version` is the version check: `None` means the
    /// session must not exist yet (used by /create); `Some(V)` means
    /// the session's current version on the hatch must equal V.
    /// Mismatch surfaces as `BridgeError::VersionMismatch` (HTTP 412).
    ///
    /// Every parameter arrives as `Exposed<_, ()>` — fully vouched at
    /// the **caller** before `write` is reached, so the signature is the
    /// type-level guarantee that nothing un-vouched can be written:
    ///   * `id` / `expected_version` — vouched at the caller as one
    ///     `boundary::outbound::to_untrusted((id, version))` tuple (see
    ///     `api::client::create`): a TEE-minted record address, for which
    ///     `outbound_session_id` carries the same reasoning, plus the
    ///     store's own counter.
    ///   * `fields` — `boundary::outbound::to_untrusted(&ops)` carries only the
    ///     collection-level concern, cardinality (`Covert`), which the
    ///     caller peels with a count acknowledgement. Each member's
    ///     content concerns (`AuthN`/`AuthZ`) are closed PER FIELD below
    ///     in `build_op`, with that field's own key/recipient — they are
    ///     deliberately NOT a collection-level concern (metadata AEAD vs
    ///     state double-AEAD vs disclosure age-sealed-to-consumer vs
    ///     plaintext status are not the same concern, so they can't be
    ///     bundled into one batch vouch).
    pub async fn write(
        &self,
        id: Exposed<&str>,
        expected_version: Exposed<Option<u64>>,
        fields: Exposed<&[&dyn WriteField]>,
    ) -> Result<Untrusted<u64, (AuthN, AuthZ, Replay)>, BridgeError> {
        let id = id.into_inner();
        let fields = fields.into_inner();
        let ctx = Ctx {
            tee_seal_key: self.tee_seal_key(),
            session_id: id,
        };
        let mut ops: Vec<Exposed<Op>> = Vec::with_capacity(fields.len());
        for f in fields {
            ops.push(f.build_op(&ctx)?);
        }

        // Absolute TTL: set the deadline ONLY on the create write (`None` =
        // must-not-exist); on every subsequent update pass `None` so the fixed
        // `created_at + ttl` cap is never moved.
        let deadline = if expected_version.as_inner().is_none() {
            self.create_deadline()
        } else {
            None
        };
        let ops: Exposed<Vec<Op>, ()> = ops.into();
        let req = ops.map(|ops| WriteRequest {
            ops,
            expected_version: expected_version.into_inner(),
        });
        let new_version = self.backend.write(id, req.into_inner(), deadline).await?;
        Ok(new_version.into())
    }

    /// Delete the session's state field. Today only used to drop session
    /// state on `/reset`; exposed as a typed method rather than via a
    /// tuple because we have no use case for batched delete.
    pub async fn delete(
        &self,
        id: Exposed<&str>,
    ) -> Result<Untrusted<u64, (AuthN, AuthZ, Replay)>, BridgeError> {
        let id = id.into_inner();
        let deleted = self.backend.delete(id).await?;
        Ok(boundary::inbound::from_untrusted(deleted))
    }

    /// Read + double-open one sealed media blob by its content hash. Backs the
    /// policy's `blob::from-blob-ref` rehydrate. `None` = no such blob in this
    /// session (the engine turns a miss into a TRAP). The plaintext comes back
    /// `Untrusted<_, (Replay,)>` — outer-AEAD-open closes AuthN (real crypto),
    /// inner-AEAD-open closes AuthZ (applicant-key possession authorises); only
    /// Replay remains for the caller (trivially closed: the blob is
    /// content-addressed, so a stale / reordered read can only return identical
    /// bytes). AAD = session_id||blob_hash, mirroring [`SetMedia`].
    pub async fn load_media(
        &self,
        id: Exposed<&str>,
        blob_hash: &[u8; 32],
        applicant_session_token: &[u8],
    ) -> Result<Untrusted<Option<Vec<u8>>, (Replay,)>, BridgeError> {
        // Read the id for the AAD + the host field name before `read_raw` releases
        // it at the URL. The AAD binds to the raw content hash (TEE-internal), but
        // the HOST field name is the identity-hiding per-session HKDF — recomputed
        // here so it matches what `SetMedia` wrote.
        let aad = media::media_aad(id.as_inner(), blob_hash);
        let field = media::media_field_name(self.tee_seal_key(), id.as_inner(), blob_hash);
        let req = core::read_request(vec![FieldSelector::Media(field)]);
        let (slots, _version) = self.read_raw(id, req).await?;
        let slot = slots
            .into_iter()
            .next()
            .ok_or_else(|| BridgeError::Transport("media read returned no slot".to_string()))?;
        let Some(sealed) = core::unwrap_scalar(slot)? else {
            return Ok(Untrusted::new(None));
        };
        let opened: Untrusted<Vec<u8>, (Replay,)> = boundary::inbound::from_untrusted(sealed)
            .trust::<AuthN, _, _, _, _>(|raw| aead::open(&raw, self.tee_seal_key(), &aad))?
            .trust::<AuthZ, _, _, _, _>(|outer| {
                aead::open(&outer, applicant_session_token, &aad)
            })?;
        Ok(opened.map(Some))
    }

    pub async fn exists(
        &self,
        id: Exposed<&str>,
    ) -> Result<Untrusted<bool, (AuthN, AuthZ, Replay)>, BridgeError> {
        let id = id.into_inner();
        let exists = self.backend.exists(id).await?;
        Ok(boundary::inbound::from_untrusted(exists))
    }

    // ---- tuple-trait helper (crate-private) ----
    //
    // Slots come back as raw `Vec<Slot>` (each slot's content gets
    // wrapped per-field inside `ReadField::decode`); the version is
    // wrapped here at the bridge boundary since it's a hatch-supplied
    // counter.
    pub(crate) async fn read_raw(
        &self,
        id: Exposed<&str>,
        req: Exposed<ReadRequest>,
    ) -> Result<(Vec<Slot>, Untrusted<u64, (AuthN, AuthZ, Replay)>), BridgeError> {
        // Both arrive vouched (id by the api caller, the selector request
        // by `fetch` which builds it) — we just release them at the wire.
        let id = id.into_inner();
        // Slots are returned in the same order as request selectors per the
        // backend contract; we trust that ordering here. Out-of-order or missing
        // slots would be a backend bug.
        let (slots, version) = self.backend.read_raw(id, req.into_inner()).await?;
        Ok((slots, boundary::inbound::from_untrusted(version)))
    }
}
