//! Domain-level session storage client.
//!
//! Talks to the broker session-store endpoints. Each per-session field
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

use broker_protocol::{FieldSelector, Op, ReadRequest, Slot, WriteRequest};
use hyper::StatusCode;

use enclavid_crypto::aead;

use crate::boundary::{AuthN, AuthZ, Replay, Untrusted};
use crate::error::BridgeError;
use crate::transport::BrokerClient;
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
    broker: BrokerClient,
    /// TEE-side AEAD key used for METADATA and as outer layer of STATE.
    /// Phase A: caller injects (random or env-supplied placeholder).
    /// Phase B: derived from attestation report / KMS-bound material.
    /// `Arc` so cloning the store is cheap without copying 32 bytes.
    tee_seal_key: Arc<[u8; 32]>,
}

impl SessionStore {
    pub fn new(broker: BrokerClient, tee_seal_key: [u8; 32]) -> Self {
        Self {
            broker,
            tee_seal_key: Arc::new(tee_seal_key),
        }
    }

    pub(crate) fn tee_seal_key(&self) -> &[u8] {
        self.tee_seal_key.as_slice()
    }

    /// Read typed session fields in one batch. Returns
    /// `(fields, version)` where each field carries its own per-field
    /// scope and `version` is wrapped in `Untrusted<u64, (AuthN, AuthZ,
    /// Replay)>`. Pass `version` back to the next `write` to detect
    /// concurrent modifications. `version == 0` (after peel) means the
    /// session does not exist yet on the broker.
    pub async fn read<T: ReadTuple>(
        &self,
        id: Exposed<&str>,
        fields: T,
    ) -> Result<(T::Output, Untrusted<u64, (AuthN, AuthZ, Replay)>), BridgeError> {
        // Type gate: the caller vouches the session id (public,
        // host-assigned). We thread the `Exposed` into `fetch`/`read_raw`
        // (no early `into_inner`): the id is released at the wire (URL)
        // inside `read_raw`, and read back as AAD via `as_inner` in
        // `fetch` for decoding the result blobs.
        fields.fetch(self, id).await
    }

    /// Atomic write of any number of field ops in one transaction.
    /// `fields` is a heterogeneous slice of `&dyn WriteField`, mixing
    /// static markers (`SetState`, `SetMetadata`, `SetStatus`) with
    /// dynamic-buffer entries (`AppendDisclosure`). The broker applies
    /// them atomically (single Lua EVAL) alongside the version check.
    ///
    /// `expected_version` is the version check: `None` means the
    /// session must not exist yet (used by /create); `Some(V)` means
    /// the session's current version on the broker must equal V.
    /// Mismatch surfaces as `BridgeError::VersionMismatch` (HTTP 412).
    ///
    /// Every parameter arrives as `Exposed<_, ()>` — fully vouched at
    /// the **caller** before `write` is reached, so the signature is the
    /// type-level guarantee that nothing un-vouched can be written:
    ///   * `id` / `expected_version` — `boundary::outbound::public(...)`
    ///     (host-assigned UUID / the host's own counter; trivially public
    ///     across all outbound concerns).
    ///   * `fields` — `boundary::outbound::batch(...)` carries only the
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

        let ops: Exposed<Vec<Op>, ()> = ops.into();
        let req = ops.map(|ops| WriteRequest {
            ops,
            expected_version: expected_version.into_inner(),
        });
        let bytes = broker_protocol::encode(&req.into_inner())?;
        let resp = self
            .broker
            .post(&format!("/sessions/{id}/write"), bytes)
            .await?;
        
        match resp.status {
            StatusCode::OK => {
                let r: broker_protocol::WriteResponse = broker_protocol::decode(&resp.body)?;
                Ok(r.new_version.into())
            }
            StatusCode::PRECONDITION_FAILED => Err(BridgeError::VersionMismatch),
            s => Err(BridgeError::Transport(format!("write: status {s}"))),
        }
    }

    /// Delete the session's state field. Today only used to drop session
    /// state on `/reset`; exposed as a typed method rather than via a
    /// tuple because we have no use case for batched delete.
    pub async fn delete(
        &self,
        id: Exposed<&str>,
    ) -> Result<Untrusted<u64, (AuthN, AuthZ, Replay)>, BridgeError> {
        let id = id.into_inner();
        let resp = self.broker.delete(&format!("/sessions/{id}/state")).await?;
        match resp.status {
            StatusCode::OK => {
                let r: broker_protocol::DeleteResponse = broker_protocol::decode(&resp.body)?;
                Ok(boundary::inbound::from_untrusted(r.deleted))
            }
            s => Err(BridgeError::Transport(format!("delete: status {s}"))),
        }
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
        // Read the id for the AAD before `read_raw` releases it at the URL.
        let aad = media::media_aad(*id.as_inner(), blob_hash);
        let req = core::read_request(vec![FieldSelector::Media(blob_hash.to_vec())]);
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
        let status = self.broker.head(&format!("/sessions/{id}")).await?;
        let exists = match status {
            StatusCode::OK => true,
            StatusCode::NOT_FOUND => false,
            s => return Err(BridgeError::Transport(format!("exists: status {s}"))),
        };
        Ok(boundary::inbound::from_untrusted(exists))
    }

    // ---- tuple-trait helper (crate-private) ----
    //
    // Slots come back as raw `Vec<Slot>` (each slot's content gets
    // wrapped per-field inside `ReadField::decode`); the version is
    // wrapped here at the bridge boundary since it's a broker-supplied
    // counter.
    pub(crate) async fn read_raw(
        &self,
        id: Exposed<&str>,
        req: Exposed<ReadRequest>,
    ) -> Result<(Vec<Slot>, Untrusted<u64, (AuthN, AuthZ, Replay)>), BridgeError> {
        // Both arrive vouched (id by the api caller, the selector request
        // by `fetch` which builds it) — we just release them at the wire.
        let id = id.into_inner();
        let bytes = broker_protocol::encode(&req.into_inner())?;
        let resp = self
            .broker
            .post(&format!("/sessions/{id}/read"), bytes)
            .await?;
        match resp.status {
            StatusCode::OK => {
                let r: broker_protocol::ReadResponse = broker_protocol::decode(&resp.body)?;
                // Slots are returned in the same order as request
                // selectors per the broker contract; we trust that
                // ordering here. Out-of-order or missing slots would be
                // a broker bug.
                let version = boundary::inbound::from_untrusted(r.version);
                Ok((r.slots, version))
            }
            s => Err(BridgeError::Transport(format!("read: status {s}"))),
        }
    }
}
