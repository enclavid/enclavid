//! Domain-level session storage client.
//!
//! Wraps the `SessionStore` gRPC service. Each per-session field
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

mod aead;
mod core;
mod disclosure;
mod metadata;
mod state;
mod status;

pub use self::core::{ReadField, ReadTuple, WriteField};
pub use disclosure::{AppendDisclosure, Disclosure};
pub use metadata::{Metadata, SetMetadata};
pub use state::{SetState, State};
pub use status::{SetStatus, Status};

use std::sync::Arc;

use enclavid_untrusted::{AuthN, Replay, Untrusted, reason};
use tonic::transport::Channel;

use crate::error::BridgeError;
use crate::proto::session_store::read_response::Slot;
use crate::proto::session_store::session_store_client::SessionStoreClient;
use crate::proto::session_store::write_request::Op;
use crate::proto::session_store::{
    BlobField, DeleteRequest, ExistsRequest, FieldSelector, ReadRequest, WriteRequest,
};
use crate::transport::GrpcChannel;

/// Per-call encryption context. Carries the TEE-side key plus the
/// session_id used as AAD, so a ciphertext copied between sessions
/// fails authentication.
pub struct Ctx<'a> {
    pub tee_key: &'a [u8],
    pub session_id: &'a str,
}

impl Ctx<'_> {
    fn aad(&self) -> &[u8] {
        self.session_id.as_bytes()
    }
}

#[derive(Clone)]
pub struct SessionStore {
    client: SessionStoreClient<Channel>,
    /// TEE-side AEAD key used for METADATA and as outer layer of STATE.
    /// Phase A: caller injects (random or env-supplied placeholder).
    /// Phase B: derived from attestation report / KMS-bound material.
    /// `Arc` so cloning the store is cheap (tonic clones it on every
    /// RPC) without copying 32 bytes each time.
    tee_key: Arc<[u8; 32]>,
}

impl SessionStore {
    pub fn new(channel: GrpcChannel, tee_key: [u8; 32]) -> Self {
        Self {
            client: SessionStoreClient::new(channel),
            tee_key: Arc::new(tee_key),
        }
    }

    pub(crate) fn tee_key(&self) -> &[u8] {
        self.tee_key.as_slice()
    }

    /// Read typed session fields in one batch. Returns
    /// `(fields, version)` where each field carries its own
    /// per-field scope (`Untrusted<_, S>` matching what the field's
    /// `decode` couldn't establish) and `version` is wrapped in
    /// `Untrusted<u64, (AuthN, Replay)>`. Pass `version` back to the
    /// next `write` to detect concurrent modifications.
    /// `version == 0` (after peel) means the session does not exist
    /// yet on the host.
    pub async fn read<T: ReadTuple>(
        &self,
        id: &str,
        fields: T,
    ) -> Result<(T::Output, Untrusted<u64, (AuthN, Replay)>), BridgeError> {
        fields.fetch(self, id).await
    }

    /// Atomic write of any number of field ops in one transaction.
    /// `fields` is a heterogeneous slice of `&dyn WriteField`, mixing
    /// static markers (`SetState`, `SetMetadata`, `SetStatus`) with
    /// dynamic-buffer entries (`AppendDisclosure` from a policy run).
    /// All ops commit together; the host applies them atomically
    /// alongside the version check.
    ///
    /// `expected_version` is the version check: `None` means the
    /// session must not exist yet (used by /create); `Some(V)` means
    /// the session's current version on the host must equal V.
    /// Mismatch surfaces as `BridgeError::VersionMismatch`.
    ///
    /// Returns the new version so callers chaining writes within a
    /// run (e.g. the engine persister) feed it forward without an
    /// extra read.
    ///
    /// Each `build_op` returns `Exposed<Op>` — the seal-output. We
    /// `release()` only here, at the wire boundary, just before the
    /// gRPC send. That's the single point where TEE-side data
    /// becomes raw bytes on the channel.
    pub async fn write(
        &self,
        id: &str,
        expected_version: Option<u64>,
        fields: &[&dyn WriteField],
    ) -> Result<Untrusted<u64, (AuthN, Replay)>, BridgeError> {
        let ctx = Ctx { tee_key: self.tee_key(), session_id: id };
        let mut ops: Vec<Op> = Vec::with_capacity(fields.len());
        for f in fields {
            ops.push(f.build_op(&ctx)?.release());
        }
        let response = self
            .client
            .clone()
            .write(WriteRequest {
                session_id: id.to_string(),
                ops,
                expected_version,
            })
            .await?;
        Ok(Untrusted::new(response.into_inner().new_version, reason!(r#"
Host-supplied counter. The TEE feeds it as `expected_version`
on the next write — a lying host either fails the next CAS (DoS)
or stomps a concurrent winner (UX regression), no data leak.
AuthZ N/A: counter is not an ownership signal.
        "#)))
    }

    /// Delete a scalar field's value. Today only used to drop session
    /// state on `/reset`; exposed as a typed method rather than via a
    /// tuple because we have no use case for batched delete.
    pub async fn delete(&self, id: &str) -> Result<Untrusted<u64, (AuthN, Replay)>, BridgeError> {
        let response = self
            .client
            .clone()
            .delete(DeleteRequest {
                session_id: id.to_string(),
                field: BlobField::State as i32,
            })
            .await?;
        Ok(Untrusted::new(response.into_inner().deleted, reason!(r#"
Deletion-count is informational; no security gate hangs on it.
Host can fabricate (AuthN open) or echo a stale value (Replay
open). AuthZ N/A.
        "#)))
    }

    pub async fn exists(&self, id: &str) -> Result<Untrusted<bool, (AuthN, Replay)>, BridgeError> {
        let response = self
            .client
            .clone()
            .exists(ExistsRequest {
                session_id: id.to_string(),
            })
            .await?;
        Ok(Untrusted::new(response.into_inner().exists, reason!(r#"
Existence is a host-controlled boolean — advisory only. Actual
gating happens via decryption / workspace check elsewhere.
AuthN open (fabrication possible), Replay open (stale state).
AuthZ N/A: a presence-bit isn't an ownership signal.
        "#)))
    }

    // ---- tuple-trait helper (crate-private) ----
    //
    // Slots come back as raw `Vec<Slot>` (each slot's content gets
    // wrapped per-field inside `ReadField::decode`); the version is
    // wrapped here at the bridge boundary since it's a host-supplied
    // counter.
    pub(crate) async fn read_raw(
        &self,
        id: &str,
        selectors: Vec<FieldSelector>,
    ) -> Result<(Vec<Slot>, Untrusted<u64, (AuthN, Replay)>), BridgeError> {
        let response = self
            .client
            .clone()
            .read(ReadRequest {
                session_id: id.to_string(),
                fields: selectors,
            })
            .await?;
        // Slots are returned in the same order as request selectors per
        // the host contract; we trust that ordering here. Out-of-order
        // or missing slots would be a host bug.
        let inner = response.into_inner();
        Ok((inner.slots, Untrusted::new(inner.version, reason!(r#"
Host-supplied counter we pin against on subsequent writes —
same shape as the version from `write`. AuthN/Replay open;
AuthZ N/A. Slots carry their own per-field scopes set inside
each ReadField::decode.
        "#))))
    }
}
