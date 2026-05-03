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
//! // Atomic write of metadata + status (e.g. /create or /init Running):
//! session_store.write(&id, &[
//!     &SetMetadata(&metadata),
//!     &SetStatus(SessionStatus::PendingInit),
//! ]).await?.trust_unchecked();
//!
//! // Read multiple fields with typed result:
//! let (status, metadata) = session_store
//!     .read(&id, (Status, Metadata))
//!     .await?
//!     .trust_unchecked();  // (Option<SessionStatus>, Option<SessionMetadata>)
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

use enclavid_untrusted::Untrusted;
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

    pub async fn read<T: ReadTuple>(
        &self,
        id: &str,
        fields: T,
    ) -> Result<Untrusted<T::Output>, BridgeError> {
        fields.fetch(self, id).await
    }

    /// Atomic write of any number of field ops in one transaction.
    /// `fields` is a heterogeneous slice of `&dyn WriteField`, mixing
    /// static markers (`SetState`, `SetMetadata`, `SetStatus`) with
    /// dynamic-buffer entries (`AppendDisclosure` from a policy run).
    /// All ops commit together via the gRPC `Write` RPC; the host
    /// wraps execution in `MULTI/EXEC` so partial commit is not
    /// observable.
    pub async fn write(
        &self,
        id: &str,
        fields: &[&dyn WriteField],
    ) -> Result<Untrusted<()>, BridgeError> {
        let ctx = Ctx { tee_key: self.tee_key(), session_id: id };
        let mut ops: Vec<Op> = Vec::with_capacity(fields.len());
        for f in fields {
            ops.push(f.build_op(&ctx)?);
        }
        self.client
            .clone()
            .write(WriteRequest {
                session_id: id.to_string(),
                ops,
            })
            .await?;
        Ok(Untrusted::new(()))
    }

    /// Delete a scalar field's value. Today only used to drop session
    /// state on `/reset`; exposed as a typed method rather than via a
    /// tuple because we have no use case for batched delete.
    pub async fn delete(&self, id: &str) -> Result<Untrusted<u64>, BridgeError> {
        let response = self
            .client
            .clone()
            .delete(DeleteRequest {
                session_id: id.to_string(),
                field: BlobField::State as i32,
            })
            .await?;
        Ok(Untrusted::new(response.into_inner().deleted))
    }

    pub async fn exists(&self, id: &str) -> Result<Untrusted<bool>, BridgeError> {
        let response = self
            .client
            .clone()
            .exists(ExistsRequest {
                session_id: id.to_string(),
            })
            .await?;
        Ok(Untrusted::new(response.into_inner().exists))
    }

    // ---- tuple-trait helper (crate-private) ----

    pub(crate) async fn read_raw(
        &self,
        id: &str,
        selectors: Vec<FieldSelector>,
    ) -> Result<Untrusted<Vec<Slot>>, BridgeError> {
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
        Ok(Untrusted::new(response.into_inner().slots))
    }
}
