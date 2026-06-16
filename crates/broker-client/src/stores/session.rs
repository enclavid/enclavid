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

mod aead;
mod core;
mod disclosure;
mod metadata;
mod principal;
mod state;
mod status;

pub use self::core::{ReadField, ReadTuple, WriteField};
pub use disclosure::{AppendDisclosure, Disclosure};
pub use metadata::{Metadata, SetMetadata};
pub use principal::SetPrincipal;
pub use state::{SetState, State};
pub use status::{SetStatus, Status};

use std::sync::Arc;

use broker_protocol::{FieldSelector, Op, ReadRequest, Slot, WriteRequest};
use hyper::StatusCode;

use crate::{Exposed, boundary};
use crate::boundary::{AuthN, AuthZ, Covert, Replay, Untrusted};
use crate::error::BridgeError;
use crate::reason;
use crate::transport::BrokerClient;

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
        id: &str,
        fields: T,
    ) -> Result<(T::Output, Untrusted<u64, (AuthN, AuthZ, Replay)>), BridgeError> {
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
    /// Each `build_op` returns `Exposed<Op, ()>` — every outbound
    /// concern has been vouched for inside the implementation. We
    /// `into_inner()` only here, at the wire boundary. That's the
    /// single point where TEE-side data becomes raw bytes on the wire.
    pub async fn write(
        &self,
        id: &str,
        expected_version: Option<u64>,
        fields: &[&dyn WriteField],
    ) -> Result<Untrusted<u64, (AuthN, AuthZ, Replay)>, BridgeError> {
        let ctx = Ctx {
            tee_seal_key: self.tee_seal_key(),
            session_id: id,
        };
        let mut ops: Vec<Exposed<Op>> = Vec::with_capacity(fields.len());
        for f in fields {
            ops.push(f.build_op(&ctx)?);
        }
        // Each op earned its `()` via build_op's real work (metadata /
        // state AEAD-sealed under tee_seal_key; disclosure age-sealed
        // for the consumer). Transpose the batch via `From` — the
        // body's `()` is *derived* from the ops, not re-asserted — then
        // fold in the public version counter via a scope-preserving
        // `map`. session_id rides the URL path.
        let ops: Exposed<Vec<Op>, ()> = ops.into();
        let req = ops.map(|ops| WriteRequest {
            ops,
            expected_version,
        });
        let bytes = broker_protocol::encode(&req.into_inner())?;
        let resp = self
            .broker
            .post(&format!("/sessions/{id}/write"), bytes)
            .await?;
        match resp.status {
            StatusCode::OK => {
                let r: broker_protocol::WriteResponse = broker_protocol::decode(&resp.body)?;
                Ok(boundary::inbound::from_host(r.new_version, reason!(r#"
Session version counter (new_version) from /write response.
Broker-supplied; the bridge does no work-backed close on any
concern — boundary returns maximal scope and the caller (the
endpoint that knows the CAS-feed-forward use) peels with rationale.
                "#)))
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
        id: &str,
    ) -> Result<Untrusted<u64, (AuthN, AuthZ, Replay)>, BridgeError> {
        let resp = self
            .broker
            .delete(&format!("/sessions/{id}/state"))
            .await?;
        match resp.status {
            StatusCode::OK => {
                let r: broker_protocol::DeleteResponse = broker_protocol::decode(&resp.body)?;
                Ok(boundary::inbound::from_host(r.deleted, reason!(r#"
Delete-row count from /sessions/{id}/state response. Broker-supplied;
no work-backed close at this layer — caller peels with rationale (the
typical one is "informational only; no security gate hangs on it").
                "#)))
            }
            s => Err(BridgeError::Transport(format!("delete: status {s}"))),
        }
    }

    pub async fn exists(
        &self,
        id: &str,
    ) -> Result<Untrusted<bool, (AuthN, AuthZ, Replay)>, BridgeError> {
        let status = self.broker.head(&format!("/sessions/{id}")).await?;
        let exists = match status {
            StatusCode::OK => true,
            StatusCode::NOT_FOUND => false,
            s => return Err(BridgeError::Transport(format!("exists: status {s}"))),
        };
        Ok(boundary::inbound::from_host(exists, reason!(r#"
Existence probe answer from HEAD /sessions/{id}. Broker-supplied; no
work-backed close at this layer — caller peels with rationale.
        "#)))
    }

    // ---- tuple-trait helper (crate-private) ----
    //
    // Slots come back as raw `Vec<Slot>` (each slot's content gets
    // wrapped per-field inside `ReadField::decode`); the version is
    // wrapped here at the bridge boundary since it's a broker-supplied
    // counter.
    pub(crate) async fn read_raw(
        &self,
        id: &str,
        selectors: Vec<FieldSelector>,
    ) -> Result<(Vec<Slot>, Untrusted<u64, (AuthN, AuthZ, Replay)>), BridgeError> {
        let req = boundary::outbound::to_host(
            ReadRequest { fields: selectors },
            reason!("ReadRequest → broker POST /sessions/{id}/read"),
        )
        .vouch_unchecked::<AuthN, _>(reason!(
            "selectors are field-kind enum tags only — no secret, no applicant data leaves"
        ))
        .vouch_unchecked::<AuthZ, _>(reason!(
            "a read request releases no TEE data; it names which fields to fetch back"
        ))
        .vouch_unchecked::<Covert, _>(reason!(
            "selector set is bounded by the field enum cardinality; no policy bandwidth"
        ));
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
                let version = boundary::inbound::from_host(r.version, reason!(r#"
Session version counter (current_version) from /read response.
Broker-supplied; no work-backed close at this layer — caller peels.
                "#));
                Ok((r.slots, version))
            }
            s => Err(BridgeError::Transport(format!("read: status {s}"))),
        }
    }
}
