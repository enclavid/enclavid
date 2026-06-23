//! Wire DTOs shared between the TEE-side `broker-client` and the
//! host-side `broker`. These are the request/response envelopes that
//! cross the vsock HTTP boundary.
//!
//! They are NOT the sealed domain types: `SessionMetadata` /
//! `SessionState` are CBOR-encoded TEE-side (see
//! `broker-client::domain`) then AEAD-sealed, and the broker only ever
//! sees the opaque `value` bytes carried inside these envelopes — it
//! has zero knowledge of what the sealed bytes mean.
//!
//! Bodies are encoded with CBOR (see [`encode`]/[`decode`]) and carried
//! as `application/octet-stream`. CBOR's named fields give schema
//! evolution across independent broker/broker-client deploys. Control-
//! flow outcomes (deny, version conflict, not-found) ride on HTTP status
//! codes, not body fields:
//!   - 401 Unauthorized        — bad credential
//!   - 403 Forbidden           — credential valid, operation not permitted
//!   - 404 Not Found           — session/manifest absent
//!   - 412 Precondition Failed — write `expected_version` mismatch (CAS)
//!   - 400 / 500               — malformed request / internal error

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------

/// Failure to encode or decode a wire envelope.
#[derive(Debug)]
pub struct CodecError(pub String);

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "broker-protocol codec error: {}", self.0)
    }
}

impl std::error::Error for CodecError {}

/// Encode a wire DTO to CBOR bytes for an HTTP body.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| CodecError(e.to_string()))?;
    Ok(buf)
}

/// Decode a wire DTO from CBOR bytes in an HTTP body.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    ciborium::from_reader(bytes).map_err(|e| CodecError(e.to_string()))
}

// ---------------------------------------------------------------------
// Auth  (POST /authorize)
// ---------------------------------------------------------------------

/// Client API operations the broker RBAC-gates. The TEE always sets
/// this; the broker decides whether the credential's permissions cover
/// it. Adding a variant is a shared-crate change visible to both sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientOperation {
    /// POST /api/v1/sessions — create + activate.
    SessionCreate,
    /// GET /api/v1/sessions/:id — read session view.
    SessionRead,
    /// GET /api/v1/sessions/:id/disclosures — pull consented data.
    DataRead,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeRequest {
    /// Verbatim HTTP `Authorization` header value. The broker detects
    /// scheme and validates; the TEE never parses it.
    pub authorization_header: String,
    pub operation: ClientOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeResponse {
    /// Authenticated principal (opaque identity string), or None when
    /// the auth scheme produces none. Deny paths are HTTP 401 / 403,
    /// not represented here.
    pub principal: Option<String>,
}

// ---------------------------------------------------------------------
// OCI pull  (POST /oci/pull)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequest {
    /// Full pinned OCI reference `<registry>/<repo>@sha256:<hex>`.
    pub policy_ref: String,
    /// Opaque bearer the broker attaches as `Authorization` (empty =
    /// anonymous). Forwarded verbatim from the TEE.
    pub registry_auth: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullResponse {
    /// Raw OCI manifest JSON bytes (digest is over these exact bytes).
    pub manifest: Vec<u8>,
    /// Hex `sha256:<hex>` of `manifest`; the TEE re-verifies it.
    pub manifest_digest: String,
    /// Layer payloads, same order as the manifest's `layers[]`. The TEE
    /// recomputes each layer digest before trusting bytes.
    pub layers: Vec<Vec<u8>>,
}

// ---------------------------------------------------------------------
// KBS relay  (POST /kbs/relay)
//
// The TEE has no outbound network, so it reaches an artifact-key broker
// (KBS) through the broker as a semantic HTTP proxy. The TEE-side driver
// runs the KBS attestation handshake (RCAR: auth -> challenge ->
// attestation -> resource) as a state machine and forwards each leg
// through here; the broker is a DUMB, STATELESS byte forwarder — it
// dials `endpoint`, replays method/path/headers/body, and returns the
// response verbatim. The released secret is JWE-wrapped to the TEE's
// ephemeral key, so the broker never sees plaintext key material even
// though it carries the bytes.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KbsRelayRequest {
    /// KBS origin the broker dials, e.g. `https://kbs.example.com:8080`.
    /// Untrusted routing target supplied by the client at session create;
    /// trust rides on the JWE-to-ephemeral-key response, not this value.
    pub endpoint: String,
    /// HTTP method for this leg (`GET` / `POST`).
    pub method: String,
    /// Request path on the KBS, e.g. `/kbs/v0/auth`.
    pub path: String,
    /// Headers to replay (carries the RCAR session cookie / token across
    /// legs; the TEE driver threads these, the broker just forwards).
    pub headers: Vec<(String, String)>,
    /// Request body bytes for this leg (opaque to the broker).
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KbsRelayResponse {
    /// KBS HTTP status for this leg; the TEE driver branches on it.
    pub status: u16,
    /// Response headers (the TEE driver reads the RCAR session cookie).
    pub headers: Vec<(String, String)>,
    /// Response body bytes (opaque to the broker).
    pub body: Vec<u8>,
}

// The RCAR application protocol (auth / attestation / resource bodies,
// JWE-wrapped resource) is the standard Trustee wire; it lives in the
// `kbs-types` crate and is driven TEE-side by `enclavid-kbs-client`. The
// broker only ever sees those opaque bytes inside a relay body — no
// enclavid-specific KBS DTOs cross this boundary.

// ---------------------------------------------------------------------
// Session store
//   POST   /sessions/{id}/read   (ReadRequest  -> ReadResponse)
//   POST   /sessions/{id}/write  (WriteRequest -> WriteResponse | 412)
//   DELETE /sessions/{id}/state  (-> DeleteResponse)        [/reset]
//   HEAD   /sessions/{id}        (-> 200 | 404)             [exists]
// ---------------------------------------------------------------------

/// Scalar fields — one value per (session, field). STATUS + PRINCIPAL
/// are plaintext/broker-visible; METADATA + STATE are opaque ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlobField {
    Status,
    Metadata,
    State,
    Principal,
}

/// List fields — append-only ordered sequences per (session, field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ListField {
    /// Age-sealed disclosure entries (opaque ciphertext to the broker).
    Disclosure,
}

/// Selector for one field in a read. Picks scalar or list shape.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum FieldSelector {
    Blob(BlobField),
    List(ListField),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadRequest {
    /// Fields to read. **Empty = version probe**: the response carries
    /// the current version and no slots (used to read the version
    /// without paying any field bandwidth).
    pub fields: Vec<FieldSelector>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResponse {
    /// Same length + order as `ReadRequest.fields`; each slot's variant
    /// matches the selector's kind at that index.
    pub slots: Vec<Slot>,
    /// Current session version; 0 if the session does not exist.
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Slot {
    Scalar(ScalarSlot),
    List(ListSlot),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalarSlot {
    /// `None` = field absent; `Some(empty)` = present-but-empty. The
    /// distinction is load-bearing: a default-valued `SessionMetadata`
    /// serializes to empty bytes, and must not read back as "absent".
    pub value: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSlot {
    /// All entries in append order. Empty when absent or never written.
    pub items: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteRequest {
    /// Ops applied atomically (single Redis EVAL). Mixing scalar writes
    /// and list appends in one call is the common case (state update +
    /// accumulated disclosure entries).
    pub ops: Vec<Op>,
    /// Optimistic-concurrency gate. `Some(v)` applies only if the
    /// session's current version == v (else 412). `None` means "the
    /// session must not exist yet" (used by session creation).
    pub expected_version: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Op {
    /// Replace a scalar field's value.
    Blob(BlobWrite),
    /// Append to a list field.
    ListAppend(ListAppend),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobWrite {
    pub field: BlobField,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListAppend {
    pub field: ListField,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteResponse {
    /// Session version after the write. Callers chain subsequent writes
    /// by feeding this back as the next `expected_version`.
    pub new_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResponse {
    /// 1 if the field had a value and was removed, 0 if already absent.
    /// Informational; not a security signal.
    pub deleted: u64,
}
