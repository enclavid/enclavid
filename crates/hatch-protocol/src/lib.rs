//! Wire DTOs of the host-side `hatch` over HTTP-over-vsock — the EGRESS
//! envelopes (`AuthorizeRequest`, `ManifestRequest`, `BlobRequest`,
//! `KbsRelayRequest`, `VcekRequest`).
//!
//! Bodies are encoded with CBOR (see [`encode`]/[`decode`]). CBOR's named
//! fields give schema evolution across independent deploys. Control-flow
//! outcomes ride status codes:
//!   - 401 Unauthorized        — bad credential
//!   - 403 Forbidden           — credential valid, operation not permitted
//!   - 429 Too Many Requests   — the principal is past its rate for the operation
//!   - 404 Not Found           — OCI manifest absent
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
        write!(f, "hatch-protocol codec error: {}", self.0)
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

/// Client API operations the hatch RBAC-gates. The TEE always sets
/// this; the hatch decides whether the credential's permissions cover
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
    /// Verbatim HTTP `Authorization` header value. The hatch detects
    /// scheme and validates; the TEE never parses it.
    pub authorization_header: String,
    pub operation: ClientOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeResponse {
    /// Authenticated principal (opaque identity string), or None when
    /// the auth scheme produces none. Deny paths are HTTP 401 / 403 /
    /// 429, not represented here.
    pub principal: Option<String>,
}

/// Body of a 429 from `/authorize`: the credential holds, but its principal
/// has asked for this operation more often than it may.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimited {
    /// When the principal may ask again, in whole seconds from the answer.
    pub retry_after_secs: u32,
}

// Every byte field below is a CBOR byte string. ciborium writes a bare
// `Vec<u8>` element by element — two bytes for every byte over 0x17 — so
// opaque bytes would cost about 1.9x their length on the wire.

// ---------------------------------------------------------------------
// OCI pull: a manifest (POST /oci/manifest), then the one blob of it the
// TEE chose (POST /oci/blob). Which blob, and whether any of it is what the
// pinned reference names, is decided TEE-side; the hatch parses neither.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestRequest {
    /// Full pinned OCI reference `<registry>/<repo>@sha256:<hex>`.
    pub reference: String,
    /// Opaque bearer the hatch attaches as `Authorization` (empty =
    /// anonymous). Forwarded verbatim from the TEE.
    #[serde(with = "serde_bytes")]
    pub registry_auth: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestResponse {
    /// Raw OCI manifest JSON bytes (the pinned digest is over these exact
    /// bytes, and the TEE recomputes it).
    #[serde(with = "serde_bytes")]
    pub manifest: Vec<u8>,
}

/// One blob of a pinned reference's repository, by its digest. The answer is
/// NOT CBOR: it is the blob's bytes, streamed as the response body as they come
/// from the registry, so no blob is held whole on either side of the hop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobRequest {
    /// Full pinned OCI reference whose repository holds the blob.
    pub reference: String,
    /// The blob's digest, `sha256:<hex>`, as the manifest names it.
    pub digest: String,
    /// As in [`ManifestRequest`].
    #[serde(with = "serde_bytes")]
    pub registry_auth: Vec<u8>,
}

// ---------------------------------------------------------------------
// KBS relay  (POST /kbs/relay)
//
// The TEE has no outbound network, so it reaches an artifact-key broker
// (KBS) through the hatch as a semantic HTTP proxy. The TEE-side driver
// runs the KBS attestation handshake (RCAR: auth -> challenge ->
// attestation -> resource) as a state machine and forwards each leg
// through here; the hatch is a DUMB, STATELESS byte forwarder — it
// dials `endpoint`, replays method/path/headers/body, and returns the
// response verbatim. The released secret is JWE-wrapped to the TEE's
// ephemeral key, so the hatch never sees plaintext key material even
// though it carries the bytes.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KbsRelayRequest {
    /// KBS origin the hatch dials, e.g. `https://kbs.example.com:8080`.
    /// Untrusted routing target supplied by the client at session create;
    /// trust rides on the JWE-to-ephemeral-key response, not this value.
    pub endpoint: String,
    /// HTTP method for this leg (`GET` / `POST`).
    pub method: String,
    /// Request path on the KBS, e.g. `/kbs/v0/auth`.
    pub path: String,
    /// Headers to replay (carries the RCAR session cookie / token across
    /// legs; the TEE driver threads these, the hatch just forwards).
    pub headers: Vec<(String, String)>,
    /// Request body bytes for this leg (opaque to the hatch).
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KbsRelayResponse {
    /// KBS HTTP status for this leg; the TEE driver branches on it.
    pub status: u16,
    /// Response headers (the TEE driver reads the RCAR session cookie).
    pub headers: Vec<(String, String)>,
    /// Response body bytes (opaque to the hatch).
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
}

// The RCAR application protocol (auth / attestation / resource bodies,
// JWE-wrapped resource) is the standard Trustee wire; it lives in the
// `kbs-types` crate and is driven TEE-side by `enclavid-kbs-client`. The
// hatch only ever sees those opaque bytes inside a relay body — no
// enclavid-specific KBS DTOs cross this boundary.

// ---------------------------------------------------------------------
// VCEK fetch  (POST /kds/vcek)
//
// A guest can mint an attestation report without any certificate, but a
// third party cannot check the signature on one without the certificate
// that endorses the signing key. AMD derives and signs that certificate
// per (chip, platform TCB) on request, and the TEE has no outbound
// network — so it names the certificate it needs and the hatch fetches it.
//
// Nothing is trusted about the answer. The certificate is public, and its
// authenticity is settled TEE-side against the AMD root compiled into the
// measured image; a substituted one simply fails to verify a report this
// chip produced, and the guest refuses to start.
// ---------------------------------------------------------------------

/// Names one certificate at AMD's key service. Typed rather than a URL:
/// the hatch owns the origin, so this cannot become a second general
/// forwarder, and an enumerated product plus a hex-only chip identity
/// leave nothing to inject into the path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcekRequest {
    /// AMD product line, e.g. `Milan`. Pinned TEE-side alongside the root.
    pub product_line: String,
    /// Hex chip identity from the TEE's own attestation report.
    pub chip_id: String,
    /// Platform security version numbers of the TCB the signing key is
    /// derived at, read from the same report.
    pub bootloader_spl: u8,
    pub tee_spl: u8,
    pub snp_spl: u8,
    pub microcode_spl: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcekResponse {
    /// DER certificate bytes, opaque to the hatch. The TEE verifies the
    /// AMD chain over them before they endorse anything.
    ///
    /// A CBOR byte string, not ciborium's default per-byte integer array:
    /// measured, the array form carried a 1351-byte certificate in 2306.
    #[serde(with = "serde_bytes")]
    pub certificate: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes past 0x17, which is nearly every byte of a ciphertext: the ones an
    /// integer array would spend two bytes on.
    fn sealed() -> Vec<u8> {
        vec![0xff; 1 << 16]
    }

    #[test]
    fn a_sealed_byte_crosses_as_one_byte() {
        let pulled = ManifestResponse { manifest: sealed() };
        assert!(encode(&pulled).unwrap().len() < 2 * sealed().len() + 256);
    }
}
