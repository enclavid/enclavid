/// Errors at the TEE↔broker bridge boundary.
///
/// These cover what can go wrong while crossing the bridge itself —
/// transport, (de)serialization — plus typed surfaces for cases callers
/// branch on (`VersionMismatch` for write CAS conflicts, `NotFound` for
/// an absent OCI manifest). They do **not** carry any semantics about
/// the truthfulness of values the broker returns: a successful `Ok(...)`
/// means "the broker responded; the body parsed", not "the broker did
/// the right thing". Trust in broker-supplied values is encoded
/// separately via `Untrusted<T>`.
#[derive(Debug)]
pub enum BridgeError {
    Transport(String),
    /// CBOR (de)serialization failure — a wire DTO or a sealed domain
    /// blob (SessionMetadata/SessionState) that wouldn't encode/decode.
    Codec(String),
    /// An AEAD seal/open failure. The one callers branch on: a session
    /// STATE blob that won't open under the presented applicant key — a
    /// wrong key / different-device claim. Kept distinct from `Transport`
    /// (a crypto failure is not a network failure) so the applicant flow can
    /// surface it as a clean 403 (offer reset) instead of a generic 500.
    Crypto(String),
    /// The session's version on the broker did not match the value the
    /// caller expected — either someone else wrote between our read and
    /// our write, or a /create-style "must not exist" check found the
    /// session already present. HTTP 412. Callers branch on this to
    /// pick idempotent retry vs surfacing the conflict.
    VersionMismatch,
    /// The broker reported the requested resource absent (HTTP 404) —
    /// e.g. an OCI manifest that doesn't exist. Lets callers surface a
    /// clean 404 instead of a generic transport error.
    NotFound,
}

impl From<broker_protocol::CodecError> for BridgeError {
    fn from(e: broker_protocol::CodecError) -> Self {
        Self::Codec(e.to_string())
    }
}

impl From<enclavid_crypto::CryptoError> for BridgeError {
    fn from(e: enclavid_crypto::CryptoError) -> Self {
        Self::Crypto(e.to_string())
    }
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport: {e}"),
            Self::Codec(e) => write!(f, "codec: {e}"),
            Self::Crypto(e) => write!(f, "crypto: {e}"),
            Self::VersionMismatch => write!(f, "version mismatch"),
            Self::NotFound => write!(f, "not found"),
        }
    }
}

impl std::error::Error for BridgeError {}
