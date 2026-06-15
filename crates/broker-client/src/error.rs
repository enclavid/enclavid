/// Errors at the TEE↔broker bridge boundary.
///
/// These cover what can go wrong while crossing the bridge itself —
/// transport, encoding — plus typed surfaces for cases callers branch
/// on (`VersionMismatch` for write CAS conflicts, `NotFound` for an
/// absent OCI manifest). They do **not** carry any semantics about the
/// truthfulness of values the broker returns: a successful `Ok(...)`
/// means "the broker responded; the body parsed", not "the broker did
/// the right thing". Trust in broker-supplied values is encoded
/// separately via `Untrusted<T>`.
#[derive(Debug)]
pub enum BridgeError {
    Transport(String),
    /// Domain (state.proto) prost encode/decode failure — sealing or
    /// unsealing a SessionMetadata/SessionState payload.
    Encode(prost::EncodeError),
    Decode(prost::DecodeError),
    /// The session's version on the broker did not match the value the
    /// caller expected — either someone else wrote between our read
    /// and our write, or a /create-style "must not exist" check found
    /// the session already present. HTTP 412. Callers branch on this
    /// to pick idempotent retry vs surfacing the conflict.
    VersionMismatch,
    /// The broker reported the requested resource absent (HTTP 404) —
    /// e.g. an OCI manifest that doesn't exist. Lets callers surface a
    /// clean 404 to the API consumer instead of a generic transport
    /// error.
    NotFound,
}

impl From<prost::EncodeError> for BridgeError {
    fn from(e: prost::EncodeError) -> Self {
        Self::Encode(e)
    }
}

impl From<prost::DecodeError> for BridgeError {
    fn from(e: prost::DecodeError) -> Self {
        Self::Decode(e)
    }
}

impl From<broker_protocol::CodecError> for BridgeError {
    fn from(e: broker_protocol::CodecError) -> Self {
        // A wire DTO that won't encode/decode is a transport-level
        // protocol failure from the caller's perspective.
        Self::Transport(e.to_string())
    }
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport: {e}"),
            Self::Encode(e) => write!(f, "encode: {e}"),
            Self::Decode(e) => write!(f, "decode: {e}"),
            Self::VersionMismatch => write!(f, "version mismatch"),
            Self::NotFound => write!(f, "not found"),
        }
    }
}

impl std::error::Error for BridgeError {}
