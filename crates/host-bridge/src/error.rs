/// Errors at the TEE↔host bridge boundary.
///
/// These cover what can go wrong while crossing the bridge itself —
/// transport, encoding — plus a typed surface for the version-mismatch
/// case so callers can branch on it (e.g. idempotent retry for /init,
/// run abort for /input). They do **not** carry any semantics about
/// the truthfulness of values the host returns: a successful
/// `Ok(...)` means "the host responded; the wire format parsed", not
/// "the host did the right thing on its side". Trust in host-supplied
/// values is encoded separately via `Untrusted<T>`.
#[derive(Debug)]
pub enum BridgeError {
    Transport(String),
    Encode(prost::EncodeError),
    Decode(prost::DecodeError),
    /// The session's version on the host did not match the value the
    /// caller expected — either someone else wrote between our read
    /// and our write, or a /create-style "must not exist" check
    /// found the session already present. Callers branch on this to
    /// pick idempotent retry vs surfacing the conflict.
    VersionMismatch,
}

impl From<tonic::Status> for BridgeError {
    fn from(e: tonic::Status) -> Self {
        match e.code() {
            tonic::Code::FailedPrecondition => Self::VersionMismatch,
            _ => Self::Transport(e.to_string()),
        }
    }
}

impl From<tonic::transport::Error> for BridgeError {
    fn from(e: tonic::transport::Error) -> Self {
        Self::Transport(e.to_string())
    }
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

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport: {e}"),
            Self::Encode(e) => write!(f, "encode: {e}"),
            Self::Decode(e) => write!(f, "decode: {e}"),
            Self::VersionMismatch => write!(f, "version mismatch"),
        }
    }
}

impl std::error::Error for BridgeError {}
