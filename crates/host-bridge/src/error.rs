/// Errors at the TEE↔host bridge boundary.
///
/// These cover what can go wrong while crossing the bridge itself —
/// gRPC transport, prost encoding/decoding. They do **not** carry any
/// semantics about the truthfulness of values the host returns: a
/// successful `Ok(...)` means "the host responded; the wire format
/// parsed", not "the host did the right thing on its side". Trust in
/// host-supplied values is encoded separately via `Untrusted<T>`.
#[derive(Debug)]
pub enum BridgeError {
    Transport(String),
    Encode(prost::EncodeError),
    Decode(prost::DecodeError),
}

impl From<tonic::Status> for BridgeError {
    fn from(e: tonic::Status) -> Self {
        Self::Transport(e.to_string())
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
        }
    }
}

impl std::error::Error for BridgeError {}
