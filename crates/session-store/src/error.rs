#[derive(Debug)]
pub enum StoreError {
    Transport(String),
    Encode(prost::EncodeError),
    Decode(prost::DecodeError),
}

impl From<tonic::Status> for StoreError {
    fn from(e: tonic::Status) -> Self {
        Self::Transport(e.to_string())
    }
}

impl From<tonic::transport::Error> for StoreError {
    fn from(e: tonic::transport::Error) -> Self {
        Self::Transport(e.to_string())
    }
}

impl From<prost::EncodeError> for StoreError {
    fn from(e: prost::EncodeError) -> Self {
        Self::Encode(e)
    }
}

impl From<prost::DecodeError> for StoreError {
    fn from(e: prost::DecodeError) -> Self {
        Self::Decode(e)
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport: {e}"),
            Self::Encode(e) => write!(f, "encode: {e}"),
            Self::Decode(e) => write!(f, "decode: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}
