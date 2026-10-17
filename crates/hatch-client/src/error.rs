/// Errors at the TEE↔hatch bridge boundary.
///
/// These cover what can go wrong while crossing the bridge itself —
/// transport, (de)serialization — plus typed surfaces for cases callers
/// branch on (`NotFound` for an absent OCI manifest, `Refused` for a pull
/// the hatch will not make). They do **not** carry any semantics about
/// the truthfulness of values the hatch returns: a successful `Ok(...)`
/// means "the hatch responded; the body parsed", not "the hatch did
/// the right thing". Trust in hatch-supplied values is encoded
/// separately via `Untrusted<T>`.
#[derive(Debug)]
pub enum BridgeError {
    Transport(String),
    /// CBOR (de)serialization failure — a wire DTO that wouldn't
    /// encode/decode.
    Codec(String),
    /// The hatch reported the requested resource absent (HTTP 404) —
    /// e.g. an OCI manifest that doesn't exist. Lets callers surface a
    /// clean 404 instead of a generic transport error.
    NotFound,
    /// The hatch will not make the pull as asked: the registry refused the
    /// bearer (HTTP 403), or the request is one the hatch never makes (HTTP
    /// 400). Asking again changes nothing — unlike `Transport`, which may be a
    /// registry that did not answer this time.
    Refused,
}

impl From<hatch_protocol::CodecError> for BridgeError {
    fn from(e: hatch_protocol::CodecError) -> Self {
        Self::Codec(e.to_string())
    }
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport: {e}"),
            Self::Codec(e) => write!(f, "codec: {e}"),
            Self::NotFound => write!(f, "not found"),
            Self::Refused => write!(f, "refused"),
        }
    }
}

impl std::error::Error for BridgeError {}
