/// Errors from the session store and the L2 cache.
///
/// These cover what can go wrong in the store itself — the leg, a value
/// that would not encode or decode, a seal that would not open — plus
/// `VersionMismatch`, which callers branch on for write CAS conflicts.
/// They do **not** carry any semantics about the truthfulness of what the
/// store returns: a successful `Ok(...)` means "the store answered; the
/// answer parsed", not "the store did the right thing". Trust in
/// store-supplied values is encoded separately via `Untrusted<T>`.
#[derive(Debug)]
pub enum StoreError {
    /// The leg to the storage-CVM, or the store behind it, failed.
    Transport(String),
    /// CBOR (de)serialization failure — a sealed domain blob
    /// (SessionMetadata/SessionState) that wouldn't encode/decode.
    Codec(String),
    /// An AEAD seal/open failure. The one callers branch on: a session
    /// STATE blob that won't open under the presented applicant key — a
    /// wrong key / different-device claim. Kept distinct from `Transport`
    /// (a crypto failure is not a network failure) so the applicant flow can
    /// surface it as a clean 403 (offer reset) instead of a generic 500.
    Crypto(String),
    /// The session's version in the store did not match the value the
    /// caller expected — either someone else wrote between our read and
    /// our write, or a /create-style "must not exist" check found the
    /// session already present. HTTP 412. Callers branch on this to
    /// pick idempotent retry vs surfacing the conflict.
    VersionMismatch,
}

impl From<session_types::CodecError> for StoreError {
    fn from(e: session_types::CodecError) -> Self {
        Self::Codec(e.to_string())
    }
}

impl From<enclavid_crypto::CryptoError> for StoreError {
    fn from(e: enclavid_crypto::CryptoError) -> Self {
        Self::Crypto(e.to_string())
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport: {e}"),
            Self::Codec(e) => write!(f, "codec: {e}"),
            Self::Crypto(e) => write!(f, "crypto: {e}"),
            Self::VersionMismatch => write!(f, "version mismatch"),
        }
    }
}

impl std::error::Error for StoreError {}
