/// Errors at the TEE↔hatch boundary.
///
/// These cover what can go wrong in reaching the hatch and hearing back, plus
/// the typed cases callers branch on (`NotFound` for an absent OCI manifest,
/// `Refused` for a pull the hatch will not make). They carry nothing about the
/// truthfulness of what the hatch returns: an `Ok(...)` means "the hatch
/// answered", not "what it fetched is what was asked for". Trust in returned
/// values is encoded separately via `Untrusted<T>`.
#[derive(Debug)]
pub enum BridgeError {
    /// The leg is down, the call did not come back within its deadline, or the
    /// hatch could not do what was asked this time.
    Transport(String),
    /// The registry has no such manifest, blob or repository.
    NotFound,
    /// The hatch will not make the pull as asked: the registry refused the
    /// bearer, or the request is one the hatch never makes. Asking again changes
    /// nothing — unlike `Transport`, which may be a registry that did not answer
    /// this time.
    Refused,
}

impl From<hatch_rpc::PullError> for BridgeError {
    fn from(e: hatch_rpc::PullError) -> Self {
        match e {
            hatch_rpc::PullError::NotFound => Self::NotFound,
            hatch_rpc::PullError::Refused => Self::Refused,
            hatch_rpc::PullError::Failed(m) => Self::Transport(m),
        }
    }
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport: {e}"),
            Self::NotFound => write!(f, "not found"),
            Self::Refused => write!(f, "refused"),
        }
    }
}

impl std::error::Error for BridgeError {}
