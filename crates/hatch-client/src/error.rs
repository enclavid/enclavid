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
    /// What the registry serves for the reference is past what the hatch reads.
    /// The pin names the same bytes every time, so asking again changes nothing.
    TooLarge,
}

impl From<hatch_rpc::PullError> for BridgeError {
    fn from(e: hatch_rpc::PullError) -> Self {
        match e {
            hatch_rpc::PullError::NotFound => Self::NotFound,
            hatch_rpc::PullError::Refused => Self::Refused,
            hatch_rpc::PullError::TooLarge => Self::TooLarge,
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
            Self::TooLarge => write!(f, "too large"),
        }
    }
}

impl std::error::Error for BridgeError {}

#[cfg(test)]
mod tests {
    use hatch_rpc::PullError;

    use super::BridgeError;

    /// A pull's failure keeps its case across the door: what asking again cannot
    /// change stays apart from what it may.
    #[test]
    fn a_pull_failure_keeps_its_case() {
        assert!(matches!(
            BridgeError::from(PullError::NotFound),
            BridgeError::NotFound
        ));
        assert!(matches!(
            BridgeError::from(PullError::Refused),
            BridgeError::Refused
        ));
        assert!(matches!(
            BridgeError::from(PullError::TooLarge),
            BridgeError::TooLarge
        ));
        assert!(matches!(
            BridgeError::from(PullError::Failed("no answer".into())),
            BridgeError::Transport(_)
        ));
    }
}
