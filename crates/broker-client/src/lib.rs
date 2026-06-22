mod auth;
pub mod boundary;
mod error;
mod kbs;
mod registry;
mod session;
mod transport;

// Sealed session-domain types — hand-written serde structs, CBOR at
// rest. No protobuf anywhere in the project.
mod domain;

pub use auth::{AuthClient, AuthVerdict, Principal};
// Boundary-sentinel re-exports — Untrusted/Exposed/concern markers
// live in `boundary::sentinel` after the untrusted-crate fold-in.
// The old crate-root path is preserved so external consumers don't
// need to update import paths.
pub use boundary::{AuthN, AuthZ, Covert, Exposed, Reason, Replay, Untrusted};
pub use boundary::outbound::public_session_id;
pub use error::BridgeError;
pub use transport::BrokerClient;
// Wire DTO re-exports — the operation selector and the OCI pull
// response now come from the shared `broker-protocol` crate.
pub use broker_protocol::{AuthorizeRequest, ClientOperation, PullRequest};
pub use broker_protocol::PullResponse as RegistryPullResponse;
pub use broker_protocol::{
    KbsKeyRequest, KbsKeyResponse, KbsRelayRequest, KbsRelayResponse, SealedBlob,
};
pub use kbs::KbsClient;
pub use registry::RegistryClient;
pub use domain::{
    CallEvent, CameraFacing, CaptureGroup, CaptureGuide, CaptureStep, Client, ClientAccess, Clip,
    Completed, ConsentRequest, DisplayField, GuideNone, GuideOval, GuideRect, KbsKey, Key,
    MediaRequest, MediaSpec, PluginPin, SessionMetadata, SessionState, SessionStatus,
    Suspended, VerificationSetData, VerificationSetRequest, call_event, capture_guide, suspended,
};
pub use session::{
    AppendDisclosure, Ctx, Disclosure, Metadata, ReadField, ReadTuple, SessionStore, SetMetadata,
    SetPrincipal, SetState, SetStatus, State, Status, WriteField,
};

// --- Suspension as wasmtime trap error ---
//
// `suspended::Request` is the oneof enum for `Suspended.request`.
// Implementing Display + Error on it lets host fns return it via wasmtime::Error,
// which is then caught by the shim and written into a CallEvent's Suspended status.

impl std::fmt::Display for suspended::Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Media(m) => write!(
                f,
                "suspend: media ({} steps)",
                m.spec.as_ref().map(|s| s.captures.len()).unwrap_or(0),
            ),
            Self::Consent(_) => write!(f, "suspend: consent"),
            Self::VerificationSet(r) => {
                write!(f, "suspend: verification-set ({} alternatives)", r.alternatives.len())
            }
        }
    }
}

impl std::error::Error for suspended::Request {}

// --- Constructor helpers ---
//
// Keep host-side code concise: `suspended::Request::media(spec).into()`
// rather than explicit struct/enum construction.

impl suspended::Request {
    /// Initial suspension — no clips captured yet. The empty map's
    /// step indices fill in as /input arrives for each step.
    pub fn media(spec: MediaSpec) -> Self {
        Self::media_with(spec, Default::default())
    }

    /// Re-suspend preserving whatever clips have already been
    /// captured. Used when policy re-invokes prompt-media and some
    /// (but not all) steps were filled by previous /input rounds.
    pub fn media_with(
        spec: MediaSpec,
        clips: std::collections::HashMap<u32, Clip>,
    ) -> Self {
        Self::Media(MediaRequest {
            spec: Some(spec),
            clips,
        })
    }

    pub fn consent(
        fields: Vec<DisplayField>,
        reason_ref: String,
        requester_ref: String,
    ) -> Self {
        Self::Consent(ConsentRequest {
            fields,
            accepted: None,
            reason_ref,
            requester_ref,
        })
    }

    pub fn verification_set(alternatives: Vec<CaptureGroup>) -> Self {
        Self::VerificationSet(VerificationSetRequest { alternatives, data: None })
    }
}
