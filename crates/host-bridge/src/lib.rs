mod age_seal;
mod auth;
mod error;
mod registry;
mod stores;
mod transport;

mod proto {
    pub mod session_store {
        tonic::include_proto!("enclavid.session_store");
    }
    pub mod report_store {
        tonic::include_proto!("enclavid.report_store");
    }
    pub mod state {
        tonic::include_proto!("enclavid.state");
    }
    pub mod report {
        tonic::include_proto!("enclavid.report");
    }
    pub mod registry {
        tonic::include_proto!("enclavid.registry");
    }
    pub mod auth {
        tonic::include_proto!("enclavid.auth");
    }
}

pub use age_seal::seal_to_recipient;
pub use auth::{AuthClient, AuthVerdict, WorkspaceId};
pub use enclavid_untrusted::{AuthN, AuthZ, Exposed, Reason, Replay, Untrusted, reason};
pub use error::BridgeError;
pub use transport::{GrpcChannel, connect_store};
pub use proto::auth::ClientOperation;
pub use proto::registry::{
    PullManifestResponse as RegistryPullManifestResponse,
    PullResponse as RegistryPullResponse,
};
pub use registry::RegistryClient;
pub use proto::report::{Report, ReportReason};
pub use proto::state::{
    CallEvent, CameraFacing, CaptureGroup, CaptureGuide, CaptureStep, Clip, Completed,
    ConsentRequest, DisplayField, GuideNone, GuideOval, GuideRect, MediaRequest, MediaSpec,
    SessionMetadata, SessionState, SessionStatus, Suspended, VerificationSetData,
    VerificationSetRequest, call_event, capture_guide, suspended,
};
pub use stores::{
    AppendDisclosure, Ctx, Disclosure, Metadata, ReadField, ReadTuple, ReportStore, SessionStore,
    SetMetadata, SetState, SetStatus, State, Status, WriteField,
};

// --- Suspension as wasmtime trap error ---
//
// `suspended::Request` is the prost-generated oneof enum for Suspended.request.
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

    pub fn consent(fields: Vec<DisplayField>, reason_ref: String) -> Self {
        Self::Consent(ConsentRequest {
            fields,
            accepted: None,
            reason_ref,
        })
    }

    pub fn verification_set(alternatives: Vec<CaptureGroup>) -> Self {
        Self::VerificationSet(VerificationSetRequest { alternatives, data: None })
    }
}
