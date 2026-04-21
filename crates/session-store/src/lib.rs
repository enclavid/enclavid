mod error;
mod grpc;
mod stores;

mod proto {
    pub mod blob {
        tonic::include_proto!("enclavid.blob_store");
    }
    pub mod list {
        tonic::include_proto!("enclavid.list_store");
    }
    pub mod state {
        tonic::include_proto!("enclavid.state");
    }
    pub mod report {
        tonic::include_proto!("enclavid.report");
    }
}

pub use error::StoreError;
pub use grpc::{connect_uds, lazy_channel, GrpcBlobStore, GrpcChannel, GrpcListStore};
pub use proto::report::{Report, ReportReason};
pub use proto::state::{
    biometric_request, call_event, capture_item, document_request, suspended, BiometricRequest,
    CallEvent, CaptureGroup, CaptureItem, Completed, ConsentRequest, DisplayField,
    DocumentRequest, DriversLicense, IdCard, Liveness, LivenessFrames, LivenessMode, Passport,
    SessionMetadata, SessionState, Suspended, TwoSidedImage, VerificationSetData,
    VerificationSetRequest,
};
pub use stores::{DisclosureStore, MetadataStore, ReportStore, StateStore};

// --- Suspension as wasmtime trap error ---
//
// `suspended::Request` is the prost-generated oneof enum for Suspended.request.
// Implementing Display + Error on it lets host fns return it via wasmtime::Error,
// which is then caught by the shim and written into a CallEvent's Suspended status.

impl std::fmt::Display for suspended::Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Document(_) => write!(f, "suspend: document"),
            Self::Biometric(_) => write!(f, "suspend: biometric"),
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
// Keep host-side code concise: `suspended::Request::passport().into()`
// rather than explicit struct/enum construction.

impl suspended::Request {
    pub fn passport() -> Self {
        Self::Document(DocumentRequest {
            kind: Some(document_request::Kind::Passport(Passport { image: None })),
        })
    }

    pub fn id_card() -> Self {
        Self::Document(DocumentRequest {
            kind: Some(document_request::Kind::IdCard(IdCard { images: None })),
        })
    }

    pub fn drivers_license() -> Self {
        Self::Document(DocumentRequest {
            kind: Some(document_request::Kind::DriversLicense(DriversLicense {
                images: None,
            })),
        })
    }

    pub fn liveness(mode: LivenessMode) -> Self {
        Self::Biometric(BiometricRequest {
            kind: Some(biometric_request::Kind::Liveness(Liveness {
                mode: mode as i32,
                frames: None,
            })),
        })
    }

    pub fn consent(fields: Vec<DisplayField>) -> Self {
        Self::Consent(ConsentRequest { fields, accepted: None })
    }

    pub fn verification_set(alternatives: Vec<CaptureGroup>) -> Self {
        Self::VerificationSet(VerificationSetRequest { alternatives, data: None })
    }
}
