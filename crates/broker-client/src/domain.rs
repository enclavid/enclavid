//! Sealed session-domain types.
//!
//! These are TEE-internal: built / matched / converted to-and-from WIT
//! by the engine and api, then CBOR-encoded ([`encode`]) and AEAD-sealed
//! before they leave the enclave as opaque bytes. The broker never sees
//! them — they ride inside `BlobField::{Metadata,State}` `value` bytes.
//!
//! **Schema evolution (at-rest, up to ~a week per session):** every
//! struct is `#[derive(Default)] #[serde(default)]`, so a missing field
//! in an older blob decodes to its `Default` — adding a field never
//! breaks an in-flight session across a deploy (proto3's "all fields
//! default" property, in serde). Removing a field is safe (serde
//! ignores unknown fields). Renaming needs `#[serde(alias = "old")]`.
//! Oneof fields are `Option<…>` so a missing one decodes to `None`.
//!
//! NOTE: the `#[serde(default)]` discipline is currently applied by hand
//! on each struct. The `sealed!` macro that *enforces* it (so it can't
//! be forgotten) is a tracked follow-up — see
//! `[[project-broker-refactor-decisions]]`.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::BridgeError;

// ---------------------------------------------------------------------
// CBOR codec for sealed domain blobs
// ---------------------------------------------------------------------

/// CBOR-encode a domain value (pre-AEAD-seal).
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, BridgeError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| BridgeError::Codec(e.to_string()))?;
    Ok(buf)
}

/// CBOR-decode a domain value (post-AEAD-open).
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, BridgeError> {
    ciborium::from_reader(bytes).map_err(|e| BridgeError::Codec(e.to_string()))
}

// ---------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------

/// Session lifecycle state. Single creation step (POST /sessions does
/// the full setup atomically), no PendingInit / FailedInit pre-states.
/// Explicit discriminants back the plaintext STATUS byte ([`to_byte`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    #[default]
    Unspecified = 0,
    /// Session created and ready; multiple /connect + /input rounds here.
    Running = 1,
    /// Policy returned a domain Status — webhook fired, data may be ready.
    Completed = 2,
    /// Unrecoverable infrastructure error during the run.
    Failed = 3,
    /// Idle TTL elapsed without applicant interaction.
    Expired = 4,
}

impl SessionStatus {
    /// Compact single-byte form for the plaintext `BlobField::Status`
    /// field (the broker indexes TTL/cleanup on it). CBOR encodes the
    /// enum by name inside sealed metadata; this is the separate
    /// host-visible representation.
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Unspecified),
            1 => Some(Self::Running),
            2 => Some(Self::Completed),
            3 => Some(Self::Failed),
            4 => Some(Self::Expired),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CameraFacing {
    #[default]
    Unknown = 0,
    Front = 1,
    Rear = 2,
    Any = 3,
}

// ---------------------------------------------------------------------
// Top-level sealed blobs
// ---------------------------------------------------------------------

/// Session metadata (`BlobField::Metadata`), created at POST /sessions
/// and updated as the session progresses. AEAD-sealed under
/// `tee_seal_key`; AAD = session_id.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionMetadata {
    pub policy_ref: String,
    pub input: Vec<u8>,
    pub client: Option<Client>,
    pub status: SessionStatus,
    pub created_at: u64,
    pub disclosure_count: u64,
    pub disclosure_hash: Vec<u8>,
}

/// Internal session state for policy replay (`BlobField::State`).
/// Double-AEAD-sealed (applicant key inner, tee_seal_key outer).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionState {
    pub policy_hash: Vec<u8>,
    pub events: Vec<CallEvent>,
}

// ---------------------------------------------------------------------
// Client bundle
// ---------------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Client {
    pub access: Option<ClientAccess>,
    pub disclosure_pubkey: String,
    pub r#ref: String,
    pub registry_auth: std::collections::HashMap<String, Vec<u8>>,
    pub plugins: Vec<PluginPin>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginPin {
    pub package: String,
    pub impl_ref: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientAccess {
    pub principal: Option<String>,
    pub session_token_hash: Vec<u8>,
}

// ---------------------------------------------------------------------
// Replay log
// ---------------------------------------------------------------------

/// One record per host call. Position in `SessionState.events` = call
/// index. On replay, intercept verifies fn_name + args_hash and returns
/// the cached Completed result or re-runs for Suspended/unset status.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CallEvent {
    pub fn_name: String,
    pub args_hash: Vec<u8>,
    pub status: Option<call_event::Status>,
}

pub mod call_event {
    use serde::{Deserialize, Serialize};
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Status {
        Completed(super::Completed),
        Suspended(super::Suspended),
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Completed {
    pub result: Vec<u8>,
}

/// Suspension request — typed by category. UI renders based on which
/// variant is populated.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Suspended {
    pub request: Option<suspended::Request>,
}

pub mod suspended {
    use serde::{Deserialize, Serialize};
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Request {
        Media(super::MediaRequest),
        Consent(super::ConsentRequest),
        VerificationSet(super::VerificationSetRequest),
    }
}

// ---------------------------------------------------------------------
// Capture / media
// ---------------------------------------------------------------------

/// One captured artifact — a sequence of JPEG frames over ~1s.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Clip {
    pub frames: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct MediaRequest {
    pub spec: Option<MediaSpec>,
    /// Per-step clips keyed by step index.
    pub clips: std::collections::HashMap<u32, Clip>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct MediaSpec {
    pub label_ref: String,
    pub captures: Vec<CaptureStep>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureStep {
    pub icon_ref: Option<String>,
    pub instructions_ref: String,
    pub label_ref: String,
    pub camera: CameraFacing,
    pub guide: Option<CaptureGuide>,
    pub review_hint_ref: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureGuide {
    pub kind: Option<capture_guide::Kind>,
}

pub mod capture_guide {
    use serde::{Deserialize, Serialize};
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Kind {
        None(super::GuideNone),
        Rect(super::GuideRect),
        Oval(super::GuideOval),
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuideNone {}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuideRect {
    pub aspect: f32,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuideOval {}

// ---------------------------------------------------------------------
// Consent / verification-set
// ---------------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConsentRequest {
    pub fields: Vec<DisplayField>,
    pub accepted: Option<bool>,
    pub reason_ref: String,
    pub requester_ref: String,
}

/// OR of alternatives (DNF). User satisfies exactly one alternative.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct VerificationSetRequest {
    pub alternatives: Vec<CaptureGroup>,
    pub data: Option<VerificationSetData>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct VerificationSetData {
    pub items: Vec<MediaRequest>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureGroup {
    pub items: Vec<MediaSpec>,
}

/// Field shown to the user on the consent screen. `key` and `label` are
/// text-refs; the host treats `key` as opaque, resolves `label` for the
/// applicant frontend.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DisplayField {
    pub key: String,
    pub label: String,
    pub value: String,
}
