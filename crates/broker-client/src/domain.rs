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
    /// The policy artifact's decryption key. `None` (incl. older blobs) ⇒
    /// the artifact is not encrypted.
    pub policy_key: Option<Key>,
}

/// Internal session state for the policy reducer (`BlobField::State`).
/// Double-AEAD-sealed (applicant key inner, tee_seal_key outer).
///
/// Pure-reducer model. `state` is the policy's OWN opaque
/// serialized blob (the engine never inspects it); the engine threads
/// it verbatim through `policy.handle(state, event)`. `current_prompt` is
/// the prompt the runtime last rendered to the applicant and is waiting
/// on — the runtime uses it to (a) build the matching inbound `Event`
/// from `/input`, and (b) gate the consent-disclosure seal: a disclosure
/// only seals to the consumer when the `current_prompt` is a
/// `Prompt::ConsentDisclosure` and it is accepted.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionState {
    pub policy_hash: Vec<u8>,
    /// The policy's own opaque serialized state, threaded verbatim
    /// through `handle`. Empty on a fresh session (genesis `start`).
    pub state: Vec<u8>,
    /// The prompt the runtime is currently awaiting input for, if any.
    /// `None` before the first render and after a `finish`.
    pub current_prompt: Option<Prompt>,
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
    /// This plugin artifact's decryption key. `None` ⇒ not encrypted.
    pub key: Option<Key>,
}

/// The decryption key for an encrypted artifact (policy or plugin) —
/// either the key itself, supplied inline, or a reference to a KBS that
/// releases it. Carries secrets (the inline key, the KBS token), so it
/// only ever lives inside AEAD-sealed metadata — never plaintext to the
/// host. Absence (`Option::None`) means the artifact is not encrypted.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Key {
    /// The symmetric layer key (ocicrypt private opts), supplied inline at
    /// POST /sessions. Valid only when the session creator is the artifact
    /// owner (it already holds the plaintext, so handing itself the key
    /// leaks nothing). MUST NOT be used for a third-party artifact — that
    /// would let the client decrypt the IP.
    Inline(Vec<u8>),
    /// The key is released by an attestation-gated KBS.
    Kbs(KbsKey),
}

/// Parameters for a [`Key::Kbs`] reference. `endpoint` is an untrusted
/// routing target (the broker dials it); trust rides on the attestation
/// the KBS verifies and the JWE the released resource is sealed in — not
/// on this value. The layer key is fetched as a standard Trustee **RCAR**
/// resource; the resource URI (`kbs:///<repo>/<type>/<tag>`) lives in the
/// artifact's digest-pinned `enc.keys.*` OCI annotation, so the client
/// supplies only which KBS to dial. See `[[project-trustee-rcar-protocol]]`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct KbsKey {
    /// KBS origin the broker dials, e.g. `https://kbs.vendor.com:8080`.
    /// The `kbs:///` annotation has an empty authority — this fills it in.
    pub endpoint: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientAccess {
    pub principal: Option<String>,
    pub session_token_hash: Vec<u8>,
}

// ---------------------------------------------------------------------
// Reducer I/O — Prompt / Event / Action
// ---------------------------------------------------------------------

/// Terminal outcome carried by [`Action::Finish`] — mirror of the WIT
/// `decision` enum. The platform renders UI from this fixed set; the
/// policy controls no free text.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    #[default]
    Approved,
    Rejected,
    RejectedRetryable,
    Review,
}

/// What the runtime renders to the applicant — the sealed mirror of the
/// WIT `prompt` variant. Stored as [`SessionState::current_prompt`] so the
/// next `/input` round can build the matching [`Event`] and so the
/// consent gate has the disclosure to seal on accept.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Prompt {
    /// Capture one artifact; reply arrives as [`Event::Media`].
    Media(MediaSpec),
    /// Consent-to-disclose screen. ON ACCEPT the runtime seals the
    /// carried `fields` to the consumer.
    ConsentDisclosure(Disclosure),
}

/// One consent-and-disclosure — sealed mirror of the WIT `disclosure`
/// record, with every ref already RESOLVED by the engine at the action
/// boundary (the WIT refs are store-bound resource handles that can't
/// cross to the api). `fields` are BOTH what the applicant sees AND, on
/// accept, the exact set sealed to the consumer. `reason` is bound to
/// the consent record; `requester` is applicant-facing only. Self-
/// contained: rendering a read needs no registry / policy component.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Disclosure {
    pub fields: Vec<DisplayField>,
    pub reason: Localized,
    pub requester: Localized,
    /// Distinct `disclosure-field` keys the whole composition can
    /// resolve (deduped). The consent screen's covert-channel bound:
    /// the composition encodes at most `log2(total_declared)` bits per
    /// `DisplayField.key`. Resolved engine-side and sealed so the read
    /// path shows it without the registry.
    pub total_declared: usize,
}

/// INBOUND to the policy reducer — sealed mirror of the WIT `event`
/// variant. Built by the runtime from the applicant's `/input` against
/// the [`SessionState::current_prompt`] prompt.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Event {
    /// Genesis: session opened.
    Start,
    /// Reply to [`Prompt::ConsentDisclosure`] — accepted?
    ConsentDisclosure(bool),
    /// Reply to [`Prompt::Media`] — one capture step completed.
    Media(MediaResult),
}

/// OUTBOUND from the policy reducer — sealed mirror of the WIT `action`
/// variant.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Action {
    /// Result-producing → applicant; reply is a future [`Event`].
    Render(Prompt),
    /// Durable checkpoint: persist `state`, then re-invoke `handle`.
    Continue,
    /// Terminal.
    Finish(Decision),
}

/// The captured frames for one `media-spec` step — sealed mirror of the
/// WIT `media-result` record. `slot` is the capture-step index it fills.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct MediaResult {
    pub slot: u32,
    pub clip: Clip,
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
pub struct MediaSpec {
    pub label: Localized,
    pub captures: Vec<CaptureStep>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureStep {
    /// Resolved icon NAME (locale-agnostic) the applicant frontend
    /// dispatches; `None` when the step declared no icon.
    pub icon: Option<String>,
    pub instructions: Localized,
    pub label: Localized,
    pub camera: CameraFacing,
    pub guide: Option<CaptureGuide>,
    pub review_hint: Localized,
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
// Consent
// ---------------------------------------------------------------------

/// Field shown to the user on the consent screen, with refs resolved
/// engine-side. `key` is the machine `disclosure-field` key the consumer
/// receives (locale-agnostic); `label` is the full translation set the
/// api narrows to the request locale for the applicant only (never
/// sealed to the consumer); `value` is the policy-supplied data.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DisplayField {
    pub key: String,
    pub label: Localized,
    pub value: String,
}

/// A resolved `localized-ref`: the full translation set the engine read
/// out of the ref resource. Applicant-facing only — the api picks the
/// request-locale text at view time (`en` fallback); the map itself
/// never reaches the consumer envelope, closing the covert translation
/// channel. Sealed into `current_prompt` so a read renders without the
/// policy component / embedded registry.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Localized {
    pub translations: Vec<Translation>,
}

/// One `(language, text)` row of a [`Localized`] set.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Translation {
    pub language: String,
    pub text: String,
}
