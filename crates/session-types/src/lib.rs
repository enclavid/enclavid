//! Sealed session-domain types.
//!
//! These are TEE-internal: built / matched / converted to-and-from WIT
//! by the engine and api, then CBOR-encoded ([`encode`]) and AEAD-sealed
//! before they leave the enclave as opaque bytes. The storage-CVM never
//! sees them — they ride inside `BlobField::{Metadata,State}` `value` bytes.
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
//! `[[project-hatch-refactor-decisions]]`.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub use engine_types::compile::{Artifact, CompileFault, InterfaceName, is_wit_name};
pub use engine_types::props::PropsProblem;

// ---------------------------------------------------------------------
// CBOR codec for sealed domain blobs
// ---------------------------------------------------------------------

/// A domain value that would not encode, or bytes that would not decode
/// as one.
#[derive(Debug)]
pub struct CodecError(pub String);

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "session-types codec error: {}", self.0)
    }
}

impl std::error::Error for CodecError {}

/// CBOR-encode a domain value (pre-AEAD-seal).
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| CodecError(e.to_string()))?;
    Ok(buf)
}

/// CBOR-decode a domain value (post-AEAD-open).
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    ciborium::from_reader(bytes).map_err(|e| CodecError(e.to_string()))
}

// ---------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------

/// Session lifecycle state. Single creation step (POST /sessions does
/// the full setup atomically), no PendingInit / FailedInit pre-states.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    #[default]
    Unspecified = 0,
    /// Session created and ready; multiple /connect + /input rounds here.
    Running = 1,
    /// Policy returned a domain Status — webhook fired, data may be ready.
    Completed = 2,
    /// The session could not be prepared to run, and asking again will not
    /// change that — see [`SessionMetadata::init_error`]. Terminal.
    InitFailed = 3,
    /// Idle TTL elapsed without applicant interaction.
    Expired = 4,
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
    /// The props the consumer gave the session: a JSON value, empty when it
    /// gave none. The policy reads them as the type it declares for them.
    pub props: Vec<u8>,
    pub client: Option<Client>,
    pub status: SessionStatus,
    pub created_at: u64,
    pub disclosure_count: u64,
    /// Per-entry leaf hashes (SHA-256, 32 bytes each) of every disclosure
    /// ciphertext emitted this session — the authoritative TEE-side source for
    /// the order-INDEPENDENT set commitment the consumer-pull handler verifies
    /// (see `enclavid-api::disclosure_commit`). The commitment is DERIVED from
    /// this list on demand, never stored, so persister and verifier cannot
    /// diverge. Order of this list is irrelevant (the commitment sorts).
    #[serde(with = "hashes")]
    pub disclosure_entry_hashes: Vec<[u8; 32]>,
    /// The policy artifact's decryption key. `None` (incl. older blobs) ⇒
    /// the artifact is not encrypted.
    pub policy_key: Option<Key>,
    /// Content hashes (BLAKE3, 32 bytes each) of every applicant media blob
    /// captured so far this session. The TEE-side authoritative set for the
    /// `blob::from-blob-ref` gate: a rehydrate for a hash NOT in here is a
    /// fabricated ref and is refused IN-TEE (no hatch read), so a policy can't
    /// use the read key as a covert channel. These raw content hashes are
    /// TEE-ONLY — the host stores media under identity-hiding per-session HKDF
    /// field names (`media::media_field_name`), never these hashes — so carrying
    /// them in sealed metadata leaks nothing to the host.
    #[serde(with = "hashes")]
    pub captured_media: Vec<Vec<u8>>,
    /// The policy's verdict, once it has given one — told to the consumer
    /// unconditionally. Kept as one byte whichever it is: the host sees the
    /// size of every sealed write, and must not read the verdict off it.
    #[serde(with = "decision_byte")]
    pub decision: Option<Decision>,
    /// What preparing the session to run settled: the registry let its bearers
    /// pull every artifact it pins, its composition compiled, and its props are
    /// read as the type the composition declares. `None` until one round's
    /// write records it; prepared before each round until then, and never after:
    /// an api restart or a reset does not prepare it again.
    ///
    /// In one frame whatever the props are: the host sees the size of every
    /// sealed write, and the length of the props as read is their type's and
    /// their own. What the size says is only whether the session was prepared.
    #[serde(with = "prepared_frame")]
    pub prepared: Option<Prepared>,
    /// Why the session could not be prepared to run, written with
    /// [`SessionStatus::InitFailed`]. In one frame whatever it says: the host
    /// sees the size of every sealed write, and which part of the consumer's
    /// setup failed, and how, is not the host's to read.
    #[serde(with = "init_error_frame")]
    pub init_error: Option<InitError>,
    /// What the session is held to, as its consumer's limits gave them at the
    /// creation, each already held to the fleet's own ceiling.
    pub terms: Terms,
    /// The quote minted at the creation — what `POST /sessions` answered the
    /// consumer with — kept to be served to the session's applicant page as
    /// those same bytes: a signature minted per request would let a caller
    /// choose how often the Secure Processor signs. Set once, with the creation.
    ///
    /// Its size is the part's, the same on every session of one machine, so it
    /// tells the host nothing it does not know.
    pub quote: Option<SessionQuote>,
    /// The session's data keys — the inner keys of its state and media, one
    /// from the claim and one more from each take-over — sealed together under
    /// the key of the applicant who holds the session. `None` until an
    /// applicant claims it, and again after a reset. Only the applicant's key
    /// opens it, so what the applicant brought stays closed between their
    /// requests even to this side. A take-over seals the keys again under the
    /// taker's key with a fresh one beside them, which everything is sealed
    /// under from then on; nothing sealed before is sealed anew.
    ///
    /// One size whenever it is set, however many keys it holds: what it tells
    /// the host is only that an applicant holds the session.
    #[serde(with = "serde_bytes")]
    pub data_key_lock: Option<Vec<u8>>,
}

/// A session's quote as it is kept: which backend minted it, and the signed
/// payload. What a sender may claim beside a quote — the measurement, the part —
/// is not kept: the signed payload is what says it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionQuote {
    pub format: String,
    /// One CBOR byte string, not an array of integers — see
    /// [`SessionState::state`].
    #[serde(with = "serde_bytes")]
    pub blob: Vec<u8>,
}

/// A session's terms: each `None` where its consumer's limits gave none, and the
/// fleet's own then. Set once, at the creation, and kept for the session's
/// life whatever the consumer's limits say later.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Terms {
    /// The policy and its plugins together, in bytes.
    pub components_bytes: Option<u64>,
    /// The composition compiled, in bytes.
    pub cwasm_bytes: Option<u64>,
    /// How long the session lives, in seconds — its deadline is set once, from
    /// the creation.
    pub session_ttl_secs: Option<u64>,
    /// How long one pull from a registry may take, in seconds.
    pub pull_deadline_secs: Option<u64>,
}

impl Terms {
    /// `term`, or `ceiling` where it names none — and never past `ceiling`.
    pub fn within(term: Option<u64>, ceiling: u64) -> u64 {
        term.map_or(ceiling, |t| t.min(ceiling))
    }
}

/// What preparing a session settled, kept for every round after.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prepared {
    /// The props as the policy reads them, in WAVE — the component model's own
    /// value encoding — as the execution-worker wrote them when it read them
    /// against the type the composition declares, and reads them back every
    /// round; `None` for a composition that declares none.
    pub props: Option<String>,
}

/// Why a session could not be prepared to run: something the consumer set up for
/// it does not work, and asking again will not change that.
///
/// Decided before any of the policy's code runs — by api from the pins, the
/// bearers and the keys, by the compile-worker from the pinned bytes, or by the
/// execution-worker reading the props against the type the composition
/// declares, in an answer api checks against the props it holds. Nothing in it
/// is the policy's to choose, which is what lets the consumer read it whole: a
/// round, where the policy runs, never produces one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InitError {
    /// An artifact the session pins could not be pulled.
    Pull {
        artifact: Artifact,
        problem: PullProblem,
    },
    /// The compile refused the composition, for the reason it gave.
    Compile(CompileFault),
    /// The session's props do not fit the type its composition declares.
    Props(PropsFault),
}

/// What stood in the way of pulling an artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PullProblem {
    /// The registry has no artifact under the pinned reference.
    NotFound,
    /// The registry refused the session's bearer for it.
    Refused,
    /// What the registry served is not what the pin names: another digest, or
    /// a layer of another length.
    NotAsPinned,
    /// Its manifest does not parse or is past what is read, or its encrypted
    /// layer lacks the annotations decrypting it takes.
    Malformed,
    /// Its manifest has no `application/wasm` layer, plain or encrypted.
    NoWasmLayer,
    /// Its layer is encrypted, and the session gave no key for it.
    KeyMissing,
    /// The session gave a key for it, and its layer is not encrypted.
    NotEncrypted,
    /// The key the session gave, or the one its KBS released, does not decrypt
    /// the layer.
    KeyDoesNotOpen,
    /// The KBS refused to release the key, or answered with none it could.
    KeyNotReleased,
}

/// Where props do not fit the type the policy declares, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropsFault {
    /// The place, as the props spell it: `props.inner.flag`, `props.tags[1]`.
    /// An unknown key is the last segment; a missing field is the object it is
    /// missing from. At most [`MAX_PROPS_AT_BYTES`], cut on a character past
    /// it.
    pub at: String,
    pub problem: PropsProblem,
}

/// The longest [`PropsFault::at`].
pub const MAX_PROPS_AT_BYTES: usize = 256;

/// The bytes a [`Prepared`] is kept in, whatever its props: props as long as a
/// round carries, and room for the CBOR around them.
pub const PREPARED_FRAME: usize = engine_types::limits::MAX_PROPS_BYTES + 64;

/// [`SessionMetadata::prepared`] on the wire: `null`, or its CBOR in a byte
/// string of [`PREPARED_FRAME`] bytes, zeros after it.
mod prepared_frame {
    use serde::de::Error as _;
    use serde::ser::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    use super::{PREPARED_FRAME, Prepared};

    pub fn serialize<S: Serializer>(prepared: &Option<Prepared>, s: S) -> Result<S::Ok, S::Error> {
        let Some(prepared) = prepared else {
            return s.serialize_none();
        };
        let mut frame = Vec::new();
        ciborium::into_writer(prepared, &mut frame).map_err(S::Error::custom)?;
        if frame.len() > PREPARED_FRAME {
            return Err(S::Error::custom("props past their frame"));
        }
        frame.resize(PREPARED_FRAME, 0);
        s.serialize_some(serde_bytes::Bytes::new(&frame))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Prepared>, D::Error> {
        // One value is read off the front; the zeros after it are not looked at.
        Option::<serde_bytes::ByteBuf>::deserialize(d)?
            .map(|frame| ciborium::from_reader(frame.as_slice()).map_err(D::Error::custom))
            .transpose()
    }
}

/// The bytes an [`InitError`] is kept in, whatever it says.
pub const INIT_ERROR_FRAME: usize = 512;

/// [`SessionMetadata::init_error`] on the wire: `null`, or the error's CBOR in a
/// byte string of [`INIT_ERROR_FRAME`] bytes, zeros after it.
mod init_error_frame {
    use serde::de::Error as _;
    use serde::ser::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    use super::{INIT_ERROR_FRAME, InitError};

    pub fn serialize<S: Serializer>(error: &Option<InitError>, s: S) -> Result<S::Ok, S::Error> {
        let Some(error) = error else {
            return s.serialize_none();
        };
        let mut frame = Vec::new();
        ciborium::into_writer(error, &mut frame).map_err(S::Error::custom)?;
        if frame.len() > INIT_ERROR_FRAME {
            return Err(S::Error::custom("an init error past its frame"));
        }
        frame.resize(INIT_ERROR_FRAME, 0);
        s.serialize_some(serde_bytes::Bytes::new(&frame))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<InitError>, D::Error> {
        // One value is read off the front; the zeros after it are not looked at.
        Option::<serde_bytes::ByteBuf>::deserialize(d)?
            .map(|frame| ciborium::from_reader(frame.as_slice()).map_err(D::Error::custom))
            .transpose()
    }
}

/// A list of hashes on the wire, each one CBOR byte string — so what the list
/// adds to a sealed blob is a function of how many it holds, never of what they
/// are. As plain integers, a byte below 0x18 encodes in one byte and the rest in
/// two, and the size would carry a few bits of every hash.
mod hashes {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer, H: AsRef<[u8]>>(hashes: &[H], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(hashes.iter().map(|h| serde_bytes::Bytes::new(h.as_ref())))
    }

    pub fn deserialize<'de, D, H>(d: D) -> Result<Vec<H>, D::Error>
    where
        D: Deserializer<'de>,
        H: TryFrom<Vec<u8>>,
    {
        Vec::<serde_bytes::ByteBuf>::deserialize(d)?
            .into_iter()
            .map(|h| {
                H::try_from(h.into_vec()).map_err(|_| D::Error::custom("a hash of another length"))
            })
            .collect()
    }
}

/// [`SessionMetadata::decision`] on the wire: `null` or one of four small
/// integers, each a single CBOR byte.
mod decision_byte {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::Decision;

    pub fn serialize<S: Serializer>(decision: &Option<Decision>, s: S) -> Result<S::Ok, S::Error> {
        decision.map(|d| d as u8).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Decision>, D::Error> {
        Option::<u8>::deserialize(d)?
            .map(|code| match code {
                0 => Ok(Decision::Approved),
                1 => Ok(Decision::Rejected),
                2 => Ok(Decision::RejectedRetryable),
                3 => Ok(Decision::Review),
                other => Err(D::Error::custom(format!("no decision is {other}"))),
            })
            .transpose()
    }
}

/// Constant plaintext size the encoded `SessionState` is padded to before
/// sealing, so the host-observable ciphertext size is FIXED every round —
/// closing the size covert channel for BOTH `state` and `current_prompt`
/// (the policy controls their sizes; a colluding host could otherwise relay
/// the length). Trust-contract constant: an encoded `SessionState` larger
/// than this traps the write (re-attest on change).
///
/// Must cover the max encoding — the policy `state` (≤ engine
/// `POLICY_MAX_STATE_BYTES`, 1 MiB) plus the largest resolved prompt plus CBOR
/// overhead; the 256 KiB over the state cap is that prompt/overhead headroom.
/// Because the padding is unconditional this is also the *floor* cost of every
/// state write: each round seals exactly this many plaintext bytes regardless of
/// how little real state the policy carries. Raising `POLICY_MAX_STATE_BYTES`
/// raises this frame — and thus every write's seal cost — in lockstep.
pub const SEALED_STATE_PLAINTEXT_BYTES: usize = 1024 * 1024 + 256 * 1024;

/// Internal session state for the policy reducer (`BlobField::State`).
/// Double-AEAD-sealed (applicant key inner, tee_seal_key outer).
///
/// Pure-reducer model. `state` is the policy's OWN opaque
/// serialized blob (the engine never inspects it); the engine threads
/// it verbatim through `policy.handle(state, event)`. `current_prompt` is
/// the prompt last rendered to the applicant and awaiting an answer — the
/// orchestrator uses it to (a) build the matching inbound `Event` from
/// `/input`, and (b) decide the consent-disclosure seal: fields seal to the
/// consumer only when this is a `Prompt::ConsentDisclosure` and it was
/// accepted. Both readings happen orchestrator-side; the runtime that WROTE
/// this value gets no say in either.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionState {
    /// The policy's own opaque serialized state, threaded verbatim
    /// through `handle`. Empty on a fresh session (genesis `start`).
    ///
    /// `serde_bytes` so ciborium encodes this as ONE CBOR byte string. Without
    /// it a `Vec<u8>` serialises element-by-element — two bytes for every byte
    /// over 0x17 — so near-uniform binary state (a re-encoded image, which is
    /// what `POLICY_MAX_STATE_BYTES` was sized for) cost ~1.9x its length. That
    /// is not only wire and seal cost: it put a legal max-cap state OVER the
    /// constant frame it has to fit, at rest and on the worker hop alike.
    #[serde(with = "serde_bytes")]
    pub state: Vec<u8>,
    /// The prompt the runtime is currently awaiting input for, if any.
    /// `None` before the first render and after a `finish`.
    pub current_prompt: Option<Prompt>,
    /// How many times the session has stopped to wait for the applicant's
    /// page, this wait included — `0` before the first. An answer names the
    /// wait it answers by this number, so one composed for an earlier wait —
    /// a second tap, a second tab, a retry after a lost reply — is refused
    /// rather than taken for this one's.
    ///
    /// api's own count: it numbers each round that ends awaiting the page as
    /// it persists it, whatever the runtime that wrote the rest of this value
    /// put here. Only a wait moves it, so no other write to the session does.
    pub awaiting_seq: u64,
}

// ---------------------------------------------------------------------
// Client bundle
// ---------------------------------------------------------------------

#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Client {
    pub access: Option<ClientAccess>,
    pub disclosure_pubkey: String,
    pub r#ref: String,
    pub registry_auth: std::collections::HashMap<String, Vec<u8>>,
    pub plugins: Vec<PluginPin>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `registry_auth` values are per-host bearer tokens — print only the
        // hostnames (its keys), never the tokens. Everything else is non-secret
        // (`plugins` carries `Key`, which redacts itself).
        f.debug_struct("Client")
            .field("access", &self.access)
            .field("disclosure_pubkey", &self.disclosure_pubkey)
            .field("ref", &self.r#ref)
            .field(
                "registry_auth",
                &self.registry_auth.keys().collect::<Vec<_>>(),
            )
            .field("plugins", &self.plugins)
            .finish()
    }
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
#[derive(Clone, PartialEq, Serialize, Deserialize)]
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

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the inline layer key. The KBS variant carries only a routing
        // endpoint (non-secret), so it prints normally.
        match self {
            Key::Inline(_) => f.debug_tuple("Inline").field(&"[REDACTED]").finish(),
            Key::Kbs(k) => f.debug_tuple("Kbs").field(k).finish(),
        }
    }
}

/// Parameters for a [`Key::Kbs`] reference. `endpoint` is an untrusted
/// routing target (the hatch dials it); trust rides on the attestation
/// the KBS verifies and the JWE the released resource is sealed in — not
/// on this value. The layer key is fetched as a standard Trustee **RCAR**
/// resource; the resource URI (`kbs:///<repo>/<type>/<tag>`) lives in the
/// artifact's digest-pinned `enc.keys.*` OCI annotation, so the client
/// supplies only which KBS to dial. See `[[project-trustee-rcar-protocol]]`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct KbsKey {
    /// KBS origin the hatch dials, e.g. `https://kbs.vendor.com:8080`.
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
#[repr(u8)]
pub enum Decision {
    #[default]
    Approved = 0,
    Rejected = 1,
    RejectedRetryable = 2,
    Review = 3,
}

/// What the runtime renders to the applicant — the sealed mirror of the
/// WIT `prompt` variant. Stored as [`SessionState::current_prompt`] so the
/// next `/input` round can build the matching [`Event`], and so the
/// orchestrator has the fields to seal on an accept without asking the
/// runtime what they were.
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

/// Frames one [`Clip`] may carry.
///
/// Derived from what api will accept at ingress, not chosen: the applicant's
/// multipart body is capped at `enclavid_api::limits::APPLICANT_INPUT_BODY_LIMIT`
/// and sized there for roughly a dozen JPEG frames. A body of that size made
/// entirely of empty parts would otherwise yield hundreds of thousands of frames,
/// each one a separate blob write and a separate WIT resource in the round.
///
/// It is restated here, away from api, because the party that must enforce it is
/// the execution-worker, which accepts any attested guest: "api already capped
/// the body" is a claim about a peer the worker cannot identify.
pub const MAX_CLIP_FRAMES: usize = 64;

/// Bytes one clip may carry in total — the same ingress limit, counted the way it
/// is counted at ingress. A per-FRAME cap is deliberately not a second number:
/// api admits a body of this size whatever shape it has, so a tighter per-frame
/// rule would be one this side invented and the other side does not enforce.
pub const MAX_CLIP_BYTES: usize = 12 * 1024 * 1024;

/// One captured artifact — a sequence of JPEG frames over ~1s.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Clip {
    /// Encoded as one CBOR byte string PER FRAME, and bounded on the way back in.
    ///
    /// Both halves are the same field's business and neither is optional. A bare
    /// `Vec<Vec<u8>>` serialises element-by-element — two bytes for every byte
    /// over 0x17 — so a full capture cost about 1.9x its length on each of the two
    /// hops it crosses; the same mistake has now been paid for on `cwasm`,
    /// `PluginInstance::wasm` and `SessionState::state`. And a `Vec` decoded with
    /// no bound is a peer's choice of how much this side allocates.
    #[serde(
        serialize_with = "frames::serialize",
        deserialize_with = "frames::deserialize"
    )]
    pub frames: Vec<Vec<u8>>,
}

/// The codec for [`Clip::frames`]: byte strings out, bounded byte strings in.
mod frames {
    use super::{MAX_CLIP_BYTES, MAX_CLIP_FRAMES};
    use serde::de::{self, SeqAccess, Visitor};
    use serde::ser::SerializeSeq;

    pub(super) fn serialize<S: serde::Serializer>(
        frames: &[Vec<u8>],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(frames.len()))?;
        for f in frames {
            seq.serialize_element(serde_bytes::Bytes::new(f))?;
        }
        seq.end()
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<Vec<u8>>, D::Error> {
        struct Frames;

        impl<'de> Visitor<'de> for Frames {
            type Value = Vec<Vec<u8>>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "at most {MAX_CLIP_FRAMES} capture frames")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                // NOT `with_capacity(seq.size_hint())`: the hint is the sender's
                // claim, and reserving against it is the allocation this bound
                // exists to refuse. It grows into what actually arrives.
                let mut out: Vec<Vec<u8>> = Vec::new();
                let mut total = 0usize;
                while let Some(frame) = seq.next_element::<serde_bytes::ByteBuf>()? {
                    if out.len() == MAX_CLIP_FRAMES {
                        return Err(de::Error::custom(format!(
                            "more than {MAX_CLIP_FRAMES} capture frames"
                        )));
                    }
                    total = total.saturating_add(frame.len());
                    if total > MAX_CLIP_BYTES {
                        return Err(de::Error::custom(format!(
                            "a clip over {MAX_CLIP_BYTES} bytes"
                        )));
                    }
                    out.push(frame.into_vec());
                }
                Ok(out)
            }
        }

        d.deserialize_seq(Frames)
    }
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

/// A resolved `localized-ref`: the full translation set the engine read out of
/// the ref resource. Applicant-facing only — the api picks the request-locale
/// text at view time (`en` fallback); the set itself never reaches the
/// consumer envelope, closing the covert translation channel. Sealed into
/// `current_prompt` so a read renders without the policy component / embedded
/// registry.
pub use engine_types::text::{Localized, Translation};

#[cfg(test)]
mod clip_tests {
    use super::*;

    fn clip(frames: Vec<Vec<u8>>) -> Vec<u8> {
        encode(&Clip { frames }).expect("a clip encodes")
    }

    /// The ordinary shape survives the codec unchanged — frames keep their order
    /// and their bytes.
    #[test]
    fn a_capture_round_trips() {
        let frames = vec![vec![0xFF, 0xD8, 0xFF], vec![], vec![1, 2, 3, 4]];
        let back: Clip = decode(&clip(frames.clone())).expect("a clip decodes");
        assert_eq!(back.frames, frames);
    }

    /// Each frame crosses as ONE CBOR byte string, so a capture costs its own
    /// length rather than about twice it. Asserted as a size bound rather than by
    /// reading the encoding: 1 KiB of frames in ~1 KiB of CBOR can only be byte
    /// strings, and the integer-array form this replaced could not fit.
    #[test]
    fn a_frame_costs_its_own_length_on_the_wire() {
        let frames = vec![vec![0x80u8; 1024]];
        let encoded = clip(frames);
        assert!(
            encoded.len() < 1024 + 64,
            "a 1 KiB frame encoded to {} bytes — not a byte string",
            encoded.len()
        );
    }

    /// The count bound, refused at the decoder rather than trusted upstream.
    #[test]
    fn more_frames_than_a_capture_can_hold_are_refused() {
        let frames = vec![vec![7u8]; MAX_CLIP_FRAMES + 1];
        assert!(decode::<Clip>(&clip(frames)).is_err());
        // And the boundary itself still decodes, so the cap is a ceiling and not
        // an off-by-one.
        let frames = vec![vec![7u8]; MAX_CLIP_FRAMES];
        assert!(decode::<Clip>(&clip(frames)).is_ok());
    }

    /// The aggregate bound. Split across several frames, because a sender that
    /// wants the allocation will not put it in one.
    #[test]
    fn a_clip_over_the_ingress_budget_is_refused() {
        let chunk = MAX_CLIP_BYTES / 4;
        let frames = vec![vec![0u8; chunk]; 5];
        assert!(decode::<Clip>(&clip(frames)).is_err());
    }

    /// An absent field is still an empty clip — the `serde(default)` discipline
    /// the at-rest blobs rely on is not broken by taking over the codec.
    #[test]
    fn an_absent_frames_field_decodes_to_none() {
        #[derive(Serialize)]
        struct Empty {}
        let bytes = encode(&Empty {}).expect("an empty map encodes");
        let back: Clip = decode(&bytes).expect("an absent field defaults");
        assert!(back.frames.is_empty());
    }
}

#[cfg(test)]
mod terms_tests {
    use super::*;

    /// A term is never past its ceiling, and is the ceiling where it names none.
    #[test]
    fn a_term_is_held_within_its_ceiling() {
        assert_eq!(Terms::within(None, 10), 10);
        assert_eq!(Terms::within(Some(3), 10), 3);
        assert_eq!(Terms::within(Some(30), 10), 10);
    }

    /// Terms with none of their fields written read as the fleet's own.
    #[test]
    fn absent_terms_are_the_fleets() {
        #[derive(Serialize)]
        struct Empty {}
        let back: Terms = decode(&encode(&Empty {}).unwrap()).unwrap();
        assert_eq!(back, Terms::default());
    }
}

#[cfg(test)]
mod hashes_tests {
    use super::*;

    fn with_hashes(byte: u8) -> SessionMetadata {
        SessionMetadata {
            disclosure_entry_hashes: vec![[byte; 32]; 3],
            captured_media: vec![vec![byte; 32]; 5],
            ..Default::default()
        }
    }

    /// What the hash lists add to the metadata is how many hashes they hold, the
    /// same whatever each hash is, and each list reads back as it was.
    #[test]
    fn a_hash_list_weighs_its_count_and_not_its_hashes() {
        let low = encode(&with_hashes(0x00)).unwrap();
        let high = encode(&with_hashes(0xff)).unwrap();
        assert_eq!(low.len(), high.len());
        let back: SessionMetadata = decode(&high).unwrap();
        assert_eq!(back, with_hashes(0xff));
    }

    /// A disclosure hash of another length is refused as it is read, not cut or
    /// padded to fit.
    #[test]
    fn a_hash_of_another_length_is_refused() {
        #[derive(Serialize)]
        struct Written {
            disclosure_entry_hashes: Vec<serde_bytes::ByteBuf>,
        }
        let short = encode(&Written {
            disclosure_entry_hashes: vec![serde_bytes::ByteBuf::from(vec![1; 31])],
        })
        .unwrap();
        assert!(decode::<SessionMetadata>(&short).is_err());
    }
}

#[cfg(test)]
mod quote_tests {
    use super::*;

    fn with_quote(blob: Vec<u8>) -> SessionMetadata {
        SessionMetadata {
            quote: Some(SessionQuote {
                format: "sev-snp".into(),
                blob,
            }),
            ..Default::default()
        }
    }

    /// The kept quote weighs its length and reads back as it was: one CBOR byte
    /// string, not an array of integers that would cost up to twice the bytes,
    /// and more for the bytes over 0x17.
    #[test]
    fn a_kept_quote_weighs_its_length_and_round_trips() {
        let empty = encode(&with_quote(Vec::new())).unwrap();
        let low = encode(&with_quote(vec![0x00; 4096])).unwrap();
        let high = encode(&with_quote(vec![0xff; 4096])).unwrap();
        assert_eq!(low.len(), high.len());
        assert!(high.len() - empty.len() < 4096 + 8);
        let back: SessionMetadata = decode(&high).unwrap();
        assert_eq!(back, with_quote(vec![0xff; 4096]));
    }
}

#[cfg(test)]
mod decision_tests {
    use super::*;

    const ALL: [Decision; 4] = [
        Decision::Approved,
        Decision::Rejected,
        Decision::RejectedRetryable,
        Decision::Review,
    ];

    fn sealed(decision: Option<Decision>) -> Vec<u8> {
        encode(&SessionMetadata {
            decision,
            ..Default::default()
        })
        .expect("metadata encodes")
    }

    /// The metadata a session is sealed into is as long whichever the verdict,
    /// and as long before one: the host sees every sealed write's size.
    #[test]
    fn the_verdict_does_not_change_the_metadatas_size() {
        let before = sealed(None).len();
        for decision in ALL {
            assert_eq!(sealed(Some(decision)).len(), before, "{decision:?}");
        }
    }

    /// What preparing a session settled is kept as it was settled — without
    /// props, with short ones and with the longest a round carries — and the
    /// metadata is as long whichever it holds.
    #[test]
    fn what_preparing_settled_round_trips_at_one_length() {
        let with = |props: Option<String>| SessionMetadata {
            prepared: Some(Prepared { props }),
            ..Default::default()
        };
        let longest = "w".repeat(engine_types::limits::MAX_PROPS_BYTES);
        let all = [None, Some("{min-age: 18}".to_owned()), Some(longest)].map(with);
        let lengths: Vec<usize> = all
            .iter()
            .map(|metadata| {
                let encoded = encode(metadata).unwrap();
                let back: SessionMetadata = decode(&encoded).unwrap();
                assert_eq!(back.prepared, metadata.prepared);
                encoded.len()
            })
            .collect();
        assert!(lengths.iter().all(|&l| l == lengths[0]), "{lengths:?}");
    }

    fn init_errors() -> Vec<InitError> {
        const PROBLEMS: [PullProblem; 9] = [
            PullProblem::NotFound,
            PullProblem::Refused,
            PullProblem::NotAsPinned,
            PullProblem::Malformed,
            PullProblem::NoWasmLayer,
            PullProblem::KeyMissing,
            PullProblem::NotEncrypted,
            PullProblem::KeyDoesNotOpen,
            PullProblem::KeyNotReleased,
        ];
        let longest_name = "a".repeat(InterfaceName::MAX_BYTES);
        let artifacts = [
            Artifact::Policy,
            Artifact::Plugin("a".into()),
            Artifact::Plugin(longest_name.clone()),
        ];
        let longest = InterfaceName::new(&longest_name).unwrap();
        let shortest = InterfaceName::new("a").unwrap();
        let pulls = artifacts.clone().into_iter().flat_map(|artifact| {
            PROBLEMS.into_iter().map(move |problem| InitError::Pull {
                artifact: artifact.clone(),
                problem,
            })
        });
        let compiles = artifacts
            .into_iter()
            .flat_map(|a| {
                [
                    CompileFault::NotAComponent(a.clone()),
                    CompileFault::ReservedExport(a.clone()),
                    CompileFault::CatalogInvalid(a),
                ]
            })
            .chain([
                CompileFault::CatalogsPastCap,
                CompileFault::Unsatisfied(longest.clone()),
                CompileFault::Unsatisfied(shortest.clone()),
                CompileFault::Mismatched(longest),
                CompileFault::Mismatched(shortest),
                CompileFault::Invalid,
                CompileFault::TooLarge,
                CompileFault::OutOfMemory,
            ])
            .map(InitError::Compile);
        // Every problem, at the shortest place and at the longest.
        let props = [
            PropsProblem::ShouldBeBool,
            PropsProblem::ShouldBeWholeNumber,
            PropsProblem::ShouldBeNumber,
            PropsProblem::ShouldBeOneCharacter,
            PropsProblem::ShouldBeString,
            PropsProblem::ShouldBeArray,
            PropsProblem::ShouldBeObject,
            PropsProblem::Unholdable,
            PropsProblem::NotACase,
            PropsProblem::OutOfRange,
            PropsProblem::UnknownField,
            PropsProblem::Missing,
            PropsProblem::NotDeclared,
            PropsProblem::NotJson,
            PropsProblem::TooLong,
        ]
        .into_iter()
        .flat_map(|problem| {
            ["props".to_string(), "ж".repeat(MAX_PROPS_AT_BYTES / 2)]
                .map(|at| InitError::Props(PropsFault { at, problem }))
        });
        pulls.chain(compiles).chain(props).collect()
    }

    fn failed(init_error: InitError) -> Vec<u8> {
        encode(&SessionMetadata {
            status: SessionStatus::InitFailed,
            init_error: Some(init_error),
            ..Default::default()
        })
        .expect("metadata encodes")
    }

    /// Which artifact failed, and how, is not read off the sealed write's size:
    /// every init error is kept in the same frame.
    #[test]
    fn the_init_error_does_not_change_the_metadatas_size() {
        let sizes: std::collections::BTreeSet<usize> =
            init_errors().into_iter().map(|e| failed(e).len()).collect();
        assert_eq!(sizes.len(), 1, "{sizes:?}");
    }

    #[test]
    fn the_init_error_round_trips() {
        for error in init_errors() {
            let back: SessionMetadata = decode(&failed(error.clone())).expect("metadata decodes");
            assert_eq!(back.init_error, Some(error));
        }
        let back: SessionMetadata = decode(&sealed(None)).expect("metadata decodes");
        assert_eq!(back.init_error, None);
    }

    #[test]
    fn the_verdict_round_trips() {
        for decision in [None, Some(Decision::Approved), Some(Decision::Review)] {
            let back: SessionMetadata = decode(&sealed(decision)).expect("metadata decodes");
            assert_eq!(back.decision, decision);
        }
    }
}
