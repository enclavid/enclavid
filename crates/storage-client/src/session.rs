//! Domain-level session storage client.
//!
//! Talks to the storage-CVM's session store through a [`SessionBackend`].
//! Each per-session field (`metadata`, `state`, `media`, `disclosure`)
//! lives in its own sub-module — read marker, write marker, encode/decode
//! logic co-located by domain so adding a new field is a single new file.
//! The shared trait machinery (`ReadField` / `WriteField` /
//! `ReadTuple` + macro) lives in `core`.
//!
//! Use sites:
//! ```ignore
//! // Read returns (typed_fields, version). Pass the version back
//! // to the next write to detect concurrent modifications.
//! let ((metadata,), version) = session_store.read(&id, (Metadata,)).await?;
//!
//! // Write at the expected version; returns the post-write version.
//! // `None` instead: the session must not exist yet (/create).
//! let fields: [&dyn WriteField; 1] = [&SetMetadata(metadata)];
//! let fields = outbound_fields(&fields)
//!     .vouch_unchecked::<Covert, _>(reason!("why this many ops says nothing"));
//! let new_v = session_store.write(&id, Some(version), fields).await?;
//! ```
//!
//! Tuple arities up to 16 supported via macro-unrolled trait impls.
//! Each call site picks the fields it needs; wire transfer is
//! proportional (status-only read = 1-byte payload, no metadata
//! baggage).

mod applicant;
mod core;
mod disclosure;
mod media;
mod metadata;
mod state;

pub use self::core::{ReadField, ReadTuple, WriteField};
pub use applicant::DropApplicantData;
pub use disclosure::{AppendDisclosure, Disclosure};
pub use media::SetMedia;
pub use metadata::{Metadata, SetMetadata};
pub use state::{SetState, State, encode_padded};

use std::sync::Arc;

use secrecy::{ExposeSecret, SecretBox};

use storage_rpc::{FieldSelector, Op, ReadRequest, Slot, WriteRequest};

use enclavid_crypto::aead;

use crate::backend::SessionBackend;
use crate::boundary;
use crate::error::StoreError;
use enclavid_boundary::reason;
use enclavid_boundary::{AuthN, AuthZ, Covert, Exposed, Replay, Untrusted};

/// Per-call encryption context. Carries the TEE-side key plus the
/// session_id used as AAD, so a ciphertext copied between sessions
/// fails authentication.
pub struct Ctx<'a> {
    pub tee_seal_key: &'a [u8],
    pub session_id: &'a str,
}

impl Ctx<'_> {
    fn aad(&self) -> &[u8] {
        self.session_id.as_bytes()
    }
}

/// The session store's client: every field is sealed and opened here, and the
/// backend underneath moves only what this side has already sealed.
///
/// A record's id, the version a write expects and a create's deadline cross as
/// plain values, not through a mint: what answers for them is the leg and the
/// store, the same on every call.
///
/// * The id travels inside RA-TLS to the one storage measurement api pins, and
///   the storage-CVM files a record under a digest of its caller's measurement
///   and the id. The volume the host reads holds that fixed-length digest and
///   never an id, whatever id a request named (`AuthN`, `Covert`), and the digest
///   is what keeps one caller from another's records (`AuthZ`). A name nobody
///   created opens nothing and makes nothing: only a create makes a record, under
///   an id minted at random in the TEE.
/// * The version is the store's own counter, and the deadline is the create's
///   time plus a configured lifetime. Both lie on the volume as sent, and neither
///   is anything a party chose or anything the host does not watch happen.
///
/// The fields are another matter. The volume holds them as they were sent, so
/// each is the host's to read and answers for itself in its own `build_op`.
#[derive(Clone)]
pub struct SessionStore {
    /// Transport seam to the storage-CVM. All crypto stays HERE; the backend
    /// moves opaque DTOs. `Arc<dyn _>` keeps this store a
    /// concrete type so `Arc<SessionStore>` doesn't ripple generics through api.
    backend: Arc<dyn SessionBackend>,
    /// TEE-side AEAD master key used for METADATA and as the outer layer of
    /// STATE — the hardware-rooted crown jewel every session seal derives from.
    /// The caller injects it, and where the caller gets it is the caller's
    /// business: api derives it from the chip under `sev-snp`
    /// (`enclavid_attestation::derive_seal_key`), so in the measured image it is
    /// bound to the measurement and never leaves the enclave. A dev build takes
    /// it from the environment instead.
    /// `SecretBox` zeroizes it on drop and redacts it from any `Debug` — so the
    /// master never lands in a log, matching how the applicant token is held; the
    /// `Arc` keeps cloning the store cheap (the store derives `Clone`).
    tee_seal_key: Arc<SecretBox<[u8; 32]>>,
    /// ABSOLUTE session lifetime in seconds. `Some(t)` ⇒ the deadline is set ONCE
    /// at create to `created_at + t` and never refreshed — a fixed cap after which
    /// the storage-CVM sweeper GCs the session (abandoned or completed-and-pulled),
    /// enforced INSIDE the trust boundary (the plaintext host STATUS byte is gone).
    /// Sized so the consumer has time to pull disclosures post-completion. `None` =
    /// no expiry.
    ttl_secs: Option<u64>,
}

impl SessionStore {
    pub fn new(
        backend: Arc<dyn SessionBackend>,
        tee_seal_key: [u8; 32],
        ttl_secs: Option<u64>,
    ) -> Self {
        Self {
            backend,
            tee_seal_key: Arc::new(SecretBox::new(Box::new(tee_seal_key))),
            ttl_secs,
        }
    }

    pub(crate) fn tee_seal_key(&self) -> &[u8] {
        self.tee_seal_key.expose_secret().as_slice()
    }

    /// How long a session lives, as this store was given it: what a session's
    /// own terms are held under.
    pub fn ttl_secs(&self) -> Option<u64> {
        self.ttl_secs
    }

    /// The absolute deadline (unix secs) for a session created NOW to live
    /// `ttl` — `None` for no TTL. Computed TEE-side and passed inside the RA-TLS
    /// channel ONLY on the create write (see [`write`](Self::write)); subsequent
    /// writes pass `None` so the deadline is never moved.
    fn deadline(ttl: Option<u64>) -> Option<u64> {
        ttl.map(|ttl| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            now.saturating_add(ttl)
        })
    }

    /// Read typed session fields in one batch. Returns
    /// `(fields, version)` where each field carries its own per-field
    /// scope and `version` is wrapped in `Untrusted<u64, (AuthN, AuthZ,
    /// Replay)>`. Pass `version` back to the next `write` to detect
    /// concurrent modifications. `version == 0` (after peel) means the
    /// session does not exist yet in the store.
    pub async fn read<T: ReadTuple>(
        &self,
        id: &str,
        fields: T,
    ) -> Result<(T::Output, Untrusted<u64, (AuthN, AuthZ, Replay)>), StoreError> {
        fields.fetch(self, id).await
    }

    /// Atomic write of any number of field ops in one transaction.
    /// `fields` is a heterogeneous slice of `&dyn WriteField`, mixing
    /// static markers (`SetState`, `SetMetadata`, `SetMedia`) with
    /// dynamic-buffer entries (`AppendDisclosure`). The store applies
    /// them in one transaction alongside the version check.
    ///
    /// `expected_version` is the version check: `None` means the
    /// session must not exist yet (used by /create); `Some(V)` means
    /// the session's current version in the store must equal V.
    /// Mismatch surfaces as `StoreError::VersionMismatch` (HTTP 412).
    ///
    /// `id` and `expected_version` are the leg's to answer for (see
    /// [`SessionStore`]). `fields` arrives fully vouched, so the signature
    /// is the type-level guarantee that nothing un-vouched can be written:
    /// [`outbound_fields`] gives what every op set answers alike, the
    /// caller how many ops this write makes (`Covert`), and each member
    /// its content's concerns in `build_op` below, with that field's own
    /// key or recipient — metadata AEAD vs state double-AEAD vs disclosure
    /// sealed to the consumer are not the same concern, so they can't be
    /// bundled into one batch vouch.
    pub async fn write(
        &self,
        id: &str,
        expected_version: Option<u64>,
        fields: Exposed<&[&dyn WriteField]>,
    ) -> Result<Untrusted<u64, (AuthN, AuthZ, Replay)>, StoreError> {
        self.write_living(id, expected_version, self.ttl_secs, fields)
            .await
    }

    /// The create write — [`write`](Self::write) with `expected_version` `None`
    /// — for a session that lives `ttl_secs` rather than this store's own TTL:
    /// its own terms'.
    pub async fn create(
        &self,
        id: &str,
        ttl_secs: u64,
        fields: Exposed<&[&dyn WriteField]>,
    ) -> Result<Untrusted<u64, (AuthN, AuthZ, Replay)>, StoreError> {
        self.write_living(id, None, Some(ttl_secs), fields).await
    }

    async fn write_living(
        &self,
        id: &str,
        expected_version: Option<u64>,
        ttl: Option<u64>,
        fields: Exposed<&[&dyn WriteField]>,
    ) -> Result<Untrusted<u64, (AuthN, AuthZ, Replay)>, StoreError> {
        let fields = fields.into_inner();
        let ctx = Ctx {
            tee_seal_key: self.tee_seal_key(),
            session_id: id,
        };
        let mut ops: Vec<Exposed<Op>> = Vec::with_capacity(fields.len());
        for f in fields {
            ops.push(f.build_op(&ctx)?);
        }

        // Absolute TTL: set the deadline ONLY on the create write (`None` =
        // must-not-exist); on every subsequent update pass `None` so the fixed
        // `created_at + ttl` cap is never moved.
        let deadline = if expected_version.is_none() {
            Self::deadline(ttl)
        } else {
            None
        };
        let ops: Exposed<Vec<Op>, ()> = ops.into();
        let req = ops.map(|ops| WriteRequest {
            ops,
            expected_version,
        });
        let new_version = self.backend.write(id, req.into_inner(), deadline).await?;
        Ok(boundary::from_untrusted(new_version))
    }

    /// Read + double-open one sealed media blob by its content hash. Backs the
    /// policy's `blob::from-blob-ref` rehydrate. `None` = no such blob in this
    /// session (the engine turns a miss into a TRAP). The plaintext comes back
    /// `Untrusted<_, (Replay,)>` — outer-AEAD-open closes AuthN (real crypto),
    /// inner-AEAD-open closes AuthZ (applicant-key possession authorises); only
    /// Replay remains for the caller (trivially closed: the blob is
    /// content-addressed, so a stale / reordered read can only return identical
    /// bytes). AAD = session_id||blob_hash, mirroring [`SetMedia`].
    pub async fn load_media(
        &self,
        id: &str,
        blob_hash: &[u8; 32],
        applicant_session_token: &[u8],
    ) -> Result<Untrusted<Option<Vec<u8>>, (Replay,)>, StoreError> {
        // The AAD binds to the raw content hash (TEE-internal), but the field
        // name the store keeps is the identity-hiding per-session HKDF —
        // recomputed here so it matches what `SetMedia` wrote.
        let aad = media::media_aad(id, blob_hash);
        let field = media::media_field_name(self.tee_seal_key(), id, blob_hash);
        let req = core::read_request(vec![FieldSelector::Media(field)]);
        let (slots, _version) = self.read_raw(id, req).await?;
        let slot = slots
            .into_iter()
            .next()
            .ok_or_else(|| StoreError::Transport("media read returned no slot".to_string()))?;
        let Some(sealed) = core::unwrap_scalar(slot)? else {
            return Ok(Untrusted::new(None));
        };
        let opened: Untrusted<Vec<u8>, (Replay,)> = boundary::inbound::from_untrusted(sealed)
            .trust::<AuthN, _, _, _, _>(|raw| aead::open(&raw, self.tee_seal_key(), &aad))?
            .trust::<AuthZ, _, _, _, _>(|outer| {
                aead::open(&outer, applicant_session_token, &aad)
            })?;
        Ok(opened.map(Some))
    }

    pub async fn exists(
        &self,
        id: &str,
    ) -> Result<Untrusted<bool, (AuthN, AuthZ, Replay)>, StoreError> {
        let exists = self.backend.exists(id).await?;
        Ok(boundary::inbound::from_untrusted(exists))
    }

    // ---- tuple-trait helper (crate-private) ----
    //
    // Slots come back as raw `Vec<Slot>` (each slot's content gets
    // wrapped per-field inside `ReadField::decode`); the version is
    // wrapped here at the boundary since it's a store-supplied counter.
    pub(crate) async fn read_raw(
        &self,
        id: &str,
        req: ReadRequest,
    ) -> Result<(Vec<Slot>, Untrusted<u64, (AuthN, AuthZ, Replay)>), StoreError> {
        // Slots are returned in the same order as request selectors per the
        // backend contract; we trust that ordering here. Out-of-order or missing
        // slots would be a backend bug.
        let (slots, version) = self.backend.read_raw(id, req).await?;
        Ok((slots, boundary::inbound::from_untrusted(version)))
    }
}

/// Open a write's op set with the two answers every write gives alike, leaving
/// the caller the one that depends on the write: how many ops it makes, which the
/// host counts in the rows of the volume the storage-CVM keeps.
///
/// `AuthN` and `AuthZ` are each member's, not the set's, and each member gives
/// them in its own `build_op` — sealed under its own key or to its own recipient,
/// or carrying no bytes at all. What the set adds is only that its members are
/// written together, to the one record the write names.
pub fn outbound_fields<'a>(
    fields: &'a [&'a dyn WriteField],
) -> Exposed<&'a [&'a dyn WriteField], (Covert,)> {
    boundary::outbound::to_untrusted(fields)
        .vouch_unchecked::<AuthN, _>(reason!(
            "each member is sealed, or carries no bytes, in its own build_op"
        ))
        .vouch_unchecked::<AuthZ, _>(reason!(
            "every member writes the one record this write names, its session's own"
        ))
}
