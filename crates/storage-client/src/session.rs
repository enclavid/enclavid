//! Domain-level session storage client.
//!
//! Talks to the storage-CVM's session store through the storage leg, at
//! [`Storage`]. Each per-session field (`metadata`, `state`, `media`,
//! `disclosure`) lives in its own sub-module — read marker, write marker,
//! encode/decode logic co-located by domain so adding a new field is a
//! single new file. The shared trait machinery (`ReadField` / `WriteField` /
//! `ReadTuple` + macro) lives in `core`.
//!
//! Use sites:
//! ```ignore
//! // Read returns (typed_fields, version). Pass the version back
//! // to the next write to detect concurrent modifications.
//! let ((metadata,), version) = session_store.read(&id, (Metadata,)).await?;
//!
//! // Seal the fields into a write's ops, say why how many there are says
//! // nothing, and write them at the expected version; returns the post-write
//! // version. `None` instead: the session must not exist yet (/create).
//! let ops = session_store
//!     .seal(&id, &[&SetMetadata(metadata)])?
//!     .vouch(reason!(Covert::Bounded, "why this many ops says nothing"));
//! let new_v = session_store.write(Some(version), ops).await?;
//! ```
//!
//! Tuple arities up to 16 supported via macro-unrolled trait impls.
//! Each call site picks the fields it needs; wire transfer is
//! proportional (status-only read = 1-byte payload, no metadata
//! baggage).

mod applicant;
mod core;
mod disclosure;
mod lock;
mod media;
mod metadata;
mod state;

pub use self::core::{ReadField, ReadTuple, WriteField};
pub use applicant::DropApplicantData;
pub use disclosure::{AppendDisclosure, Disclosure};
pub use lock::{DataKeys, MAX_DATA_KEYS, lock_data_keys, lock_digest, unlock_data_keys};
pub use media::SetMedia;
pub use metadata::{Metadata, SetMetadata};
pub use state::{SealedState, SetState, StateBinding, encode_padded};

use std::sync::Arc;

use secrecy::{ExposeSecret, SecretBox};

use session_types::{SessionMetadata, SessionState};
use storage_rpc::{Expected, Fields, Ops, RecordName, Slot, Version};

use enclavid_crypto::{aead, derive_key};

use crate::boundary::Storage;
use crate::error::StoreError;
use crate::link::{Link, storage};
use enclavid_boundary::{AuthN, AuthZ, Covert, Exposed, Replay, Untrusted};

/// HKDF info label for the subkey a record's name is derived under.
const RECORD_INFO: &[u8] = b"enclavid.session-record.v1";
/// HKDF info label for the subkey a hand-over is sealed under, and what each
/// hand-over is labelled with beside its session.
const HANDOFF_INFO: &[u8] = b"enclavid.handoff.v1";

/// What a hand-over carries: the key that held the session as it was made, the
/// lock that key held it by, and the time it may be taken until.
pub struct Handoff {
    pub key: SecretBox<Vec<u8>>,
    /// The [`lock_digest`] of the lock `key` opened as the hand-over was made.
    pub lock: [u8; 32],
    pub until_unix_secs: u64,
}

/// Per-call encryption context: the TEE-side key, and the session every seal
/// it makes or opens is bound to. Each field binds its own AAD from these, so a
/// ciphertext copied between sessions, or between fields, fails authentication.
pub struct Ctx<'a> {
    pub tee_seal_key: &'a [u8],
    pub session_id: &'a str,
}

/// The session store's client: every field is sealed and opened here, and the
/// leg underneath moves only what this side has already sealed.
///
/// A session's id never crosses. Its record is named by a digest of the id under
/// a key only api holds ([`record`](Self::record)), so neither the storage-CVM
/// nor the volume it keeps the record on ever holds the id. What the record must
/// be for a write to land crosses as an [`Expected`], which [`Storage`] answers
/// in full: the version is the store's own counter, and the deadline is the
/// create's time plus a configured lifetime.
///
/// The fields are another matter. The volume holds them as they were sent, so
/// each is the host's to read, and each is an op of its own kind, answered for
/// itself as [`seal`](Self::seal) adds it.
#[derive(Clone)]
pub struct SessionStore {
    /// The storage leg, at [`Storage`]. All crypto stays HERE; the leg moves
    /// what this side has already sealed.
    link: Arc<dyn Link>,
    /// TEE-side AEAD master key used for METADATA and as the outer layer of
    /// STATE — the hardware-rooted crown jewel every session seal derives from.
    /// The caller injects it, and where the caller gets it is the caller's
    /// business: api derives it from the chip under `sev-snp`
    /// (`enclavid_attestation::derive_seal_key`), so in the measured image it is
    /// bound to the measurement and never leaves the enclave. A dev build takes
    /// it from the environment instead.
    /// `SecretBox` zeroizes it on drop and redacts it from any `Debug` — so the
    /// master never lands in a log, matching how the applicant's key is held; the
    /// `Arc` keeps cloning the store cheap (the store derives `Clone`).
    tee_seal_key: Arc<SecretBox<[u8; 32]>>,
    /// The subkey of `tee_seal_key` a record's name is derived under, its own
    /// label apart from every other use of the master.
    record_key: Arc<SecretBox<[u8; 32]>>,
    /// The subkey of `tee_seal_key` a hand-over is sealed under, its own label
    /// apart from every other use of the master.
    handoff_key: Arc<SecretBox<[u8; 32]>>,
    /// ABSOLUTE session lifetime in seconds. `Some(t)` ⇒ the deadline is set ONCE
    /// at create to `created_at + t` and never refreshed — a fixed cap after which
    /// the storage-CVM sweeper GCs the session (abandoned or completed-and-pulled).
    /// The sweep runs on the storage-CVM's guarded clock, but the deadline lies
    /// on the host's volume, so a host can move it; and it can keep a copy of the
    /// volume regardless. Sized so the consumer has time to pull disclosures
    /// post-completion. `None` = no expiry.
    ttl_secs: Option<u64>,
}

impl SessionStore {
    pub fn new(link: Arc<dyn Link>, tee_seal_key: [u8; 32], ttl_secs: Option<u64>) -> Self {
        Self {
            link,
            record_key: Arc::new(SecretBox::new(Box::new(derive_key(
                &tee_seal_key,
                RECORD_INFO,
            )))),
            handoff_key: Arc::new(SecretBox::new(Box::new(derive_key(
                &tee_seal_key,
                HANDOFF_INFO,
            )))),
            tee_seal_key: Arc::new(SecretBox::new(Box::new(tee_seal_key))),
            ttl_secs,
        }
    }

    pub(crate) fn tee_seal_key(&self) -> &[u8] {
        self.tee_seal_key.expose_secret().as_slice()
    }

    /// The name the record of `session_id` is kept under: a keyed digest of the
    /// id, which tells whoever reads it nothing of the id — the work that lets
    /// it leave. Deterministic, so every call for one session names its one
    /// record.
    fn record(&self, session_id: &str) -> Exposed<RecordName, (), Storage> {
        let Ok(name) = Storage::expose_builder::<RecordName, _>(session_id).vouch_with(
            AuthN::Verified,
            |id| {
                Ok::<_, std::convert::Infallible>(RecordName(derive_key(
                    self.record_key.expose_secret(),
                    id.as_bytes(),
                )))
            },
        );
        name.build()
    }

    /// How long a session lives, as this store was given it: what a session's
    /// own terms are held under.
    pub fn ttl_secs(&self) -> Option<u64> {
        self.ttl_secs
    }

    /// The absolute deadline (unix secs) for a session created NOW to live
    /// `ttl` — `None` for no TTL. Computed TEE-side and passed ONLY on the create
    /// write (see [`write`](Self::write)); subsequent writes name a version
    /// instead, so the deadline is never moved.
    fn deadline(ttl: Option<u64>) -> Option<u64> {
        ttl.map(|ttl| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            now.saturating_add(ttl)
        })
    }

    /// Read typed session fields in one batch. Returns `(fields, version)`
    /// where each field carries its own per-field scope and `version` is open
    /// on `Replay` alone. Pass `version` back to the next `write` to detect
    /// concurrent modifications; nothing else is decided on it — whether a
    /// session exists is its metadata's to say, opened.
    pub async fn read<T: ReadTuple>(
        &self,
        id: &str,
        fields: T,
    ) -> Result<(T::Output, Untrusted<u64, (Replay,), Storage>), StoreError> {
        fields.fetch(self, id).await
    }

    /// The ops `fields` make for the session `id`, each sealed under its own key
    /// or to its own recipient as it is added — metadata AEAD vs state
    /// double-AEAD vs disclosure sealed to the consumer are not the same concern,
    /// so each answers for itself. What is left open on the set is how many ops
    /// it makes and of which kinds (`Covert`), which the host counts in the rows
    /// of the volume and only the caller can say why it says nothing.
    ///
    /// `fields` is a heterogeneous slice of `&dyn WriteField`, mixing static
    /// markers (`SetState`, `SetMetadata`, `SetMedia`) with dynamic-buffer
    /// entries (`AppendDisclosure`). The set names the record of `id`, which is
    /// the session its ops are sealed for, so it can only be written there.
    ///
    /// The count is the caller's to answer before the set is written:
    ///
    /// ```compile_fail
    /// # async fn f(store: &storage_client::SessionStore, set: &storage_client::SetMetadata<'_>) {
    /// let ops = store.seal("ses", &[set]).unwrap();
    /// store.write(Some(1), ops).await.unwrap();
    /// # }
    /// ```
    ///
    /// and once answered, the set is written:
    ///
    /// ```
    /// # use enclavid_boundary::{Covert, reason};
    /// # async fn f(store: &storage_client::SessionStore, set: &storage_client::SetMetadata<'_>) {
    /// let ops = store
    ///     .seal("ses", &[set])
    ///     .unwrap()
    ///     .vouch(reason!(Covert::Bounded, "one fixed field"));
    /// store.write(Some(1), ops).await.unwrap();
    /// # }
    /// ```
    pub fn seal(
        &self,
        id: &str,
        fields: &[&dyn WriteField],
    ) -> Result<Exposed<Ops<Storage>, (Covert,), Storage>, StoreError> {
        let ctx = Ctx {
            tee_seal_key: self.tee_seal_key(),
            session_id: id,
        };
        let mut ops = Ops::for_record(self.record(id));
        for f in fields {
            f.add_to(&mut ops, &ctx)?;
        }
        Ok(Storage::expose(ops))
    }

    /// Atomic write of a set of ops in one transaction, to the record they were
    /// sealed for: the store applies them alongside the version check. `ops` is
    /// what [`seal`](Self::seal) made, answered in full — the signature is the
    /// type-level guarantee that nothing unanswered is written.
    ///
    /// `expected_version` is the version check: `None` means the
    /// session must not exist yet (used by /create); `Some(V)` means
    /// the session's current version in the store must equal V.
    /// Mismatch surfaces as `StoreError::VersionMismatch` (HTTP 412).
    pub async fn write(
        &self,
        expected_version: Option<u64>,
        ops: Exposed<Ops<Storage>, (), Storage>,
    ) -> Result<Untrusted<u64, (Replay,), Storage>, StoreError> {
        self.write_living(expected_version, self.ttl_secs, ops)
            .await
    }

    /// The create write — [`write`](Self::write) with `expected_version` `None`
    /// — for a session that lives `ttl_secs` rather than this store's own TTL:
    /// its own terms'.
    pub async fn create(
        &self,
        ttl_secs: u64,
        ops: Exposed<Ops<Storage>, (), Storage>,
    ) -> Result<Untrusted<u64, (Replay,), Storage>, StoreError> {
        self.write_living(None, Some(ttl_secs), ops).await
    }

    async fn write_living(
        &self,
        expected_version: Option<u64>,
        ttl: Option<u64>,
        ops: Exposed<Ops<Storage>, (), Storage>,
    ) -> Result<Untrusted<u64, (Replay,), Storage>, StoreError> {
        // Absolute TTL: set the deadline ONLY on the create write (`None` =
        // must-not-exist); every subsequent update names a version instead, so
        // the fixed `created_at + ttl` cap is never moved.
        let expected = Storage::expose(match expected_version {
            None => Expected::Absent {
                deadline_unix_secs: Self::deadline(ttl),
            },
            Some(version) => Expected::Version(version),
        });
        let version = storage(self.link.as_ref())?.write(expected, ops).await?;
        Ok(version.map(|Version(v)| v))
    }

    /// Open the state of session `id`, as read with [`SealedState`] beside the
    /// session's metadata, opened: `metadata`. The state is bound to what that
    /// metadata records of the applicant ([`StateBinding`]), so one put back from
    /// before a reset, or from before a newer disclosure or capture, does not
    /// open; and one missing beside metadata that records an applicant's data is
    /// refused as one that does not open. Both come back as `StoreError::Crypto`,
    /// as a key that does not open the state does. `data_key` is the one the
    /// session seals under now — [`DataKeys::current`].
    pub fn open_state(
        &self,
        id: &str,
        sealed: Untrusted<Option<Vec<u8>>, (AuthN, AuthZ, Replay), Storage>,
        metadata: &SessionMetadata,
        data_key: &[u8],
    ) -> Result<Untrusted<Option<SessionState>, (Replay,), Storage>, StoreError> {
        let ctx = Ctx {
            tee_seal_key: self.tee_seal_key(),
            session_id: id,
        };
        state::open(&ctx, sealed, metadata, data_key)
    }

    /// A hand-over of session `id`: the key that holds it, the lock that key
    /// holds it by ([`lock_digest`]), and the time it may be taken until, sealed
    /// under a key only this side holds. The page carries it to another device
    /// and only this side opens it, so the key never travels in the open. It is
    /// good against that one lock: taking it, or anything else that replaces
    /// the lock, leaves it opening nothing.
    pub fn seal_handoff(&self, id: &str, handoff: &Handoff) -> Result<Vec<u8>, StoreError> {
        let key = handoff.key.expose_secret();
        let mut plaintext = Vec::with_capacity(8 + 32 + key.len());
        plaintext.extend_from_slice(&handoff.until_unix_secs.to_be_bytes());
        plaintext.extend_from_slice(&handoff.lock);
        plaintext.extend_from_slice(key);
        let plaintext = SecretBox::new(Box::new(plaintext));
        Ok(aead::seal(
            plaintext.expose_secret(),
            self.handoff_key.expose_secret(),
            &handoff_aad(id),
        )?)
    }

    /// What [`seal_handoff`](Self::seal_handoff) sealed for session `id`. One
    /// made for another session, or not by this side, is a
    /// `StoreError::Crypto`.
    pub fn open_handoff(&self, id: &str, sealed: &[u8]) -> Result<Handoff, StoreError> {
        let opened = SecretBox::new(Box::new(aead::open(
            sealed,
            self.handoff_key.expose_secret(),
            &handoff_aad(id),
        )?));
        let short = || StoreError::Crypto("a hand-over too short for its fields".into());
        let (until, rest) = opened
            .expose_secret()
            .split_at_checked(8)
            .ok_or_else(short)?;
        let (lock, key) = rest.split_at_checked(32).ok_or_else(short)?;
        Ok(Handoff {
            key: SecretBox::new(Box::new(key.to_vec())),
            lock: lock.try_into().expect("split at thirty-two"),
            until_unix_secs: u64::from_be_bytes(until.try_into().expect("split at eight")),
        })
    }

    /// Read + double-open one sealed media blob by its content hash. Backs the
    /// policy's `blob::from-blob-ref` rehydrate. `None` = no such blob in this
    /// session (the engine turns a miss into a TRAP). The plaintext comes back
    /// open on `Replay` alone — outer-AEAD-open closes AuthN (real crypto),
    /// inner-AEAD-open closes AuthZ (possession of the data keys, which only the
    /// applicant's key unlocks, authorises); only Replay remains for the caller
    /// (trivially closed: the blob is content-addressed, so a stale / reordered
    /// read can only return identical bytes). The AAD mirrors [`SetMedia`]'s.
    ///
    /// A blob is under the key the session sealed under as it was captured,
    /// which a take-over since may have followed with newer ones: the keys are
    /// tried newest first, and an AEAD under any other key refuses to open.
    pub async fn load_media(
        &self,
        id: &str,
        blob_hash: &[u8; 32],
        data_keys: &DataKeys,
    ) -> Result<Untrusted<Option<Vec<u8>>, (Replay,), Storage>, StoreError> {
        // The AAD binds to the raw content hash (TEE-internal), but the name the
        // store keeps is the identity-hiding per-session HKDF — recomputed here
        // so it matches what `SetMedia` wrote.
        let ctx = Ctx {
            tee_seal_key: self.tee_seal_key(),
            session_id: id,
        };
        let aad = media::media_aad(id, blob_hash);
        let mut fields = Fields::new();
        fields.media(media::media_name(&ctx, blob_hash));
        let (slots, _version) = self.read_raw(id, fields).await?;
        let slot = slots
            .into_iter()
            .next()
            .expect("read_raw holds the slots to the selectors");
        // An absent blob opens to an absent value, through both layers.
        let opened = core::scalar(slot)?
            .trust_with(AuthN::Verified, |sealed| {
                sealed
                    .map(|raw| aead::open(&raw, self.tee_seal_key(), &aad))
                    .transpose()
            })?
            .trust_with(AuthZ::Matched, |outer| {
                outer
                    .map(|outer| {
                        data_keys
                            .newest_first()
                            .find_map(|key| aead::open(&outer, key, &aad).ok())
                            .ok_or_else(|| {
                                StoreError::Crypto("no data key of the session opens it".into())
                            })
                    })
                    .transpose()
            })?;
        Ok(opened)
    }

    // ---- tuple-trait helper (crate-private) ----
    //
    // Each slot comes back open on what `Storage` leaves open on one, and is
    // answered per field inside `ReadField::decode`; the version comes back open
    // on `Replay` alone, `Storage` having answered the rest for every version.
    #[allow(clippy::type_complexity)]
    pub(crate) async fn read_raw(
        &self,
        id: &str,
        fields: Fields<Storage>,
    ) -> Result<
        (
            Vec<Untrusted<Slot, (AuthN, AuthZ, Replay), Storage>>,
            Untrusted<u64, (Replay,), Storage>,
        ),
        StoreError,
    > {
        let asked = fields.len();
        // Field tags and media names, each answered where it was minted:
        // `Storage` answers the set in full.
        let (slots, version) = storage(self.link.as_ref())?
            .read(self.record(id), Storage::expose(fields))
            .await?;
        // One slot a field, in order: the store answers so whatever its volume
        // holds, and a reply that does not is refused rather than read.
        if slots.len() != asked {
            return Err(StoreError::Transport(
                "a read came back without one slot a field".to_string(),
            ));
        }
        Ok((slots, version.map(|Version(v)| v)))
    }
}

/// The AAD a hand-over is sealed under: the label, then the session. The label
/// is fixed-length, so the session id last cannot be read two ways.
fn handoff_aad(session_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HANDOFF_INFO.len() + session_id.len());
    aad.extend_from_slice(HANDOFF_INFO);
    aad.extend_from_slice(session_id.as_bytes());
    aad
}

#[cfg(test)]
mod tests;
