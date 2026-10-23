//! `MEDIA` per-session store. Sealed applicant captures (camera frames today,
//! documents/PDFs later), each found by its 32-byte BLAKE3 content hash and
//! kept under a [`MediaName`] derived from it. Double-AEAD'd exactly like
//! STATE: inner layer under the applicant's bearer token, outer under
//! `tee_seal_key`. Both layers are bound (AAD) to the field, the content hash and
//! the session, so (a) cross-session copies fail at the outer check and (b) a
//! host swapping blob-A's ciphertext under blob-B's name within a session also
//! fails auth.
//!
//! Writes ride the same atomic `SessionStore::write` batch as the reducer
//! `SetState` (co-committed under one version CAS). Reads are one-off per ref
//! via [`SessionStore::load_media`](super::SessionStore::load_media), backing
//! the policy's `blob::from-blob-ref` rehydrate — a miss returns `None`, which
//! the engine turns into a TRAP (a fabricated ref is never a legitimate
//! outcome). The api layer fronts this read with an in-TEE captured-hash gate,
//! so a hash nobody captured never reaches the store.

use storage_rpc::{MediaName, MediaOp, Ops};

use crate::boundary::Storage;
use crate::error::StoreError;
use enclavid_boundary::{AuthN, Exposed, ExposedBuilder};

use enclavid_crypto::{aead, derive_key};

use super::Ctx;
use super::core::WriteField;

/// What a media seal is labelled with, apart from every other field's.
const MEDIA_AAD: &[u8] = b"enclavid.media.v1";

/// AAD for a media blob: the field, its content hash, its session. The label and
/// the hash are fixed-length, so the session id last cannot be read two ways.
pub(super) fn media_aad(session_id: &str, blob_hash: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(MEDIA_AAD.len() + blob_hash.len() + session_id.len());
    aad.extend_from_slice(MEDIA_AAD);
    aad.extend_from_slice(blob_hash);
    aad.extend_from_slice(session_id.as_bytes());
    aad
}

/// HKDF info label for the identity-hiding media field name.
const MEDIA_FIELD_INFO: &[u8] = b"enclavid.media-field.v1";

/// The name a record keeps a media blob under:
/// `HKDF(tee_seal_key, "media-field.v1" || session_id || content_hash)`.
///
/// The blob VALUE is double-AEAD'd, but the raw content-hash must NOT be the
/// name: it is a deterministic function of the applicant's plaintext, so the
/// untrusted host could compare it ACROSS sessions and link two sessions that
/// captured byte-identical content (e.g. the same document re-uploaded). Keying
/// the name under the per-session `tee_seal_key` PRF gives the host a
/// pseudo-random, per-session name it cannot invert or compare — the same
/// identity-hiding the L2 cwasm cache uses for its blob names. It stays
/// DETERMINISTIC within a session (same inputs → same name) so `from-blob-ref`
/// recomputes it on read, and dedups identical captures; the raw content-hash
/// never leaves the TEE. (The 32-byte hash is fixed-length and last, so the
/// `session_id || hash` concatenation is unambiguous — no length-prefix needed.)
pub(super) fn media_field_name(
    tee_seal_key: &[u8],
    session_id: &str,
    blob_hash: &[u8; 32],
) -> [u8; 32] {
    let mut info = Vec::with_capacity(MEDIA_FIELD_INFO.len() + session_id.len() + blob_hash.len());
    info.extend_from_slice(MEDIA_FIELD_INFO);
    info.extend_from_slice(session_id.as_bytes());
    info.extend_from_slice(blob_hash);
    let master: &[u8; 32] = tee_seal_key.try_into().expect("tee_seal_key is 32 bytes");
    derive_key(master, &info)
}

/// The name the capture whose content hash is `blob_hash` is kept under, minted
/// to leave: the keyed derivation is the work that lets it — what its reader
/// sees is a digest it can neither invert nor compute.
pub(super) fn media_name(ctx: &Ctx<'_>, blob_hash: &[u8; 32]) -> Exposed<MediaName, (), Storage> {
    let Ok(name) =
        Storage::expose_builder::<MediaName, _>(blob_hash).vouch_with(AuthN::Verified, |hash| {
            Ok::<_, std::convert::Infallible>(MediaName(media_field_name(
                ctx.tee_seal_key,
                ctx.session_id,
                hash,
            )))
        });
    name.build()
}

/// Write marker: seal one captured media blob into the per-session media hash,
/// keyed by its content hash. Payload is a [`MediaOp`] being built from the
/// frame, with `AuthN` alone open: [`Storage`] answers `AuthZ` for every media
/// op, and the caller (persister) `Covert` — the ciphertext SIZE is
/// applicant-capture-driven, not policy-controlled, so it is not a new channel;
/// and because every capture is stored unconditionally — "always store" —
/// write PRESENCE is not a channel either. storage-client answers `AuthN` with
/// the double-AEAD seal it owns the keys for, which builds the op.
pub struct SetMedia<'a> {
    pub blob_hash: [u8; 32],
    pub bytes: ExposedBuilder<Vec<u8>, MediaOp, (AuthN,), Storage>,
    pub applicant_session_token: &'a [u8],
}

impl SetMedia<'_> {
    /// The op, sealed, and the name it is kept under.
    #[allow(clippy::type_complexity)]
    fn op(
        &self,
        ctx: &Ctx<'_>,
    ) -> Result<
        (
            Exposed<MediaName, (), Storage>,
            Exposed<MediaOp, (), Storage>,
        ),
        StoreError,
    > {
        // The double-AEAD seal: inner under applicant_session_token, outer under
        // tee_seal_key. Each layer gets its own random nonce; both are bound to
        // the same AAD (field, content hash, session), so a cross-session (or
        // cross-name-within-session) copy fails. The name the host sees is the
        // identity-hiding per-session HKDF of the content hash, NOT the raw hash
        // (see `media_field_name`); the AAD stays bound to the raw hash inside
        // the TEE.
        let aad = media_aad(ctx.session_id, &self.blob_hash);
        let op = self
            .bytes
            .clone()
            .vouch_with(AuthN::Verified, |plaintext| -> Result<_, StoreError> {
                let inner = aead::seal(&plaintext, self.applicant_session_token, &aad)?;
                Ok(MediaOp(aead::seal(&inner, ctx.tee_seal_key, &aad)?))
            })?
            .build();
        Ok((media_name(ctx, &self.blob_hash), op))
    }
}

impl WriteField for SetMedia<'_> {
    fn add_to(&self, ops: &mut Ops<Storage>, ctx: &Ctx<'_>) -> Result<(), StoreError> {
        let (name, op) = self.op(ctx)?;
        ops.media(name, op);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclavid_boundary::{Covert, reason};

    fn exposed_bytes(bytes: Vec<u8>) -> ExposedBuilder<Vec<u8>, MediaOp, (AuthN,), Storage> {
        Storage::expose_builder::<MediaOp, _>(bytes)
            .vouch(reason!(Covert::AlreadyHeld, "test fixture"))
    }

    #[test]
    fn seal_open_round_trips_and_binds_aad() {
        let tee_key = [7u8; 32];
        let app_token = [9u8; 32];
        let ctx = Ctx {
            tee_seal_key: &tee_key,
            session_id: "ses_abc",
        };
        let hash = [3u8; 32];
        let plaintext = b"one jpeg frame's bytes".to_vec();

        let set = SetMedia {
            blob_hash: hash,
            bytes: exposed_bytes(plaintext.clone()),
            applicant_session_token: &app_token,
        };
        let (name, op) = set.op(&ctx).unwrap();
        let (MediaName(name), MediaOp(sealed)) = (name.into_inner(), op.into_inner());
        // Host-visible field name is the identity-hiding HKDF name, NOT the raw
        // content-hash (which would let the host link identical content across
        // sessions).
        assert_eq!(
            name,
            media_field_name(ctx.tee_seal_key, ctx.session_id, &hash),
            "keyed by the per-session HKDF field name",
        );
        assert_ne!(name, hash, "must NOT expose the raw content-hash");

        // Double-open with the same keys + AAD round-trips.
        let aad = media_aad(ctx.session_id, &hash);
        let outer = aead::open(&sealed, &tee_key, &aad).unwrap();
        let inner = aead::open(&outer, &app_token, &aad).unwrap();
        assert_eq!(inner, plaintext, "double-AEAD round-trips");

        // A different blob-hash → different AAD → outer open fails (the host
        // can't relabel one session's blob as another's key).
        let wrong_aad = media_aad(ctx.session_id, &[4u8; 32]);
        assert!(aead::open(&sealed, &tee_key, &wrong_aad).is_err());
        // A different session id → different AAD → outer open fails.
        let cross_session = media_aad("ses_other", &hash);
        assert!(aead::open(&sealed, &tee_key, &cross_session).is_err());
    }

    #[test]
    fn media_field_name_hides_content_identity_across_sessions() {
        let key = [7u8; 32];
        let hash = [3u8; 32];
        let a1 = media_field_name(&key, "ses_a", &hash);
        let a2 = media_field_name(&key, "ses_a", &hash);
        let b = media_field_name(&key, "ses_b", &hash);
        let other_content = media_field_name(&key, "ses_a", &[4u8; 32]);

        // Deterministic within a session → from-blob-ref rehydrate recomputes it,
        // and identical captures dedup to one field.
        assert_eq!(a1, a2, "same (session, content) -> same field name");
        // THE POINT: identical content in two sessions -> DIFFERENT host field name,
        // so the untrusted host can't link the sessions by comparing field names.
        assert_ne!(
            a1, b,
            "identical content in two sessions must not share a name"
        );
        // Different content in the same session -> different name.
        assert_ne!(a1, other_content);
        // Never the raw content hash (that is exactly what we are hiding).
        assert_ne!(a1, hash);
        // Keyed: whoever knows the session id and the content, but not the key,
        // cannot compute the name.
        assert_ne!(a1, media_field_name(&[8u8; 32], "ses_a", &hash));
    }
}
