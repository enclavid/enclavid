//! `MEDIA` per-session store. Content-addressed, sealed applicant captures
//! (camera frames today, documents/PDFs later), keyed by each blob's 32-byte
//! BLAKE3. Double-AEAD'd exactly like STATE: inner layer under the applicant's
//! bearer token, outer under `tee_seal_key`. AAD = `session_id || blob_hash`
//! on both layers, so (a) cross-session copies fail at the outer check and
//! (b) a host swapping blob-A's ciphertext under blob-B's key within a session
//! also fails auth.
//!
//! Writes ride the same atomic `SessionStore::write` batch as the reducer
//! `SetState` (co-committed under one version CAS). Reads are one-off per ref
//! via [`SessionStore::load_media`](super::SessionStore::load_media), backing
//! the policy's `blob::from-blob-ref` rehydrate — a miss returns `None`, which
//! the engine turns into a TRAP (a fabricated ref is never a legitimate
//! outcome). The api layer fronts this read with a pull-through cache + an
//! in-TEE captured-hash gate, so most reads never reach the hatch.

use hatch_protocol::{MediaWrite, Op};

use crate::boundary::{AuthN, Exposed};
use crate::error::BridgeError;

use enclavid_crypto::{aead, derive_key};

use super::Ctx;
use super::core::WriteField;

/// AAD for a media blob: `session_id || blob_hash`. Binds the sealed blob to
/// both its session and its content-hash key.
pub(super) fn media_aad(session_id: &str, blob_hash: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(session_id.len() + blob_hash.len());
    aad.extend_from_slice(session_id.as_bytes());
    aad.extend_from_slice(blob_hash);
    aad
}

/// HKDF info label for the identity-hiding media field name.
const MEDIA_FIELD_INFO: &[u8] = b"enclavid.media-field.v1";

/// The HOST-visible field name for a media blob inside `session:{id}:media`:
/// `HKDF(tee_seal_key, "media-field.v1" || session_id || content_hash)`.
///
/// The blob VALUE is double-AEAD'd, but the raw content-hash must NOT be the field
/// name: it is a deterministic function of the applicant's plaintext, so the
/// untrusted host could compare it ACROSS sessions and link two sessions that
/// captured byte-identical content (e.g. the same document re-uploaded). Keying the
/// name under the per-session `tee_seal_key` PRF gives the host a pseudo-random,
/// per-session name it cannot invert or compare — the same identity-hiding the L2
/// cwasm cache uses for its blob names. It stays DETERMINISTIC within a session
/// (same inputs → same name) so `from-blob-ref` recomputes it on read, and dedups
/// identical captures; the raw content-hash never leaves the TEE. (The 32-byte hash
/// is fixed-length and last, so the `session_id || hash` concatenation is
/// unambiguous — no length-prefix needed.)
pub(super) fn media_field_name(tee_seal_key: &[u8], session_id: &str, blob_hash: &[u8; 32]) -> Vec<u8> {
    let mut info = Vec::with_capacity(MEDIA_FIELD_INFO.len() + session_id.len() + blob_hash.len());
    info.extend_from_slice(MEDIA_FIELD_INFO);
    info.extend_from_slice(session_id.as_bytes());
    info.extend_from_slice(blob_hash);
    let master: &[u8; 32] = tee_seal_key.try_into().expect("tee_seal_key is 32 bytes");
    derive_key(master, &info).to_vec()
}

/// Write marker: seal one captured media blob into the per-session media hash,
/// keyed by its content hash. Payload is `Exposed<Vec<u8>, (AuthN,)>` — the
/// caller (persister) pre-vouches AuthZ (key possession authorises) and Covert
/// (the ciphertext SIZE is applicant-capture-driven, not policy-controlled, so
/// it is not a new channel; and because every capture is stored
/// unconditionally — "always store" — write PRESENCE is not a channel either).
/// Host-bridge closes AuthN via the double-AEAD seal it owns the keys for.
pub struct SetMedia<'a> {
    pub blob_hash: [u8; 32],
    pub bytes: Exposed<Vec<u8>, (AuthN,)>,
    pub applicant_session_token: &'a [u8],
}

impl WriteField for SetMedia<'_> {
    fn build_op(&self, ctx: &Ctx<'_>) -> Result<Exposed<Op, ()>, BridgeError> {
        // AuthZ + Covert are pre-vouched at the construction site. Host-bridge
        // closes AuthN with the double-AEAD seal: inner under
        // applicant_session_token, outer under tee_seal_key. Each layer gets
        // its own random nonce; AAD = session_id||blob_hash identical on both,
        // so a cross-session (or cross-key-within-session) copy fails.
        let aad = media_aad(ctx.session_id, &self.blob_hash);
        // Host-visible field name = the identity-hiding per-session HKDF of the
        // content hash (NOT the raw hash — see `media_field_name`). The AAD above
        // stays keyed by the raw content hash (TEE-internal binding), so the
        // double-AEAD's cross-session / cross-key protection is unchanged.
        let blob_key = media_field_name(ctx.tee_seal_key, ctx.session_id, &self.blob_hash);
        let sealed = self.bytes.clone().vouch::<AuthN, _, _, _, _>(
            |plaintext| -> Result<Vec<u8>, BridgeError> {
                let inner = aead::seal(&plaintext, self.applicant_session_token, &aad)?;
                aead::seal(&inner, ctx.tee_seal_key, &aad).map_err(Into::into)
            },
        )?;
        Ok(sealed.map(move |value| Op::MediaWrite(MediaWrite { blob_key, value })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary;
    use crate::reason;

    fn exposed_bytes(bytes: Vec<u8>) -> Exposed<Vec<u8>, (AuthN,)> {
        boundary::outbound::to_untrusted(bytes)
            .vouch_unchecked::<crate::boundary::AuthZ, _>(reason!("test"))
            .vouch_unchecked::<crate::boundary::Covert, _>(reason!("test"))
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
        let op = set.build_op(&ctx).unwrap().into_inner();
        let sealed = match op {
            Op::MediaWrite(m) => {
                // Host-visible field name is the identity-hiding HKDF name, NOT the
                // raw content-hash (which would let the host link identical content
                // across sessions).
                assert_eq!(
                    m.blob_key,
                    media_field_name(ctx.tee_seal_key, ctx.session_id, &hash),
                    "keyed by the per-session HKDF field name",
                );
                assert_ne!(m.blob_key, hash.to_vec(), "must NOT expose the raw content-hash");
                m.value
            }
            _ => panic!("SetMedia must emit Op::MediaWrite"),
        };

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
        assert_ne!(a1, b, "identical content in two sessions must not share a name");
        // Different content in the same session -> different name.
        assert_ne!(a1, other_content);
        // Never the raw content hash (that is exactly what we are hiding).
        assert_ne!(a1, hash.to_vec());
        assert_eq!(a1.len(), 32);
    }
}
