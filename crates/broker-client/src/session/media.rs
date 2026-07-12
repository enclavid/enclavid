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
//! the policy's `frame::from-blob-ref` rehydrate — a miss returns `None`
//! (surfaced as `load-error::not-found`).

use broker_protocol::{MediaWrite, Op};

use crate::boundary::{AuthN, Exposed};
use crate::error::BridgeError;

use enclavid_crypto::aead;

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
        let blob_key = self.blob_hash.to_vec();
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
                assert_eq!(m.blob_key, hash.to_vec(), "keyed by the content hash");
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
}
