//! AEAD over a stream, for blobs too large to seal or open whole.
//!
//! The STREAM construction over ChaCha20-Poly1305, as the `aead` crate's
//! `stream` module implements it (a big-endian 32-bit segment counter and a
//! last-segment flag in the nonce). A sealed stream is
//!
//! ```text
//! version (1 byte) || salt (32 bytes) || segment || ... || last segment
//! ```
//!
//! Every segment seals [`SEGMENT_BYTES`] of plaintext and the last one the rest,
//! possibly none, each under its own tag. So an [`Opener`] hands plaintext on a
//! segment at a time, each authenticated before it is handed on, and nobody
//! holds the whole stream.
//!
//! The key is derived from the caller's key and the salt, so it is fresh for
//! every stream and the nonce — a counter and the flag — never repeats under
//! one. The flag is what makes the end of the stream part of what is
//! authenticated: a stream cut short, at a segment boundary or inside a
//! segment, does not open, and neither does one with a segment dropped,
//! reordered or taken from another stream.
//!
//! `aad` binds every segment to the caller's context, as it does in
//! [`crate::aead`].

use chacha20poly1305::aead::Payload;
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::{ChaCha20Poly1305, Key};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::kdf::derive_key;

/// How much plaintext each segment but the last seals.
pub const SEGMENT_BYTES: usize = 64 * 1024;

/// What each segment adds to its plaintext: its Poly1305 tag.
const TAG_BYTES: usize = 16;

/// The format this module writes and the only one it opens.
const VERSION: u8 = 1;

const SALT_BYTES: usize = 32;

/// What precedes the segments: the version and the salt.
const HEADER_BYTES: usize = 1 + SALT_BYTES;

/// What the per-stream key is derived under, beside the salt.
const KEY_INFO: &[u8] = b"enclavid.sealed-stream.v1";

/// The length of the stream that seals `plain` bytes of plaintext.
pub const fn sealed_len(plain: u64) -> u64 {
    let segments = match plain.div_ceil(SEGMENT_BYTES as u64) {
        0 => 1,
        n => n,
    };
    HEADER_BYTES as u64 + plain + segments * TAG_BYTES as u64
}

/// The length of the plaintext a stream of `sealed` bytes holds, or `None` when
/// no stream is that long.
pub fn plain_len(sealed: u64) -> Option<u64> {
    let body = sealed.checked_sub(HEADER_BYTES as u64)?;
    let segments = body.div_ceil((SEGMENT_BYTES + TAG_BYTES) as u64).max(1);
    let plain = body.checked_sub(segments * TAG_BYTES as u64)?;
    (sealed_len(plain) == sealed).then_some(plain)
}

/// The key one stream is sealed under: `key` and the stream's salt.
fn stream_key(key: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    let mut info = Vec::with_capacity(KEY_INFO.len() + salt.len());
    info.extend_from_slice(KEY_INFO);
    info.extend_from_slice(salt);
    derive_key(key, &info)
}

/// Seals a stream piece by piece.
///
/// [`new`](Self::new) gives the header, which goes first; each
/// [`push`](Self::push) gives the segments its plaintext completes; and
/// [`finish`](Self::finish) gives the last one. A segment is sealed only once
/// more plaintext is known to follow it, because the last one is sealed
/// differently.
pub struct Sealer {
    encryptor: EncryptorBE32<ChaCha20Poly1305>,
    aad: Vec<u8>,
    /// Plaintext not sealed yet: at most one segment's worth.
    pending: Vec<u8>,
}

impl Sealer {
    /// A sealer under a key derived from `key` and a fresh salt, and the
    /// stream's header.
    pub fn new(key: &[u8; 32], aad: &[u8]) -> (Self, Vec<u8>) {
        let mut header = vec![VERSION; HEADER_BYTES];
        OsRng.fill_bytes(&mut header[1..]);
        let mut derived = stream_key(key, &header[1..]);
        // The key is this stream's alone, so the nonce prefix needs nothing in it.
        let encryptor = EncryptorBE32::new(Key::from_slice(&derived), &Default::default());
        derived.zeroize();
        (
            Self {
                encryptor,
                aad: aad.to_vec(),
                pending: Vec::with_capacity(SEGMENT_BYTES),
            },
            header,
        )
    }

    /// Take `plain`, and return the sealed segments it completes. What it
    /// returns grows with what it is given, so a caller with much to seal
    /// gives it in pieces.
    pub fn push(&mut self, mut plain: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut sealed = Vec::new();
        while !plain.is_empty() {
            if self.pending.len() == SEGMENT_BYTES {
                let segment = self
                    .encryptor
                    .encrypt_next(Payload {
                        msg: &self.pending,
                        aad: &self.aad,
                    })
                    .map_err(|_| CryptoError::new("stream seal failed"))?;
                sealed.extend_from_slice(&segment);
                self.pending.clear();
            }
            let take = (SEGMENT_BYTES - self.pending.len()).min(plain.len());
            self.pending.extend_from_slice(&plain[..take]);
            plain = &plain[take..];
        }
        Ok(sealed)
    }

    /// Seal what is left as the last segment.
    pub fn finish(self) -> Result<Vec<u8>, CryptoError> {
        self.encryptor
            .encrypt_last(Payload {
                msg: &self.pending,
                aad: &self.aad,
            })
            .map_err(|_| CryptoError::new("stream seal failed"))
    }
}

/// Opens a stream piece by piece.
///
/// Each [`push`](Self::push) returns the plaintext of the segments it
/// completes, every one authenticated; [`finish`](Self::finish) opens the
/// last. A segment is opened only once more of the stream is known to follow
/// it, because the last one opens differently. An error leaves the stream
/// refused: nothing after it is opened.
pub struct Opener {
    key: [u8; 32],
    aad: Vec<u8>,
    /// The header while it is still arriving; empty once it has.
    header: Vec<u8>,
    decryptor: Option<DecryptorBE32<ChaCha20Poly1305>>,
    /// Sealed bytes not opened yet: at most one segment and its tag.
    pending: Vec<u8>,
}

impl Opener {
    /// An opener for a stream sealed under `key` with `aad`.
    pub fn new(key: &[u8; 32], aad: &[u8]) -> Self {
        Self {
            key: *key,
            aad: aad.to_vec(),
            header: Vec::with_capacity(HEADER_BYTES),
            decryptor: None,
            pending: Vec::with_capacity(SEGMENT_BYTES + TAG_BYTES),
        }
    }

    /// Take `sealed`, and return the plaintext of the segments it completes.
    pub fn push(&mut self, mut sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.decryptor.is_none() {
            let take = (HEADER_BYTES - self.header.len()).min(sealed.len());
            self.header.extend_from_slice(&sealed[..take]);
            sealed = &sealed[take..];
            if self.header.len() < HEADER_BYTES {
                return Ok(Vec::new());
            }
            if self.header[0] != VERSION {
                return Err(CryptoError::new("stream of an unknown format"));
            }
            let mut derived = stream_key(&self.key, &self.header[1..]);
            self.decryptor = Some(DecryptorBE32::new(
                Key::from_slice(&derived),
                &Default::default(),
            ));
            derived.zeroize();
            self.key.zeroize();
        }
        let decryptor = self.decryptor.as_mut().expect("set above");
        let mut plain = Vec::new();
        while !sealed.is_empty() {
            if self.pending.len() == SEGMENT_BYTES + TAG_BYTES {
                let segment = decryptor
                    .decrypt_next(Payload {
                        msg: &self.pending,
                        aad: &self.aad,
                    })
                    .map_err(|_| CryptoError::new("stream open failed"))?;
                plain.extend_from_slice(&segment);
                self.pending.clear();
            }
            let take = (SEGMENT_BYTES + TAG_BYTES - self.pending.len()).min(sealed.len());
            self.pending.extend_from_slice(&sealed[..take]);
            sealed = &sealed[take..];
        }
        Ok(plain)
    }

    /// Open what is left as the last segment: the stream has ended.
    pub fn finish(mut self) -> Result<Vec<u8>, CryptoError> {
        let decryptor = self
            .decryptor
            .take()
            .ok_or_else(|| CryptoError::new("stream ended inside its header"))?;
        decryptor
            .decrypt_last(Payload {
                msg: &self.pending,
                aad: &self.aad,
            })
            .map_err(|_| CryptoError::new("stream open failed"))
    }
}

impl Drop for Opener {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];
    const AAD: &[u8] = b"comp.v1";

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    fn seal(plain: &[u8], piece: usize) -> Vec<u8> {
        let (mut sealer, mut sealed) = Sealer::new(&KEY, AAD);
        for p in plain.chunks(piece.max(1)) {
            sealed.extend(sealer.push(p).unwrap());
        }
        sealed.extend(sealer.finish().unwrap());
        sealed
    }

    fn open(
        sealed: &[u8],
        piece: usize,
        key: &[u8; 32],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut opener = Opener::new(key, aad);
        let mut plain = Vec::new();
        for p in sealed.chunks(piece.max(1)) {
            plain.extend(opener.push(p)?);
        }
        plain.extend(opener.finish()?);
        Ok(plain)
    }

    /// Every length around the segment size, sealed and opened in pieces that
    /// do not line up with segments, comes back whole at the length promised.
    #[test]
    fn every_length_round_trips_in_any_pieces() {
        for len in [
            0,
            1,
            SEGMENT_BYTES - 1,
            SEGMENT_BYTES,
            SEGMENT_BYTES + 1,
            3 * SEGMENT_BYTES,
            3 * SEGMENT_BYTES + 5,
        ] {
            let plain = pattern(len);
            for piece in [1usize, 7, 4096, SEGMENT_BYTES + 3, len + 1] {
                if piece == 1 && len > SEGMENT_BYTES + 1 {
                    continue;
                }
                let sealed = seal(&plain, piece);
                assert_eq!(sealed.len() as u64, sealed_len(len as u64), "len {len}");
                assert_eq!(open(&sealed, piece, &KEY, AAD).unwrap(), plain, "len {len}");
            }
        }
    }

    /// Every sealed length gives back the plaintext length it came from, and a
    /// length no stream has gives nothing.
    #[test]
    fn plain_len_inverts_sealed_len() {
        let seg = SEGMENT_BYTES as u64;
        for plain in [0, 1, seg - 1, seg, seg + 1, 5 * seg, 5 * seg + 7] {
            assert_eq!(plain_len(sealed_len(plain)), Some(plain), "plain {plain}");
        }
        let body = |n: u64| HEADER_BYTES as u64 + n;
        for sealed in [
            0,
            HEADER_BYTES as u64,
            body(15),
            body(seg + TAG_BYTES as u64 + 5),
        ] {
            assert_eq!(plain_len(sealed), None, "sealed {sealed}");
        }
    }

    #[test]
    fn the_same_plaintext_seals_differently_each_time() {
        let plain = pattern(1000);
        assert_ne!(seal(&plain, 1000), seal(&plain, 1000));
    }

    /// Cut at a segment boundary the remaining segments are all well formed,
    /// and only the last-segment flag says the stream did not end there.
    #[test]
    fn a_stream_cut_short_does_not_open() {
        let plain = pattern(3 * SEGMENT_BYTES + 5);
        let sealed = seal(&plain, 4096);
        let boundary = HEADER_BYTES + 2 * (SEGMENT_BYTES + TAG_BYTES);
        for cut in [boundary, boundary + 100, sealed.len() - 1, HEADER_BYTES, 10] {
            assert!(
                open(&sealed[..cut], 4096, &KEY, AAD).is_err(),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn a_dropped_or_reordered_segment_does_not_open() {
        let plain = pattern(3 * SEGMENT_BYTES + 5);
        let sealed = seal(&plain, 4096);
        let seg = SEGMENT_BYTES + TAG_BYTES;
        let at = |i: usize| HEADER_BYTES + i * seg..HEADER_BYTES + (i + 1) * seg;

        let mut dropped = sealed[..HEADER_BYTES].to_vec();
        dropped.extend_from_slice(&sealed[at(1)]);
        dropped.extend_from_slice(&sealed[at(2).start..]);
        assert!(open(&dropped, 4096, &KEY, AAD).is_err());

        let mut swapped = sealed[..HEADER_BYTES].to_vec();
        swapped.extend_from_slice(&sealed[at(1)]);
        swapped.extend_from_slice(&sealed[at(0)]);
        swapped.extend_from_slice(&sealed[at(2).start..]);
        assert!(open(&swapped, 4096, &KEY, AAD).is_err());
    }

    #[test]
    fn a_segment_from_another_stream_does_not_open() {
        let plain = pattern(2 * SEGMENT_BYTES + 5);
        let (a, b) = (seal(&plain, 4096), seal(&plain, 4096));
        let mut mixed = a[..HEADER_BYTES + SEGMENT_BYTES + TAG_BYTES].to_vec();
        mixed.extend_from_slice(&b[HEADER_BYTES + SEGMENT_BYTES + TAG_BYTES..]);
        assert!(open(&mixed, 4096, &KEY, AAD).is_err());
    }

    #[test]
    fn a_flipped_byte_or_another_context_does_not_open() {
        let plain = pattern(SEGMENT_BYTES + 5);
        let sealed = seal(&plain, 4096);
        for at in [0, 5, HEADER_BYTES + 3, sealed.len() - 1] {
            let mut bad = sealed.clone();
            bad[at] ^= 1;
            assert!(open(&bad, 4096, &KEY, AAD).is_err(), "flip at {at}");
        }
        assert!(open(&sealed, 4096, &KEY, b"comp.v2").is_err());
        assert!(open(&sealed, 4096, &[8; 32], AAD).is_err());
    }

    #[test]
    fn nothing_at_all_does_not_open() {
        assert!(open(&[], 1, &KEY, AAD).is_err());
    }
}
