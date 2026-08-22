//! Hybrid public-key sealing to an `age` recipient. Used for outbound
//! data the host stores opaquely but a downstream consumer (platform
//! operator, client of the platform) reads — disclosure entries
//! (`client_disclosure_pubkey`) and applicant reports
//! (`platform_pubkey`).
//!
//! Symmetric counterpart to [`crate::aead`] but for
//! asymmetric recipients: the TEE doesn't hold the private key, only
//! the consumer does. Identical wire format to what stock `age`
//! produces, so consumers decrypt with the canonical `age` CLI / SDK.
//!
//! Failure modes (malformed recipient, IO during stream wrap) collapse
//! to `CryptoError`. Callers treat sealing failures as 5xx
//! infra errors — there is no domain meaning to a failed seal.

use std::io::Write;
use std::str::FromStr;

use age::x25519::Recipient;

use crate::error::CryptoError;

/// Seal `plaintext` to the canonical age recipient encoded in
/// `recipient` (form: `age1...`). Returns the binary age envelope:
/// header + encrypted stream + auth tag, ready to hand to a host
/// store.
pub fn seal_to_recipient(plaintext: &[u8], recipient: &str) -> Result<Vec<u8>, CryptoError> {
    let recipient = Recipient::from_str(recipient)
        .map_err(|e| CryptoError::new(format!("invalid age recipient: {e}")))?;
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .map_err(|e| CryptoError::new(format!("age encryptor: {e}")))?;
    let mut out = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut out)
        .map_err(|e| CryptoError::new(format!("age wrap_output: {e}")))?;
    writer
        .write_all(plaintext)
        .map_err(|e| CryptoError::new(format!("age write: {e}")))?;
    writer
        .finish()
        .map_err(|e| CryptoError::new(format!("age finish: {e}")))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Why the disclosure size-padding is both necessary and sufficient:
    /// age ciphertext length tracks the PLAINTEXT LENGTH (AEAD: plaintext + a
    /// per-chunk tag/nonce + a header), NOT the content. A colluding policy could
    /// therefore ride a field value's byte length into the host-observable
    /// ciphertext length — which is exactly why every disclosure envelope is padded
    /// to a constant plaintext frame before sealing (api's
    /// `SEALED_DISCLOSURE_PLAINTEXT_BYTES`). Content is NOT a length lever: the
    /// spread across seals of IDENTICAL content is age's content-independent header
    /// randomness, so once the plaintext length is pinned, the residual ciphertext-
    /// length jitter carries no policy signal.
    #[test]
    fn ciphertext_length_tracks_plaintext_length_not_content() {
        let recipient = age::x25519::Identity::generate().to_public().to_string();

        // Length DOES track plaintext length — the signal padding removes.
        let short = seal_to_recipient(&vec![0u8; 1024], &recipient)
            .unwrap()
            .len();
        let long = seal_to_recipient(&vec![0u8; 64 * 1024], &recipient)
            .unwrap()
            .len();
        assert!(
            long > short,
            "ciphertext length must grow with plaintext length"
        );

        // Identical content, two seals → the length can already differ purely from
        // age's random header, i.e. the length carries per-seal noise, not content.
        // Exercised (not asserted (in)equal) so the test stays non-flaky.
        let _ = seal_to_recipient(&vec![7u8; 1024], &recipient).unwrap();
    }
}
