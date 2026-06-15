//! Hybrid public-key sealing to an `age` recipient. Used for outbound
//! data the host stores opaquely but a downstream consumer (platform
//! operator, client of the platform) reads — disclosure entries
//! (`client_disclosure_pubkey`) and applicant reports
//! (`platform_pubkey`).
//!
//! Symmetric counterpart to [`stores::session::aead`] but for
//! asymmetric recipients: the TEE doesn't hold the private key, only
//! the consumer does. Identical wire format to what stock `age`
//! produces, so consumers decrypt with the canonical `age` CLI / SDK.
//!
//! Failure modes (malformed recipient, IO during stream wrap) collapse
//! to `BridgeError::Transport`. Callers treat sealing failures as 5xx
//! infra errors — there is no domain meaning to a failed seal.

use std::io::Write;
use std::str::FromStr;

use age::x25519::Recipient;

use crate::error::BridgeError;

/// Seal `plaintext` to the canonical age recipient encoded in
/// `recipient` (form: `age1...`). Returns the binary age envelope:
/// header + encrypted stream + auth tag, ready to hand to a host
/// store.
pub fn seal_to_recipient(plaintext: &[u8], recipient: &str) -> Result<Vec<u8>, BridgeError> {
    let recipient = Recipient::from_str(recipient)
        .map_err(|e| BridgeError::Transport(format!("invalid age recipient: {e}")))?;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .map_err(|e| BridgeError::Transport(format!("age encryptor: {e}")))?;
    let mut out = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut out)
        .map_err(|e| BridgeError::Transport(format!("age wrap_output: {e}")))?;
    writer
        .write_all(plaintext)
        .map_err(|e| BridgeError::Transport(format!("age write: {e}")))?;
    writer
        .finish()
        .map_err(|e| BridgeError::Transport(format!("age finish: {e}")))?;
    Ok(out)
}
