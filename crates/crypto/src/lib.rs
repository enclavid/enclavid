//! Encryption primitives for Enclavid.
//!
//! - [`aead`] — symmetric AEAD (ChaCha20-Poly1305) for session blobs the
//!   TEE reads back, sealed under TEE-held keys (`tee_seal_key`,
//!   `applicant_session_token`); AAD binds a ciphertext to its session.
//! - [`sealed_box`] — anonymous public-key sealing (libsodium `crypto_box_seal`)
//!   to a consumer's X25519 key, for blobs a downstream consumer reads. The
//!   sender's keypair is ephemeral, so the TEE cannot reopen what it sealed.
//! - [`ocicrypt`] — faithful ocicrypt layer encryption
//!   (`AES_256_CTR_HMAC_SHA256`) for encrypted-OCI policy/plugin
//!   artifacts; encrypt (CLI) + decrypt (TEE) as a tested pair. The layer
//!   key reaches the TEE inline or via a standard Trustee KBS resource
//!   (see `enclavid-kbs-client`) — no bespoke key-wrap lives here.
//!
//! Leaf crate: no enclavid dependencies. Every function takes raw key /
//! recipient material + bytes (+ AAD); callers own key management and
//! map [`CryptoError`] into their own error type.

mod error;

pub mod aead;
pub mod kdf;
pub mod ocicrypt;
pub mod sealed_box;
pub mod secret_bytes;

pub use error::CryptoError;
pub use kdf::derive_key;
pub use sealed_box::{generate_recipient, open_sealed, public_from_secret, seal_to_recipient};
pub use secret_bytes::SecretBytes;
