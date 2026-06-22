//! Encryption primitives for Enclavid.
//!
//! - [`aead`] — symmetric AEAD (ChaCha20-Poly1305) for session blobs the
//!   TEE reads back, sealed under TEE-held keys (`tee_seal_key`,
//!   `applicant_session_token`); AAD binds a ciphertext to its session.
//! - [`age_seal`] — hybrid public-key sealing to an `age` recipient, for
//!   blobs a downstream consumer reads (the TEE holds no private key).
//! - [`ocicrypt`] — faithful ocicrypt layer encryption
//!   (`AES_256_CTR_HMAC_SHA256`) for encrypted-OCI policy/plugin
//!   artifacts; encrypt (CLI) + decrypt (TEE) as a tested pair.
//!
//! Leaf crate: no enclavid dependencies. Every function takes raw key /
//! recipient material + bytes (+ AAD); callers own key management and
//! map [`CryptoError`] into their own error type. Future home of the
//! COSE envelope work — see the COSE/CBOR roadmap.

mod error;

pub mod aead;
pub mod age_seal;
pub mod kbswrap;
pub mod ocicrypt;

pub use age_seal::seal_to_recipient;
pub use error::CryptoError;
