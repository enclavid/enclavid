//! `enclavid policy ...` — OCI artifact operations on policy
//! bundles: keygen, embed, encrypt, push, validate. Registry-
//! agnostic by design — works against any OCI registry, not just the
//! Enclavid one. Credentials come from the standard docker config
//! chain (see `crates/cli/src/registry_auth.rs`).

pub mod embed;
pub mod encrypt;
pub mod keygen;
pub mod push;
pub mod validate;
