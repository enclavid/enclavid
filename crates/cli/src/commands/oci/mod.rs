//! `enclavid oci ...` — registry operations on Enclavid artifacts.
//!
//! Role-agnostic by design: a policy and a plugin are the same kind of
//! thing on the wire — a plaintext wasm component shipped as a single
//! `application/wasm` OCI layer, integrity-pinned by digest (the TEE
//! re-verifies the layer digest on pull). So push/pull live here, once,
//! rather than duplicated per role. The role-specific authoring
//! (`embed` / `validate`, where `policy` carries the disclosure-fields
//! section and `plugin` does not) stays under `policy` / `plugin`.
//!
//! Registry-agnostic: works against any OCI registry; credentials come
//! from the standard docker config chain (see `registry_auth.rs`).

pub mod push;
