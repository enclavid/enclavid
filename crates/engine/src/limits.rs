//! Engine-side resource and validation limits — re-exported from the
//! [`engine_types::limits`] leaf.
//!
//! These caps are compile-time constants by design: together they form the
//! engine's slice of the TEE trust contract (a consumer attesting an
//! enclave hash is implicitly attesting these values too). Loading any of
//! them from env / config / runtime input would open covert host→policy
//! channels, enable per-session selective DoS, and break the
//! "PCR = behavior" attestation contract. They live in the `engine-types`
//! leaf so the wasmtime-free halves of the fleet (the api orchestrator,
//! the rpc contract) can reference the same trust contract without pulling
//! the runtime; the rationale for each constant lives with its definition
//! there. Engine code keeps using `crate::limits::*`.
//!
//! For HTTP / multipart / external-input size caps see the api crate's
//! `limits` module — same review discipline, but those live at the IO
//! boundary and are reviewed alongside the HTTP routes that enforce them.

pub use engine_types::limits::*;
