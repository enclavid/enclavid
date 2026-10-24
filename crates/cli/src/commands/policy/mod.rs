//! `enclavid policy ...` — **authoring** of policy artifacts: embed
//! the policy's catalogs (its texts and its disclosure fields) and
//! validate them. Registry push lives in the role-
//! agnostic `oci` group (a policy and a plugin are the same wasm
//! component on the wire). `embed` additionally asserts the component
//! exports the `enclavid:policy/policy` world — a plugin handed here
//! is rejected with a pointer to `enclavid plugin embed`.

pub mod embed;
pub mod validate;
