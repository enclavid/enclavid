//! `engine-types` — the leaf domain types shared across the compile and
//! execute halves of the engine fleet.
//!
//! **No wasmtime, no cranelift.** These types straddle the
//! compiler/executor boundary: `PluginInstance` is a compiler input;
//! [`composition::EmbeddedImport`] and [`embedded::ComponentDecls`] are
//! compiler-produced and executor-consumed; [`embedded::EmbeddedRegistry`]
//! is the executor's (and the api view layer's) ref→data projection. They
//! are plain data (serde + `std` collections), so the client-only
//! orchestrator can hold and project them without pulling the wasmtime
//! runtime, and the `engine-rpc` contract can name them without
//! taking a runtime dependency. That wasmtime-freedom is load-bearing —
//! see the fleet crate map.
//!
//! The wasmtime-coupled pieces stay in the engine crates: the section
//! parsers (`load_embedded`) + fusion + the `Compiler` live in
//! `engine-compiler`; the bindgen ref resource reps (`LocalizedRef` /
//! `IconRef` / `DisclosureFieldRef`) + the `Executor` live in
//! `engine-executor`. Each re-exports the types here it needs at
//! ergonomic paths.

pub mod composition;
pub mod embedded;
pub mod limits;
pub mod sanitize;
