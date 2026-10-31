//! Native inference: a vendor's own ONNX graph, run by the host in a process
//! of its own beside the round.
//!
//! [`graph::check`] reads a vendor's graph and the data file its weights lie
//! in, refuses what could reach past computation, and readies the graph for
//! ONNX Runtime — every weight in the data file made a graph input, fed a view
//! of the mapped file. [`protocol`] is what a round and the coprocess that runs
//! its model say to each other. Neither needs ONNX Runtime: the coprocess links
//! it, and a compile, a round and a check by hand read graphs and messages
//! without it.
//!
//! ```text
//! graph     ← a vendor's graph, checked, its weights made inputs
//! onnx      ← the part of ONNX's schema the check reads
//! wire      ← protobuf fields as they lie, for the splice that readies a graph
//! protocol  ← a round's requests to its model's coprocess, and the answers
//! ```

#[cfg(feature = "test-models")]
pub mod fixture;
pub mod graph;
mod onnx;
pub mod protocol;
mod wire;
