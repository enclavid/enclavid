//! Policy → host text-channel hardening. The implementation lives in the
//! wasmtime-free [`engine_types::sanitize`] leaf so the client-only orchestrator
//! (api view layer) applies the SAME stripping to manifest translation values
//! without pulling the runtime. Re-exported here so engine-internal call sites
//! (`runner::convert`) and the `engine_executor::sanitize_text_value` re-export
//! keep their existing paths.

pub use engine_types::sanitize::*;
