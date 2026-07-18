//! The EXECUTE boundary: drive ONE reducer round of a compiled policy against
//! the decrypted session state + event, behind an [`Executor`] trait so the
//! run can move OUT of process (an execution-worker CVM) later.
//!
//! [`LocalExecutor`] runs the round in-process on the shared [`Runner`] today.
//! A future `RemoteExecutor` implements the same trait over a transport.
//!
//! Unlike the compile boundary, a round makes MID-CALL callbacks through
//! [`RunInputs`]: the [`SessionListener`](enclavid_engine::SessionListener)
//! seals + persists state / disclosures, and the
//! [`MediaStore`](enclavid_engine::MediaStore) unseals stored blobs. Those hold
//! the seal key / applicant token / broker connection and STAY orchestrator-
//! side — so a remote executor's `inputs` become IPC proxies back to the
//! orchestrator (Phase 3), which services the callbacks. The key never moves
//! into the executor; only the round's already-decrypted `session`/`event` and
//! the (non-secret) compiled `component` cross the boundary.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use enclavid_engine::{
    Component, EmbeddedImport, Event, Prop, RunInputs, RunStatus, Runner, SessionState,
};

/// The result of one reducer round: next [`RunStatus`] + updated
/// [`SessionState`]. Boxed as a `wasmtime::Result` because the run originates in
/// the engine and any failure surfaces as an anyhow chain the caller classifies.
type RunOutput = enclavid_engine::RunResult<(RunStatus, SessionState)>;

/// The EXECUTE boundary. Given the compiled `component` + the round's decrypted
/// `session`/`event`/`props` and the orchestrator-held `inputs` (listener +
/// media-store + embedded registry), drive one `handle` round. Object-safe
/// boxed-future (mirrors [`MediaStore`](enclavid_engine::MediaStore)) so the
/// impl can be swapped for an out-of-process `RemoteExecutor` behind an
/// `Arc<dyn Executor>`.
pub trait Executor: Send + Sync {
    fn execute<'a>(
        &'a self,
        component: &'a Component,
        embedded_imports: &'a [EmbeddedImport],
        session: SessionState,
        event: Event,
        props: Vec<(String, Prop)>,
        inputs: RunInputs,
    ) -> Pin<Box<dyn Future<Output = RunOutput> + Send + 'a>>;
}

/// In-process executor: runs the round on the shared process [`Runner`]. A
/// later `RemoteExecutor` deserializes the cwasm into its own engine, runs the
/// round in an execution-worker CVM, and proxies the `inputs` callbacks back to
/// the orchestrator over a transport.
pub struct LocalExecutor {
    runner: Arc<Runner>,
}

impl LocalExecutor {
    pub fn new(runner: Arc<Runner>) -> Self {
        Self { runner }
    }
}

impl Executor for LocalExecutor {
    fn execute<'a>(
        &'a self,
        component: &'a Component,
        embedded_imports: &'a [EmbeddedImport],
        session: SessionState,
        event: Event,
        props: Vec<(String, Prop)>,
        inputs: RunInputs,
    ) -> Pin<Box<dyn Future<Output = RunOutput> + Send + 'a>> {
        Box::pin(
            self.runner
                .run(component, embedded_imports, session, event, props, inputs),
        )
    }
}
