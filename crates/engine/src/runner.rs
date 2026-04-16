use crate::suspend::MediaRequest;
use enclavid_session_store::SessionState;

/// Outcome of running a policy session.
pub enum RunOutcome {
    /// Policy completed, returned a decision.
    // TODO: Decision type from policy WIT
    Completed,
    /// Policy suspended, needs media from user.
    Suspended(MediaRequest),
}

/// Runs policy WASM against session state.
pub struct Runner {
    engine: wasmtime::Engine,
}

impl Runner {
    pub fn new() -> wasmtime::Result<Self> {
        let engine = wasmtime::Engine::default();
        Ok(Self { engine })
    }

    /// Run or resume a session. Returns outcome.
    pub fn run(&self, state: &mut SessionState) -> wasmtime::Result<RunOutcome> {
        // TODO: load policy WASM, instantiate, link host functions, call evaluate
        // For now: simulate the suspend/resume flow

        if state.passport.is_none() {
            return Ok(RunOutcome::Suspended(MediaRequest::Passport));
        }

        if state.liveness_frames.is_empty() {
            return Ok(RunOutcome::Suspended(MediaRequest::Liveness));
        }

        Ok(RunOutcome::Completed)
    }
}
