//! Policy execution: run a session through the policy wasm.
//!
//! `EvalArgs` is re-exported from bindgen for callers constructing the
//! typed args passed to `policy.evaluate`.

use enclavid_host_bridge::{SessionState, suspended};
use wasmtime::component::Component;
use wasmtime::{Config, Engine, Store};

use crate::host_state::{HostResources, HostState};
use crate::wasmtime_shim::component::{InterceptView, Linker};
use crate::Host_ as GeneratedHost;

pub use crate::exports::enclavid::policy::policy::{Decision, EvalArgs};
pub use crate::host_state::HostResources as RunResources;

/// Status of a policy session run.
pub enum RunStatus {
    /// Policy completed with a decision.
    Completed(Decision),
    /// Policy suspended, awaiting user input for the carried request.
    Suspended(suspended::Request),
}

/// Runs policy WASM against session state.
pub struct Runner {
    engine: Engine,
}

impl Runner {
    pub fn new() -> wasmtime::Result<Self> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        let engine = Engine::new(&config)?;
        Ok(Self { engine })
    }

    /// Compile a policy component from its binary (wasm or wat).
    pub fn compile(&self, bytes: &[u8]) -> wasmtime::Result<Component> {
        Component::new(&self.engine, bytes)
    }

    /// Run or resume a policy: replay existing events, execute to next
    /// suspend or completion. Host fibers returning
    /// `Err(suspended::Request)` propagate as wasmtime traps. We
    /// distinguish our suspend trap from a real bug trap by checking
    /// for a Suspended event at the tail of the log.
    ///
    /// Side effects (state mutations + disclosure entries) are
    /// published per host call via `RunResources::listener` — see
    /// `SessionListener`. The returned `SessionState` mirrors what the
    /// listener last acknowledged; engine itself doesn't write
    /// anywhere.
    pub async fn run(
        &self,
        component: &Component,
        session: SessionState,
        args: Vec<(String, EvalArgs)>,
        resources: HostResources,
    ) -> wasmtime::Result<(RunStatus, SessionState)> {
        let mut linker: Linker<HostState> = Linker::new(&self.engine, |s| InterceptView {
            replay: &mut s.replay,
            disclosures: &mut s.pending_disclosures,
            listener: &s.listener,
        });
        GeneratedHost::add_to_linker::<_, HasHost>(&mut linker, |s| s)?;

        let mut store = Store::new(&self.engine, HostState::new(session, resources));
        let bindings = GeneratedHost::instantiate_async(&mut store, component, &linker).await?;

        let result = bindings
            .enclavid_policy_policy()
            .call_evaluate(&mut store, &args)
            .await;

        let data = store.into_data();
        let status = match result {
            Ok(decision) => RunStatus::Completed(decision),
            Err(e) => match data.replay.pending().cloned() {
                Some(req) => RunStatus::Suspended(req),
                None => return Err(e),
            },
        };
        Ok((status, data.into_session()))
    }
}

/// Marker type bridging bindgen's `HasData` to `&mut HostState`. Host traits
/// are implemented directly on `HostState`, so the Data<'a> is just a
/// mutable reborrow.
struct HasHost;

impl wasmtime::component::HasData for HasHost {
    type Data<'a> = &'a mut HostState;
}
