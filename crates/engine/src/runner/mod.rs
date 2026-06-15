//! Top-level policy execution. [`Runner`] owns the wasmtime
//! [`Engine`], compiles components, and drives one policy run
//! together with its plugin composition through to a [`RunStatus`].

mod status;

use broker_client::SessionState;
use wasm_runtime_composer::{
    Composable, ComposableComponent, ComposableDescriptor, ComposableLinker, Composer,
};
use wasmtime::component::Component;
use wasmtime::{Config, Engine, Store};

use crate::Host_ as GeneratedHost;
use crate::intercept::shim::component::{InterceptView, Linker};
use crate::limits::POLICY_FUEL_BUDGET;
use crate::state::{HostState, PluginHostState, RunInputs};

pub use status::{Decision, EvalArgs, RunStatus};

/// One compiled plugin component bundled with the WIT package id it
/// satisfies. The api crate constructs these from the client-supplied
/// `PluginPin` list at session start (pull → compile) and hands them
/// to [`Runner::run`]. `package` is the value the client passed in
/// `PluginPin.package` (e.g. `"vendor:plugin@0.1.0"`); it identifies
/// which set of imports declared in the policy's WIT world this plugin
/// is meant to satisfy and serves as the descriptor id when the engine
/// hands the plugin to wasm-runtime-composer.
pub struct PluginInstance {
    pub package: String,
    pub component: std::sync::Arc<Component>,
}

/// Runs policy WASM against session state.
pub struct Runner {
    engine: Engine,
}

impl Runner {
    pub fn new() -> wasmtime::Result<Self> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        // Enable fuel accounting so per-Store budgets actually trap
        // out a runaway policy. Memory caps live on the Store via
        // `Store::limiter` — set up in `run` alongside the fuel
        // budget. Without both, a malicious policy could hang or OOM
        // the enclave.
        config.consume_fuel(true);
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
    /// published per host call via `RunInputs::listener` — see
    /// [`crate::SessionListener`]. The returned `SessionState` mirrors
    /// what the listener last acknowledged; engine itself doesn't
    /// write anywhere.
    pub async fn run(
        &self,
        component: &Component,
        plugins: &[PluginInstance],
        session: SessionState,
        args: Vec<(String, EvalArgs)>,
        inputs: RunInputs,
    ) -> wasmtime::Result<(RunStatus, SessionState)> {
        // The composition-wide embedded-ref registry is constructed
        // **outside** the engine — in `api::applicant::shared::
        // lookup_policy`, alongside the localized-text registry, so
        // the same `Arc` can feed both consumers without re-walking
        // the wasm sections (engine for slot-bound resolve + use-site
        // reverse-lookup; api views for resolving slot-tagged refs to
        // user-facing strings). Builder discipline (slot 0 = policy,
        // slots 1..N = plugins in the same order as `plugins` here)
        // lives at the construction site; we just consume.
        let embedded = inputs.embedded.clone();

        // Phase 1 — compose every plugin into a single Composition.
        //
        // wasm-runtime-composer:
        //   * spawns one Store + inbox loop per plugin descriptor;
        //   * resolves the full plugin↔plugin graph (topological order,
        //     interface-name matching);
        //   * the resulting Composition implements `Composable`, so
        //     calling its `link_export(name, ops)` routes through the
        //     internal resolver to the correct plugin's inbox channel.
        //
        // Held in an `Option` so the no-plugins path is allocation-free
        // and never touches the composer. Plugin inbox loops live for
        // the duration of this composition handle — we drop it after
        // evaluate returns, which closes their channels and lets the
        // tasks exit cleanly.
        let mut plugin_composition = if plugins.is_empty() {
            None
        } else {
            let mut composer = Composer::new();
            for (idx, plugin) in plugins.iter().enumerate() {
                let engine_for_factory = self.engine.clone();
                let embedded_for_factory = embedded.clone();
                // Slot 0 is the policy; plugins occupy slots 1..N in
                // the order they appear in `plugins`. The api crate
                // populated the `EmbeddedRegistry` in the same order
                // when building the composition (see
                // `lookup_policy`), so slot indices line up here
                // without extra plumbing.
                let plugin_slot = idx + 1;
                // Plugin's Linker is restricted to the three pure
                // scoped-lookup interfaces (`enclavid:embedded/
                // disclosure-fields`, `enclavid:embedded/i18n`,
                // `enclavid:embedded/icons`) — no WASI, no suspending
                // `enclavid:*`, nothing else. `register_for_slot`
                // captures `plugin_slot` in the closure for each
                // interface, so the only refs the plugin can issue
                // are for keys it declared in its own embedded
                // sections; foreign-slot refs trap inside
                // `get_token`. Composer fails loud at compose-time
                // if a plugin declares any other unsatisfied import.
                let mut plugin_linker =
                    wasmtime::component::Linker::<PluginHostState>::new(&self.engine);
                crate::embedded::register_for_slot(
                    &mut plugin_linker,
                    plugin_slot,
                    embedded.clone(),
                )?;
                composer.add(ComposableDescriptor::new(
                    &plugin.package,
                    ComposableComponent::new(
                        (*plugin.component).clone(),
                        plugin_linker,
                        move || {
                            let mut store = Store::new(
                                &engine_for_factory,
                                PluginHostState::new(embedded_for_factory.clone()),
                            );
                            // Same memory ceiling enforcement we do
                            // for the policy Store — `StoreLimits` on
                            // the `T` itself, surfaced via
                            // `Store::limiter`. Without this the cap
                            // we set up in `PluginHostState::new` is
                            // dead weight; wasmtime only consults it
                            // when we explicitly hand it the closure.
                            store.limiter(|s: &mut PluginHostState| &mut s.limits);
                            store
                        },
                    ),
                ));
            }
            Some(composer.compose().await.map_err(|e| {
                wasmtime::Error::msg(format!("wasm-runtime-composer compose plugins: {e}"))
            })?)
        };

        // Phase 2 — build policy's Linker through our shim (so the
        // intercept/replay layer wraps every typed host call wired in
        // by `bindgen!`'s `add_to_linker`).
        let mut linker: Linker<HostState> = Linker::new(&self.engine, |s| InterceptView {
            replay: &mut s.replay,
            disclosures: &mut s.pending_disclosures,
            listener: &s.listener,
        });
        GeneratedHost::add_to_linker::<_, HasHost>(&mut linker, |s| s)?;

        // Plug each plugin-side export into the policy linker as an
        // import. `Composition::link_export(name, ops)` already routes
        // to the correct child composition's inbox channel, so we
        // don't need to know which plugin provides which interface —
        // composer resolved that during `compose()` above. `ops` is a
        // `ComposableLinker` wrapping the native `LinkerInstance`
        // we expose from the shim via `inner_mut().root()`.
        //
        // Iterating over *all* of the plugin composition's exports
        // (rather than the policy's imports) is the simpler half of
        // the symmetry — `wasmtime` ignores Linker entries the
        // instantiated component never imports, and missing imports
        // trap loud at `instantiate_async` with a clear "missing
        // import" message. No extra validation pass needed.
        if let Some(plugin_composition) = plugin_composition.as_mut() {
            let exports = plugin_composition.ty().exports().clone();
            for export_name in exports {
                let mut ops = ComposableLinker::new(linker.inner_mut().root());
                // Disambiguate from the private inherent `link_export`
                // on `Composition` — the trait method (public via
                // `Composable`) is what does the routing through the
                // composer-resolved child map.
                Composable::link_export(plugin_composition, &export_name, &mut ops).map_err(|e| {
                    wasmtime::Error::msg(format!(
                        "link plugin export `{export_name}` into policy linker: {e}",
                    ))
                })?;
            }
        }

        // Phase 3 — instantiate policy ourselves and drive evaluate
        // through the bindgen-typed call. Composer is invisible from
        // here — plugin calls look like normal host imports from the
        // policy's perspective, and route through composer's channel
        // machinery under the hood.
        let mut store = Store::new(&self.engine, HostState::new(session, inputs));
        store.limiter(|s| &mut s.limits);
        store.set_fuel(POLICY_FUEL_BUDGET)?;
        let bindings = GeneratedHost::instantiate_async(&mut store, component, &linker).await?;
        let result = bindings
            .enclavid_policy_policy()
            .call_evaluate(&mut store, &args)
            .await;

        // State extraction is unchanged — policy's Store is ours.
        let data = store.into_data();
        let status = match result {
            Ok(decision) => RunStatus::Completed(decision),
            Err(e) => match data.replay.pending().cloned() {
                Some(req) => RunStatus::Suspended(req),
                None => return Err(e),
            },
        };

        // Dropping the plugin composition closes its channels; its
        // per-plugin inbox loops observe the closed receiver and exit.
        drop(plugin_composition);

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
