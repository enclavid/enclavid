//! Top-level policy execution. [`Runner`] owns the wasmtime [`Engine`],
//! compiles components, and drives ONE pure-reducer round
//! (`enclavid:policy/policy.handle`) together with its plugin
//! composition through to a [`RunStatus`].
//!
//! No replay, no intercept, no compaction. The runner
//!   1. builds the inbound WIT `event` from the caller-supplied
//!      [`Event`] (the runtime's mailbox);
//!   2. calls `handle(state, event)` exactly once;
//!   3. performs the returned `action`: `render` persists the prompt as
//!      [`SessionState::current_prompt`] and yields `AwaitingInput`;
//!      `finish` yields `Completed`; `continue` (a durable checkpoint) is
//!      rejected loud — this engine does not implement it.
//!
//! ## Consent gate (security-critical)
//!
//! The disclosure → consumer seal is runtime-driven, NOT a policy host
//! call. When the inbound event is [`Event::ConsentDisclosure(true)`]
//! AND the session's `current_prompt` prompt was a
//! [`Prompt::ConsentDisclosure`], the runner fires the
//! [`SessionListener`] with exactly the fields the applicant saw and
//! accepted on the consent screen — "show == seal". On a `false` reply,
//! or any other event, NOTHING is sealed.

mod convert;
mod status;

use broker_client::{Event, Prompt, SessionState};
use wasm_runtime_composer::{
    Composable, ComposableComponent, ComposableDescriptor, ComposableLinker, Composer,
};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};

use crate::Host_ as GeneratedHost;
use crate::limits::POLICY_FUEL_BUDGET;
use crate::listener::{ConsentDisclosure, SessionChange};
use crate::state::{HostState, PluginHostState, RunInputs};

pub use status::RunStatus;

/// One compiled plugin component bundled with the WIT package id it
/// satisfies. The api crate constructs these from the client-supplied
/// `PluginPin` list at session start (pull → compile) and hands them to
/// [`Runner::run`]. `package` is the value the client passed in
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
        // Enable fuel accounting so per-Store budgets actually trap out
        // a runaway policy. Memory caps live on the Store via
        // `Store::limiter` — set up in `run` alongside the fuel budget.
        // Without both, a malicious policy could hang or OOM the enclave.
        config.consume_fuel(true);
        let engine = Engine::new(&config)?;
        Ok(Self { engine })
    }

    /// Compile a policy component from its binary (wasm or wat).
    pub fn compile(&self, bytes: &[u8]) -> wasmtime::Result<Component> {
        Component::new(&self.engine, bytes)
    }

    /// Drive one reducer round. `session` carries the policy's opaque
    /// `state` blob and the `current_prompt` prompt from the previous
    /// round; `event` is the inbound mailbox message the runtime built
    /// from the applicant's `/input`. `props` is the static consumer
    /// config the policy reads via `enclavid:policy/context.props`.
    ///
    /// Returns the next [`RunStatus`] and the updated [`SessionState`]
    /// (new opaque `state` + new `current_prompt`). The
    /// [`SessionListener`] is fired exactly once with the post-round
    /// state and — only on a consent-disclosure accept — the consented
    /// fields being sealed to the consumer.
    pub async fn run(
        &self,
        component: &Component,
        plugins: &[PluginInstance],
        session: SessionState,
        event: Event,
        props: Vec<(String, crate::Prop)>,
        inputs: RunInputs,
    ) -> wasmtime::Result<(RunStatus, SessionState)> {
        let embedded = inputs.embedded.clone();
        let listener = inputs.listener.clone();

        // CONSENT GATE — decide BEFORE calling the policy whether this
        // round seals a disclosure to the consumer. The seal fires iff
        // the applicant accepted a consent-disclosure prompt the runtime
        // had current_prompt; the sealed fields are EXACTLY what was on the
        // screen they accepted (show == seal). Computed here, off the
        // session's own record of what it last rendered — never trusting
        // a fresh policy-supplied list this round.
        let sealed_disclosure: Option<ConsentDisclosure> = match (&event, &session.current_prompt) {
            (Event::ConsentDisclosure(true), Some(Prompt::ConsentDisclosure(d))) => {
                Some(ConsentDisclosure {
                    fields: d.fields.clone(),
                })
            }
            _ => None,
        };

        // Compose every plugin into a single Composition: one Store +
        // inbox loop per plugin, slot-scoped embedded resolvers, and a
        // per-plugin fuel + memory cap.
        let mut plugin_composition = if plugins.is_empty() {
            None
        } else {
            let mut composer = Composer::new();
            for (idx, plugin) in plugins.iter().enumerate() {
                let engine_for_factory = self.engine.clone();
                // Slot 0 is the policy; plugins occupy slots 1..N in the
                // order they appear in `plugins`. The api crate populated
                // the `EmbeddedRegistry` in the same order, so slot
                // indices line up here without extra plumbing.
                let plugin_slot = idx + 1;
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
                                PluginHostState::new(),
                            );
                            store.limiter(|s: &mut PluginHostState| &mut s.limits);
                            store
                                .set_fuel(POLICY_FUEL_BUDGET)
                                .expect("fuel accounting enabled on the engine");
                            store
                        },
                    ),
                ));
            }
            Some(composer.compose().await.map_err(|e| {
                wasmtime::Error::msg(format!("wasm-runtime-composer compose plugins: {e}"))
            })?)
        };

        // Build the policy's Linker — a plain `wasmtime::component::Linker`
        // (no intercept shim): the reducer imports only pure read surfaces
        // (`context.props`, `enclavid:embedded/*`) plus whatever the
        // plugins export.
        let mut linker: Linker<HostState> = Linker::new(&self.engine);
        GeneratedHost::add_to_linker::<_, HasHost>(&mut linker, |s| s)?;

        // Plug each plugin-side export into the policy linker as an
        // import. `Composition::link_export` already routes to the
        // correct child composition's inbox channel.
        if let Some(plugin_composition) = plugin_composition.as_mut() {
            let exports = plugin_composition.ty().exports().clone();
            for export_name in exports {
                let mut ops = ComposableLinker::new(linker.root());
                Composable::link_export(plugin_composition, &export_name, &mut ops).map_err(
                    |e| {
                        wasmtime::Error::msg(format!(
                            "link plugin export `{export_name}` into policy linker: {e}",
                        ))
                    },
                )?;
            }
        }

        // Instantiate the policy and call `handle` ONCE.
        let mut store = Store::new(&self.engine, HostState::new(props, embedded.clone()));
        store.limiter(|s| &mut s.limits);
        store.set_fuel(POLICY_FUEL_BUDGET)?;
        let bindings = GeneratedHost::instantiate_async(&mut store, component, &linker).await?;

        let wit_event = convert::event_to_wit(event, &store.data().embedded)?;
        let (new_state, wit_action) = bindings
            .enclavid_policy_policy()
            .call_handle(&mut store, &session.state, &wit_event)
            .await?;

        // Perform the action and assemble the next session record.
        let embedded_for_convert = store.data().embedded.clone();
        let mut next_session = SessionState {
            policy_hash: session.policy_hash,
            state: new_state,
            current_prompt: None,
        };
        let status = match wit_action {
            crate::enclavid::policy::types::Action::Render(prompt) => {
                // Validate every embedded ref the prompt carries BEFORE
                // it is persisted/rendered — runtime-crafted or
                // cross-component refs trap here.
                let prompt = convert::prompt_to_domain(prompt, &embedded_for_convert)?;
                next_session.current_prompt = Some(prompt.clone());
                RunStatus::AwaitingInput(prompt)
            }
            crate::enclavid::policy::types::Action::Finish(decision) => {
                RunStatus::Completed(convert::decision_to_domain(decision))
            }
            crate::enclavid::policy::types::Action::Continue => {
                // Durable checkpoint (persist + re-invoke `handle`). This
                // engine does not implement it — fail loud rather than
                // silently no-op.
                drop(plugin_composition);
                return Err(wasmtime::Error::msg(
                    "the `continue` action (durable checkpoint) is not supported",
                ));
            }
        };

        // Single listener fire for the round: post-round state plus the
        // consented disclosure (only on a consent-disclosure accept).
        let disclosures: Vec<ConsentDisclosure> = sealed_disclosure.into_iter().collect();
        listener
            .on_session_change(SessionChange {
                state: &next_session,
                disclosures: &disclosures,
            })
            .await?;

        // Dropping the plugin composition closes its channels; its
        // per-plugin inbox loops observe the closed receiver and exit.
        drop(plugin_composition);

        Ok((status, next_session))
    }
}

/// Marker type bridging bindgen's `HasData` to `&mut HostState`. Host
/// traits are implemented directly on `HostState`, so the Data<'a> is
/// just a mutable reborrow.
struct HasHost;

impl wasmtime::component::HasData for HasHost {
    type Data<'a> = &'a mut HostState;
}
