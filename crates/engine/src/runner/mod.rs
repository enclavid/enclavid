//! Top-level policy execution. [`Runner`] owns the wasmtime [`Engine`],
//! compiles components, and drives ONE pure-reducer round
//! (`enclavid:policy/policy.handle`) through to a [`RunStatus`].
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

mod compose;
mod convert;
mod status;

use broker_client::{Event, Prompt, SessionState};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};

use crate::Host_ as GeneratedHost;
use crate::limits::{POLICY_FUEL_BUDGET, POLICY_MAX_STATE_BYTES};
use crate::listener::{ConsentDisclosure, SessionChange};
use crate::state::{HostState, RunInputs};

pub use status::RunStatus;

/// One plugin's component bytes bundled with the WIT package id it
/// satisfies. The api crate constructs these from the client-supplied
/// `PluginPin` list at session start (pull → bytes) and hands them to
/// [`Runner::compose`]. `package` is the value the client passed in
/// `PluginPin.package` (e.g. `"vendor:plugin@0.1.0"`); it identifies
/// which set of imports declared in the policy's WIT world this plugin
/// is meant to satisfy and names the plugin in the composition graph.
/// `wasm` is the raw component binary — fusion happens on bytes, so no
/// pre-compiled `Component` is kept.
pub struct PluginInstance {
    pub package: String,
    pub wasm: Vec<u8>,
}

/// The two applicant-facing embedded interfaces routed strictly
/// per-component (i18n and icons). DF stays merged, so it is not one of
/// these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddedIface {
    I18n,
    Icons,
}

impl EmbeddedIface {
    /// Slug segment used in the distinct import name, and the tag by
    /// which the host `Linker` picks the matching registry store.
    pub fn as_str(self) -> &'static str {
        match self {
            EmbeddedIface::I18n => "i18n",
            EmbeddedIface::Icons => "icons",
        }
    }
}

/// One distinct per-component embedded import produced by fusion. The
/// host `Linker` registers an instance named `instance_name` whose func
/// resolves keys against the catalog with `catalog_hash` — strict
/// per-component routing, so a plugin's i18n key never resolves to the
/// policy's (or another plugin's) translation. Emitted only for i18n /
/// icons; DF is merged and served first-match under its canonical name.
pub struct EmbeddedImport {
    pub instance_name: String,
    pub catalog_hash: [u8; 32],
    pub iface: EmbeddedIface,
}

/// A fused policy component plus the manifest of distinct embedded
/// imports its host `Linker` must register. Returned by
/// [`Runner::compose`]; the caller caches both and hands the manifest
/// back to [`Runner::run`].
pub struct Composition {
    pub component: Component,
    pub embedded_imports: Vec<EmbeddedImport>,
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

    /// Fuse a policy with its pinned plugins into ONE component and
    /// compile it. `wac-graph` single-store fusion (see
    /// [`compose::fuse`]) wires every plugin export into the policy's
    /// imports; the result runs in one wasmtime `Store`, so
    /// cross-component WIT resources are native handles. With no
    /// plugins this is just [`compile`](Self::compile) on the policy
    /// bytes.
    ///
    /// This is a build-time step: the caller compiles once per
    /// `(policy, plugin-set)` and reuses the returned [`Composition`]
    /// across every reducer round.
    ///
    /// With no plugins the policy is compiled as-is; its own
    /// `enclavid:embedded/*` imports stay canonical (merged) and the
    /// host serves them first-match — the manifest is empty. With
    /// plugins, [`compose::fuse`] routes each component's i18n / icons
    /// import to a distinct per-catalog import and returns them in the
    /// manifest for the host `Linker`.
    pub fn compose(
        &self,
        policy_wasm: &[u8],
        plugins: &[PluginInstance],
    ) -> wasmtime::Result<Composition> {
        if plugins.is_empty() {
            return Ok(Composition {
                component: self.compile(policy_wasm)?,
                embedded_imports: Vec::new(),
            });
        }
        let (fused, embedded_imports) = compose::fuse(policy_wasm, plugins)?;
        Ok(Composition {
            component: Component::new(&self.engine, &fused)?,
            embedded_imports,
        })
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
        embedded_imports: &[EmbeddedImport],
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

        // `component` is the already-fused policy (+plugins) from
        // `Runner::compose`. Build the host `Linker` for the imports that
        // bubbled up out of fusion. bindgen wires the CANONICAL-named
        // imports on `HostState`: `context.props`, the merged
        // `enclavid:embedded/disclosure-fields` (first-match, option B),
        // and the canonical `enclavid:embedded/{i18n,icons}` (used only
        // by a lone unfused policy — a fused component routes those
        // away, so the canonical registrations sit unused, which is
        // harmless). Plugin↔policy interfaces are internal to the fused
        // component, so the Linker never sees them.
        let mut linker: Linker<HostState> = Linker::new(&self.engine);
        GeneratedHost::add_to_linker::<_, HasHost>(&mut linker, |s| s)?;
        // Then the DISTINCT per-catalog i18n/icons instances the fusion
        // produced (`embedded-slot:<hash>/<iface>`), each resolving
        // strictly against its own catalog — bindgen can't emit these
        // dynamic names.
        register_strict_embedded(&mut linker, embedded_imports, &embedded)?;

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

        // Data-minimization backstop: the policy's opaque blob must stay
        // under POLICY_MAX_STATE_BYTES so raw media clips can't be
        // smuggled into the sealed mailbox and the ciphertext-size covert
        // channel stays narrow. A breach traps the round.
        if new_state.len() > POLICY_MAX_STATE_BYTES {
            return Err(wasmtime::Error::msg(format!(
                "policy returned a {}-byte state blob, over the \
                 {POLICY_MAX_STATE_BYTES}-byte POLICY_MAX_STATE_BYTES cap",
                new_state.len(),
            )));
        }

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

        Ok((status, next_session))
    }
}

/// Register the distinct per-catalog i18n / icons instances the fusion
/// produced. Each [`EmbeddedImport`] names one composite import
/// (`embedded-slot:<hash>/<iface>`) whose single func resolves keys
/// STRICTLY against the one catalog identified by `catalog_hash` — a
/// plugin's i18n key can never resolve to the policy's translation.
/// Instance names are unique per `(hash, iface)` (fusion dedups), so
/// no double-registration; the canonical `enclavid:embedded/*` names
/// bindgen registered are disjoint from these.
fn register_strict_embedded(
    linker: &mut Linker<HostState>,
    imports: &[EmbeddedImport],
    embedded: &std::sync::Arc<crate::embedded::EmbeddedRegistry>,
) -> wasmtime::Result<()> {
    for imp in imports {
        let hash = imp.catalog_hash;
        let iface = imp.iface;
        let embedded = embedded.clone();
        // WIT func name inside the interface (unchanged by routing —
        // only the instance's outer import name is renamed).
        let func = match iface {
            EmbeddedIface::I18n => "localized",
            EmbeddedIface::Icons => "icon",
        };
        linker.root().instance(&imp.instance_name)?.func_wrap_async(
            func,
            move |_store, (key,): (String,)| {
                let embedded = embedded.clone();
                Box::new(async move {
                    let token = match iface {
                        EmbeddedIface::I18n => {
                            crate::embedded::strict_token(&embedded.localized, &hash, &key)?
                        }
                        EmbeddedIface::Icons => {
                            crate::embedded::strict_token(&embedded.icons, &hash, &key)?
                        }
                    };
                    Ok((token,))
                })
            },
        )?;
    }
    Ok(())
}

/// Marker type bridging bindgen's `HasData` to `&mut HostState`. Host
/// traits are implemented directly on `HostState`, so the Data<'a> is
/// just a mutable reborrow.
struct HasHost;

impl wasmtime::component::HasData for HasHost {
    type Data<'a> = &'a mut HostState;
}
