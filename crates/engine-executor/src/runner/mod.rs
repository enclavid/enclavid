//! Top-level policy execution. [`Executor`] owns the RUNTIME wasmtime
//! [`Engine`], deserializes a compiled `cwasm`, and drives ONE pure-reducer
//! round (`enclavid:policy/policy.handle`) through to a [`RunStatus`]. It
//! carries no Cranelift — codegen (fuse + `Component::new`) is
//! engine-compiler's job; this crate only ever `deserialize`s + runs.
//!
//! No replay, no intercept, no compaction. The executor
//!   1. builds the inbound WIT `event` from the caller-supplied
//!      [`Event`] (the runtime's mailbox);
//!   2. calls `handle(state, event)` exactly once;
//!   3. performs the returned `action`: `render` persists the prompt as
//!      [`SessionState::current_prompt`] and yields `AwaitingInput`;
//!      `finish` yields `Completed`. (The sealed-state size covert channel is
//!      closed at the seal boundary in broker-client — `SetState`'s Covert
//!      vouch pads the encoded `SessionState` to a constant — not here.)
//!
//! ## Consent gate (security-critical)
//!
//! The disclosure → consumer seal is runtime-driven, NOT a policy host
//! call. When the inbound event is [`Event::ConsentDisclosure(true)`]
//! AND the session's `current_prompt` prompt was a
//! [`Prompt::ConsentDisclosure`], the executor fires the
//! `SessionListener` with exactly the fields the applicant saw and
//! accepted on the consent screen — "show == seal". On a `false` reply,
//! or any other event, NOTHING is sealed.

mod convert;
mod status;

use broker_client::{Event, Prompt, SessionState};
use wasmtime::component::{Component, Linker, Resource};
use wasmtime::{Config, Engine, Store};

use crate::Host_ as GeneratedHost;
use crate::embedded::{Icon, IconRef, Localized, LocalizedRef, undeclared_trap};
use crate::limits::{POLICY_FUEL_BUDGET, POLICY_MAX_STATE_BYTES};
use crate::listener::{ConsentDisclosure, SessionChange};
use crate::state::{HostState, RunInputs};

pub use status::RunStatus;

/// Composition domain types — the plugin fusion input (`PluginInstance`)
/// and the embedded-import manifest (`EmbeddedImport` / `EmbeddedIface`)
/// — are pure data and live in the [`engine_types::composition`] leaf, so
/// the wasmtime-free halves of the fleet can name them. Re-exported here
/// so callers keep addressing them as `engine_executor::*`.
pub use engine_types::composition::{EmbeddedIface, EmbeddedImport, PluginInstance};

/// Runs a compiled policy component against session state.
///
/// Owns the RUNTIME wasmtime [`Engine`] (`deserialize` + instantiate +
/// `handle`). A component is only instantiable on the engine it was
/// compiled on, so in-process the `Runner` facade builds this executor from
/// the SAME engine as its `Compiler` (via [`from_engine`](Self::from_engine)
/// + `Engine::clone`, which share the underlying engine). The cross-CVM
/// split instead gives the execution-worker its own engine and feeds it a
/// serialized `cwasm` produced by a matching compiler engine.
pub struct Executor {
    engine: Engine,
}

impl Executor {
    /// Build an executor with a fresh runtime engine — the execution-worker
    /// entry point.
    pub fn new() -> wasmtime::Result<Self> {
        Ok(Self {
            engine: Engine::new(&engine_config())?,
        })
    }

    /// Build an executor sharing an existing engine — used by the in-process
    /// `Runner` facade to run on the SAME engine its `Compiler` compiled on
    /// (`Engine::clone` shares the underlying engine, so a component compiled
    /// there is instantiable here).
    pub fn from_engine(engine: Engine) -> Self {
        Self { engine }
    }

    /// The runtime [`Engine`] this executor instantiates on.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Reconstruct a component from `cwasm` bytes produced by the compiler's
    /// `serialize_component`. Two facts make the `unsafe` deserialize
    /// sound for the L2 cache:
    ///
    ///   * **Provenance** — the caller only feeds bytes it AEAD-opened
    ///     under a TEE-only key, so the untrusted host cannot substitute
    ///     crafted bytes for the deserializer to interpret.
    ///   * **Version** — wasmtime embeds a compatibility fingerprint
    ///     (version + `Config` + target) and this returns `Err` on
    ///     mismatch instead of executing incompatible code, so a
    ///     toolchain bump degrades to a cache miss, not undefined
    ///     behaviour.
    pub fn deserialize_component(&self, cwasm: &[u8]) -> wasmtime::Result<Component> {
        // SAFETY: bytes are TEE-sealed (trusted provenance) and
        // wasmtime's own header check rejects an incompatible build —
        // see the doc comment above.
        unsafe { Component::deserialize(&self.engine, cwasm) }
    }

    /// Drive one reducer round. `session` carries the policy's opaque
    /// `state` blob and the `current_prompt` prompt from the previous
    /// round; `event` is the inbound mailbox message the runtime built
    /// from the applicant's `/input`. `props` is the static consumer
    /// config the policy reads via `enclavid:host/session-context.props`.
    ///
    /// Returns the next [`RunStatus`] and the updated [`SessionState`]
    /// (new opaque `state` + new `current_prompt`). The
    /// `SessionListener` is fired exactly once with the post-round
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
        let media_store = inputs.media_store.clone();

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
        // imports on `HostState`: `session-context.props`, the merged
        // `enclavid:host/embedded-disclosure-fields` (first-match, option B),
        // and the canonical `enclavid:host/embedded-{i18n,icons}` (used only
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
        let mut store = Store::new(
            &self.engine,
            HostState::new(props, embedded.clone(), media_store),
        );
        store.limiter(|s| &mut s.limits);
        store.set_fuel(POLICY_FUEL_BUDGET)?;
        let bindings = GeneratedHost::instantiate_async(&mut store, component, &linker).await?;

        // Mint the frame handles for this round and stage the captured blobs
        // (media rounds only) for the listener to seal alongside the state.
        let (wit_event, captured) = convert::event_to_wit(&mut store.data_mut().table, event)?;
        let (new_state, wit_action) = bindings
            .enclavid_policy_policy()
            .call_handle(&mut store, &session.state, &wit_event)
            .await?;

        // Data-minimization backstop: the policy's opaque blob must stay
        // under POLICY_MAX_STATE_BYTES so raw media clips can't be
        // smuggled into the sealed mailbox. A breach traps the round. (The
        // ciphertext-size covert channel is closed separately by constant-size
        // padding at the seal boundary — see broker-client `SetState`.)
        if new_state.len() > POLICY_MAX_STATE_BYTES {
            return Err(wasmtime::Error::msg(format!(
                "policy returned a {}-byte state blob, over the \
                 {POLICY_MAX_STATE_BYTES}-byte POLICY_MAX_STATE_BYTES cap",
                new_state.len(),
            )));
        }

        // Perform the action and assemble the next session record.
        let mut next_session = SessionState {
            policy_hash: session.policy_hash,
            state: new_state,
            current_prompt: None,
        };
        let status = match wit_action {
            crate::enclavid::policy::types::Action::Render(prompt) => {
                // Dereference every ref-resource handle the prompt carries
                // into its resolved data (translations / icon name / DF
                // key), reading the run's ResourceTable, and build the
                // self-contained sealed prompt. The handles can't cross
                // the engine→api seam, so this is the single resolution
                // point.
                let host = store.data();
                let prompt = convert::prompt_to_domain(prompt, &host.table, &host.embedded)?;
                next_session.current_prompt = Some(prompt.clone());
                RunStatus::AwaitingInput(prompt)
            }
            crate::enclavid::policy::types::Action::Finish(decision) => {
                RunStatus::Completed(convert::decision_to_domain(decision))
            }
        };

        // Single listener fire for the round: post-round state, the consented
        // disclosure (only on a consent-disclosure accept), and the captured
        // media to seal into the blob store (only on a media round). All
        // committed in one transaction by the listener.
        let disclosures: Vec<ConsentDisclosure> = sealed_disclosure.into_iter().collect();
        listener
            .on_session_change(SessionChange {
                state: &next_session,
                disclosures: &disclosures,
                media: captured.as_ref(),
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
/// no double-registration; the canonical `enclavid:host/*` names
/// bindgen registered are disjoint from these.
fn register_strict_embedded(
    linker: &mut Linker<HostState>,
    imports: &[EmbeddedImport],
    embedded: &std::sync::Arc<crate::embedded::EmbeddedRegistry>,
) -> wasmtime::Result<()> {
    // Branch by kind at REGISTRATION (not inside the closure) so each
    // func's closure has a single concrete resource return type. Each
    // resolves STRICTLY against the bound `catalog_hash` and mints the
    // ref resource into the run's ResourceTable.
    for imp in imports {
        let hash = imp.catalog_hash;
        match imp.iface {
            EmbeddedIface::I18n => {
                let embedded = embedded.clone();
                linker.root().instance(&imp.instance_name)?.func_wrap_async(
                    "localized",
                    move |mut store, (key,): (String,)| {
                        let embedded = embedded.clone();
                        Box::new(async move {
                            let data = embedded
                                .localized
                                .resolve_strict(&hash, &key)
                                .ok_or_else(|| undeclared_trap::<Localized>(&key))?
                                .clone();
                            let res: Resource<LocalizedRef> =
                                store.data_mut().table.push(LocalizedRef(data))?;
                            Ok((res,))
                        })
                    },
                )?;
            }
            EmbeddedIface::Icons => {
                let embedded = embedded.clone();
                linker.root().instance(&imp.instance_name)?.func_wrap_async(
                    "icon",
                    move |mut store, (name,): (String,)| {
                        let embedded = embedded.clone();
                        Box::new(async move {
                            let data = embedded
                                .icons
                                .resolve_strict(&hash, &name)
                                .ok_or_else(|| undeclared_trap::<Icon>(&name))?
                                .clone();
                            let res: Resource<IconRef> =
                                store.data_mut().table.push(IconRef(data))?;
                            Ok((res,))
                        })
                    },
                )?;
            }
        }
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

/// The wasmtime [`Config`] this executor builds its runtime [`Engine`] from.
/// It MUST match engine-compiler's `engine_config` verbatim: `consume_fuel`
/// compiles fuel checks INTO the code, so a mismatch would make a
/// compiler-produced `cwasm` fail this engine's compatibility-header check.
/// Duplicated (not shared) because the two crates live in separate CVMs and
/// cannot share a wasmtime-bearing dependency without one pulling the
/// other's toolchain.
fn engine_config() -> Config {
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.consume_fuel(true);
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Garbage bytes are rejected, not interpreted — wasmtime's header
    /// check turns a toolchain skew / host tamper into a clean `Err`
    /// (which the cache treats as a miss), never undefined behaviour.
    /// (The full compile→serialize→deserialize round-trip is exercised by
    /// the `TestRunner` in this crate's `happy_path` integration test, which
    /// holds both a `Compiler` and an `Executor`.)
    #[test]
    fn deserialize_rejects_non_cwasm() {
        let executor = Executor::new().unwrap();
        assert!(executor.deserialize_component(b"definitely not cwasm").is_err());
        assert!(executor.deserialize_component(&[]).is_err());
    }
}
