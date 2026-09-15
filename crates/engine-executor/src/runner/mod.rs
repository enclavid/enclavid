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
//!      `finish` yields `Completed`. (The size covert channel both carry is
//!      closed where the bytes are observable, not here: `SetState`'s Covert
//!      vouch at the seal boundary, and `engine_rpc::Padded` on the api hop the
//!      supervisor frames at. This process is behind a socketpair inside the
//!      CVM, so nothing here is padded.)
//!
//! ## Consent is decided elsewhere (security-critical)
//!
//! The disclosure → consumer seal is not a policy host call, and it is not
//! this process's call either. The orchestrator derives what a round seals
//! from the prompt it rendered and the event it built — the same two values
//! this runner sees, held on the side that did not execute the policy. Nothing
//! about consent is reported from here; see `SessionChange`.

mod convert;
mod status;

use hatch_client::{Event, SessionState};
use wasmtime::component::{Component, Linker, Resource};
use wasmtime::{Config, Engine, Store};

use crate::Host_ as GeneratedHost;
use crate::Host_Pre as GeneratedHostPre;
use crate::embedded::{Icon, IconRef, Localized, LocalizedRef, undeclared_trap};
use crate::limits::{POLICY_FUEL_BUDGET, POLICY_MAX_STATE_BYTES};
use crate::listener::SessionChange;
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
/// compiled on, so a cwasm compiled by a [`Compiler`](engine_compiler::Compiler)
/// on a matching `engine_config` deserializes here — the bridge across the
/// compile→execute seam (in-process the orchestrator holds one of each; the
/// cross-CVM split gives each worker its own engine).
pub struct Executor {
    engine: Engine,
}

/// A composition primed for repeated instantiation. Holds the bindgen
/// [`InstancePre`](wasmtime::component::InstancePre) wrapper (the Linker built +
/// type-checked ONCE — [`add_to_linker`] plus the strict per-catalog embedded
/// resolvers) and the composition-wide embedded registry the run reads at the
/// action boundary. Built by [`Executor::prime`]; every [`Executor::run`] against
/// it only mints a fresh `Store` + `instantiate_async`, so the link/type-check
/// cost is paid once per composition, not once per round.
///
/// Under the per-round child-process model this is primed and run exactly once
/// per child; the split still eliminates the previous per-round relink and is the
/// exact shape a warm zygote reuses across many `instantiate_async` calls.
pub struct PrimedComposition {
    pre: GeneratedHostPre<HostState>,
    embedded: std::sync::Arc<crate::embedded::EmbeddedRegistry>,
}

impl Executor {
    /// Build an executor with a fresh runtime engine — the execution-worker
    /// entry point.
    pub fn new() -> wasmtime::Result<Self> {
        Ok(Self {
            engine: Engine::new(&engine_config())?,
        })
    }

    /// Reconstruct a component from `cwasm` bytes in memory.
    ///
    /// TEST-ONLY in this tree — the shipped path is
    /// [`deserialize_component_file`](Self::deserialize_component_file), because a
    /// child MMAPs an inherited fd rather than receiving the bytes. The safety
    /// argument is that one's; see it.
    pub fn deserialize_component(&self, cwasm: &[u8]) -> wasmtime::Result<Component> {
        // SAFETY: see `deserialize_component_file`. Reached only from tests, which
        // feed bytes this workspace just compiled.
        unsafe { Component::deserialize(&self.engine, cwasm) }
    }

    /// Reconstruct a component by MMAP-ing a cwasm FILE (wasmtime
    /// `Component::deserialize_file`) instead of copying a byte slice. The mmap
    /// means the ~7 MiB never crosses the child hop as a copy, and several
    /// children mapping the same file share its read-only code pages.
    ///
    /// ## What makes the `unsafe` acceptable, and what it does not
    ///
    /// Not provenance. This used to read "the caller only feeds bytes it
    /// AEAD-opened under a TEE-only key", which is a claim about WHO the caller is
    /// — and nothing establishes it. The bytes arrive on the execute leg from a
    /// peer the listener accepts under `AcceptAny`: a genuine SNP guest, not
    /// identifiably api. No seal is opened on this side at all.
    ///
    /// What is true, in the order it applies:
    ///
    ///   * **Shape** — the supervisor refuses a bundle whose header is not a
    ///     wasmtime-serialized component before it ever becomes a file
    ///     (`engine_executor::admission`).
    ///   * **Stability** — the file is a write-sealed `memfd` the supervisor
    ///     created and no child can grow, shrink or write, so what is verified is
    ///     what stays mapped.
    ///   * **Version** — wasmtime embeds a compatibility fingerprint (version +
    ///     `Config` + target) and returns `Err` on a mismatch rather than
    ///     executing incompatible code.
    ///   * **Containment** — this runs in a disposable per-round child behind an
    ///     address-space boundary, an egress seccomp filter and a wall-clock
    ///     deadline, so undefined behaviour here reaches one round's plaintext and
    ///     no further.
    ///
    /// None of that verifies the body. A caller that can put bytes past the header
    /// check gets them deserialized, and the containment above is what bounds that
    /// — an accepted risk named where it is taken, not one argued away.
    pub fn deserialize_component_file(
        &self,
        path: impl AsRef<std::path::Path>,
    ) -> wasmtime::Result<Component> {
        // SAFETY: shape-checked at admission, mapped from a write-sealed memfd,
        // version-checked by wasmtime, and contained in a disposable child — see
        // the doc comment above, which says plainly what is NOT checked.
        unsafe { Component::deserialize_file(&self.engine, path) }
    }

    /// Build a [`PrimedComposition`] from an already-deserialized `component`:
    /// construct the host `Linker` for the imports fusion bubbled up and
    /// type-check it into a reusable `InstancePre`, ONCE. `embedded_imports` names
    /// the distinct per-catalog i18n/icons instances (`embedded-slot:<hash>/
    /// <iface>`); `embedded` is the composition-wide registry those resolve
    /// against (and that [`run`](Self::run) reads at the action boundary).
    ///
    /// bindgen wires the CANONICAL-named imports on `HostState`:
    /// `session-context.props`, the merged
    /// `enclavid:host/embedded-disclosure-fields` (first-match, option B), and the
    /// canonical `enclavid:host/embedded-{i18n,icons}` (used only by a lone
    /// unfused policy — a fused component routes those away, so the canonical
    /// registrations sit unused, harmless). Plugin↔policy interfaces are internal
    /// to the fused component, so the Linker never sees them. The strict
    /// per-catalog resolvers (`embedded-slot:<hash>/<iface>`) — which bindgen
    /// can't emit as dynamic names — are added on top.
    pub fn prime(
        &self,
        component: &Component,
        embedded_imports: &[EmbeddedImport],
        embedded: std::sync::Arc<crate::embedded::EmbeddedRegistry>,
    ) -> wasmtime::Result<PrimedComposition> {
        let mut linker: Linker<HostState> = Linker::new(&self.engine);
        GeneratedHost::add_to_linker::<_, HasHost>(&mut linker, |s| s)?;
        register_strict_embedded(&mut linker, embedded_imports, &embedded)?;
        let pre = GeneratedHostPre::new(linker.instantiate_pre(component)?)?;
        Ok(PrimedComposition { pre, embedded })
    }

    /// Drive one reducer round against a [`PrimedComposition`]. `session` carries
    /// the policy's opaque `state` blob and the `current_prompt` prompt from the
    /// previous round; `event` is the inbound mailbox message the runtime built
    /// from the applicant's `/input`. `props` is the static consumer config the
    /// policy reads via `enclavid:host/session-context.props`. `inputs` carries
    /// the per-round `listener` + `media_store` (the composition-wide `embedded`
    /// already lives in `primed`).
    ///
    /// Returns the next [`RunStatus`] and the updated [`SessionState`]
    /// (new opaque `state` + new `current_prompt`). The `SessionListener` is
    /// fired exactly once, with the post-round state and nothing else — neither
    /// the round's disclosure nor its captures, both of which the orchestrator
    /// already holds.
    pub async fn run(
        &self,
        primed: &PrimedComposition,
        session: SessionState,
        event: Event,
        props: Vec<(String, crate::Prop)>,
        inputs: RunInputs,
    ) -> wasmtime::Result<(RunStatus, SessionState)> {
        let embedded = primed.embedded.clone();
        let listener = inputs.listener;
        let media_store = inputs.media_store;

        // Instantiate the primed composition and call `handle` ONCE. The Linker
        // (imports) was built + type-checked in `prime`; here we only mint a
        // fresh `Store` (the per-round `HostState`) and instantiate against it.
        let mut store = Store::new(
            &self.engine,
            HostState::new(props, embedded.clone(), media_store),
        );
        store.limiter(|s| &mut s.limits);
        store.set_fuel(POLICY_FUEL_BUDGET)?;
        let bindings = primed.pre.instantiate_async(&mut store).await?;

        // Mint the frame handles for this round. Nothing is staged for the
        // listener: the orchestrator sent these frames and keeps them.
        let wit_event = convert::event_to_wit(&mut store.data_mut().table, event)?;
        let (new_state, wit_action) = bindings
            .enclavid_policy_policy()
            .call_handle(&mut store, &session.state, &wit_event)
            .await?;

        // Data-minimization backstop: the policy's opaque blob must stay
        // under POLICY_MAX_STATE_BYTES so raw media clips can't be
        // smuggled into the sealed mailbox. A breach traps the round. (The
        // size covert channel is closed separately by constant-size padding
        // wherever the bytes are observable — hatch-client `SetState` at rest,
        // `engine_rpc::Padded` on the api hop.)
        if new_state.len() > POLICY_MAX_STATE_BYTES {
            return Err(wasmtime::Error::msg(format!(
                "policy returned a {}-byte state blob, over the \
                 {POLICY_MAX_STATE_BYTES}-byte POLICY_MAX_STATE_BYTES cap",
                new_state.len(),
            )));
        }

        // Perform the action and assemble the next session record.
        let mut next_session = SessionState {
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

        // Single listener fire for the round, carrying the post-round state and
        // nothing else.
        //
        // The consent gate that used to sit here — accept + a consent
        // `current_prompt` ⇒ seal those exact fields — now runs in the
        // orchestrator instead, over its own copy of the same two values. It
        // could not stay in both places: this process runs the policy, so a
        // disclosure computed here is only ever as trustworthy as this process
        // is, and the orchestrator would have to re-derive it regardless.
        listener
            .on_session_change(SessionChange {
                state: &next_session,
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
                linker
                    .root()
                    .instance(&imp.instance_name)?
                    .func_wrap_async("localized", move |mut store, (key,): (String,)| {
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
                    })?;
            }
            EmbeddedIface::Icons => {
                let embedded = embedded.clone();
                linker
                    .root()
                    .instance(&imp.instance_name)?
                    .func_wrap_async("icon", move |mut store, (name,): (String,)| {
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
                    })?;
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
        assert!(
            executor
                .deserialize_component(b"definitely not cwasm")
                .is_err()
        );
        assert!(executor.deserialize_component(&[]).is_err());
    }
}
