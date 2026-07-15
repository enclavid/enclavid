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
//!      `finish` yields `Completed`. (The sealed-state size covert channel is
//!      closed at the seal boundary in broker-client — `SetState`'s Covert
//!      vouch pads the encoded `SessionState` to a constant — not here.)
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
use wasmtime::component::{Component, Linker, Resource};
use wasmtime::{Config, Engine, Store};

use crate::Host_ as GeneratedHost;
use crate::embedded::{Icon, IconRef, Localized, LocalizedRef, undeclared_trap};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
///
/// serde: part of the L2 cwasm-cache bundle — the import manifest is
/// stored beside the cwasm so a cache hit reconstructs the host
/// `Linker` registrations without re-fusing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmbeddedImport {
    pub instance_name: String,
    pub catalog_hash: [u8; 32],
    pub iface: EmbeddedIface,
    /// Version of the routed interface — the canonical import's `@x.y.z`
    /// (empty if unversioned). Baked into `instance_name` so a
    /// same-catalog different-version import can't collide onto one twin;
    /// also lets host registration be version-aware if interface
    /// signatures ever diverge across versions.
    pub version: String,
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

    /// Serialize a compiled component to `cwasm` bytes for the L2
    /// compiled-artifact cache. Inverse of [`deserialize_component`].
    /// The bytes are only valid on an engine built compatibly (same
    /// wasmtime version / `Config` / target) — the cache seals them and
    /// treats an incompatible load as a miss.
    pub fn serialize_component(&self, component: &Component) -> wasmtime::Result<Vec<u8>> {
        component.serialize()
    }

    /// Reconstruct a component from `cwasm` bytes produced by
    /// [`serialize_component`]. Two facts make the `unsafe` deserialize
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

    /// Fuse a policy with plugins into a self-contained component's
    /// BYTES — the strict-routed static artifact `enclavid link` would
    /// publish. The embedded manifest is reconstructed from these bytes
    /// at load time (see [`compose::reconstruct_strict_manifest`]), so
    /// it isn't returned here.
    pub fn fuse(&self, policy_wasm: &[u8], plugins: &[PluginInstance]) -> wasmtime::Result<Vec<u8>> {
        let (bytes, _manifest) = compose::fuse(policy_wasm, plugins)?;
        Ok(bytes)
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
    /// Three shapes are handled:
    ///
    ///   * **Dynamic** — a non-fused policy plus runtime `plugins`:
    ///     [`compose::fuse`] routes each component's i18n / icons import
    ///     to a distinct per-catalog import (the manifest).
    ///   * **Static** — a pre-fused policy artifact with no runtime
    ///     plugins: compiled as-is; the manifest is reconstructed from
    ///     the `embedded-slot:*` imports the artifact already carries
    ///     (empty for a lone unfused policy, whose canonical embedded
    ///     imports the host serves first-match).
    ///   * **Hybrid** — a pre-fused core plus runtime `plugins`: fused
    ///     again; the core's own routed imports bubble through and are
    ///     re-emitted alongside the freshly routed runtime ones.
    pub fn compose(
        &self,
        policy_wasm: &[u8],
        plugins: &[PluginInstance],
    ) -> wasmtime::Result<Composition> {
        let (component, mut embedded_imports) = if plugins.is_empty() {
            (
                self.compile(policy_wasm)?,
                compose::reconstruct_strict_manifest(policy_wasm)?,
            )
        } else {
            let (fused, mut manifest) = compose::fuse(policy_wasm, plugins)?;
            // Hybrid pass-through: the core's own `embedded-slot:*`
            // imports came through fusion untouched — add their manifest
            // entries. Empty for a non-fused dynamic policy.
            manifest.extend(compose::reconstruct_strict_manifest(policy_wasm)?);
            (Component::new(&self.engine, &fused)?, manifest)
        };
        // Dedup by instance name: a runtime plugin and a baked one can
        // share a catalog (same slug) — register the host instance once.
        let mut seen = std::collections::HashSet::new();
        embedded_imports.retain(|e| seen.insert(e.instance_name.clone()));
        Ok(Composition {
            component,
            embedded_imports,
        })
    }

    /// Drive one reducer round. `session` carries the policy's opaque
    /// `state` blob and the `current_prompt` prompt from the previous
    /// round; `event` is the inbound mailbox message the runtime built
    /// from the applicant's `/input`. `props` is the static consumer
    /// config the policy reads via `enclavid:host/session-context.props`.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A compiled component serializes to `cwasm` and deserializes back
    /// on the same engine — the L2 cache's compile-amortization path.
    #[test]
    fn serialize_deserialize_component_round_trips() {
        let runner = Runner::new().unwrap();
        // Minimal valid empty component.
        let bytes = wasm_encoder::Component::new().finish();
        let component = runner.compile(&bytes).unwrap();
        let cwasm = runner.serialize_component(&component).unwrap();
        assert!(!cwasm.is_empty(), "serialize produces cwasm bytes");
        // Round-trips on the same engine; re-serialize proves the
        // restored component is a live artifact, not a dangling handle.
        let restored = runner.deserialize_component(&cwasm).unwrap();
        runner.serialize_component(&restored).unwrap();
    }

    /// Garbage bytes are rejected, not interpreted — wasmtime's header
    /// check turns a toolchain skew / host tamper into a clean `Err`
    /// (which the cache treats as a miss), never undefined behaviour.
    #[test]
    fn deserialize_rejects_non_cwasm() {
        let runner = Runner::new().unwrap();
        assert!(runner.deserialize_component(b"definitely not cwasm").is_err());
        assert!(runner.deserialize_component(&[]).is_err());
    }
}
