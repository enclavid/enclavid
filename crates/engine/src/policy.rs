//! Policy execution: run a session through the policy wasm.
//!
//! `EvalArgs` is re-exported from bindgen for callers constructing the
//! typed args passed to `policy.evaluate`.

use std::collections::HashSet;
use std::sync::Arc;

use enclavid_host_bridge::{SessionState, suspended};
use wasmtime::component::Component;
use wasmtime::{Config, Engine, Store};

use crate::host_state::{HostResources, HostState};
use crate::limits::{MAX_TEXT_ENTRIES, MAX_TEXT_VALUE_HARD_BYTES, POLICY_FUEL_BUDGET};
use crate::listener::{SessionChange, SessionListener};
use crate::sanitize;
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

/// Output of `Runner::extract_texts`. The policy's
/// `prepare-text-refs` declarations are pre-split into the two
/// classes so the api crate doesn't need to walk the WIT-bindgen
/// variant itself:
///
///   * `identifiers` — pure machine keys (registered for
///     membership-check only, never resolved to user-facing text).
///   * `localized` — one `LocalizedDecl` per key, carrying its full
///     translation set. `TextRegistry::from_decls` indexes these by
///     key and the host membership-check union is `identifiers ∪
///     localized.keys`.
pub struct TextDecls {
    pub identifiers: Vec<String>,
    pub localized: Vec<LocalizedDecl>,
}

pub struct LocalizedDecl {
    pub key: String,
    /// `(language, value)` rows. Per-language uniqueness is a policy-
    /// authoring discipline, not enforced by the type — the host can
    /// later trap on duplicates during registry build.
    pub translations: Vec<(String, String)>,
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
        // `Store::limiter` — set up in `run` / `extract_texts`
        // alongside the fuel budget. Without both, a malicious
        // policy could hang or OOM the enclave.
        config.consume_fuel(true);
        let engine = Engine::new(&config)?;
        Ok(Self { engine })
    }

    /// Compile a policy component from its binary (wasm or wat).
    pub fn compile(&self, bytes: &[u8]) -> wasmtime::Result<Component> {
        Component::new(&self.engine, bytes)
    }

    /// Instantiate the policy briefly, call its `prepare-text-refs`
    /// export, and return the declared text-refs already split into
    /// identifier-only refs and translation rows. Called once per
    /// policy load — the caller (api crate) caches the result
    /// alongside the compiled component and never re-invokes this.
    ///
    /// The instantiation uses a stub session + no-op listener: the
    /// policy isn't supposed to make host calls inside this export
    /// (it's pure constant declarations). The empty registered set
    /// guarantees that any disallowed host fn call traps loudly,
    /// surfacing the policy bug at load time rather than at first
    /// /input.
    pub async fn extract_texts(
        &self,
        component: &Component,
    ) -> wasmtime::Result<TextDecls> {
        let mut linker: Linker<HostState> = Linker::new(&self.engine, |s| InterceptView {
            replay: &mut s.replay,
            disclosures: &mut s.pending_disclosures,
            listener: &s.listener,
        });
        GeneratedHost::add_to_linker::<_, HasHost>(&mut linker, |s| s)?;

        let session = SessionState::default();
        let resources = HostResources {
            listener: Arc::new(NoopListener),
            registered_text_refs: Arc::new(Default::default()),
        };
        let mut store = Store::new(&self.engine, HostState::new(session, resources));
        store.limiter(|s| &mut s.limits);
        store.set_fuel(POLICY_FUEL_BUDGET)?;
        let bindings = GeneratedHost::instantiate_async(&mut store, component, &linker).await?;

        let raw_decls = bindings
            .enclavid_policy_policy()
            .call_prepare_text_refs(&mut store)
            .await?;

        process_decls(raw_decls)
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
        store.limiter(|s| &mut s.limits);
        store.set_fuel(POLICY_FUEL_BUDGET)?;
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

/// Walk the WIT-bindgen output of `prepare-text-refs` into the
/// engine-owned `TextDecls` shape, enforcing every invariant the
/// host promises in `wit/policy/policy.wit`:
///
///   * Top-level decl count ≤ `MAX_TEXT_ENTRIES` — bounds registry
///     memory; pairs with the wasmtime linear-memory cap.
///   * Every text-ref key passes `validate_key_format` (ASCII,
///     ≤128 chars, starts with a letter).
///   * No duplicate keys across identifier + localized variants —
///     each text-ref is declared at most once.
///   * No duplicate `(key, language)` pair inside a `localized`
///     block.
///   * Each translation `language` passes `validate_language`
///     (BCP-47-shaped, ≤16 chars).
///   * Each translation `value` is hard-rejected if it exceeds
///     `MAX_TEXT_VALUE_HARD_BYTES`, otherwise sanitised
///     (strip control / BIDI / zero-width / Unicode-tag chars,
///     soft-truncate to `MAX_TEXT_VALUE_SOFT_CHARS`).
///
/// Failures trap; the policy load fails and the api crate maps
/// that to a generic 500 — the surfaced error message is
/// host-controlled (function role + bound name) and never echoes
/// raw policy bytes back to the caller.
fn process_decls(
    raw: Vec<crate::exports::enclavid::policy::policy::TextDecl>,
) -> wasmtime::Result<TextDecls> {
    use crate::exports::enclavid::policy::policy::TextDecl;

    if raw.len() > MAX_TEXT_ENTRIES {
        return Err(wasmtime::Error::msg(format!(
            "prepare-text-refs returned {} declarations, max is {MAX_TEXT_ENTRIES}",
            raw.len(),
        )));
    }

    let mut identifiers = Vec::new();
    let mut localized = Vec::new();
    let mut seen_keys: HashSet<String> = HashSet::new();

    for d in raw {
        match d {
            TextDecl::Identifier(key) => {
                sanitize::validate_key_format(&key)?;
                if !seen_keys.insert(key.clone()) {
                    return Err(wasmtime::Error::msg(format!(
                        "prepare-text-refs declared text-ref '{key}' more than once"
                    )));
                }
                identifiers.push(key);
            }
            TextDecl::Localized(lt) => {
                sanitize::validate_key_format(&lt.key)?;
                if !seen_keys.insert(lt.key.clone()) {
                    return Err(wasmtime::Error::msg(format!(
                        "prepare-text-refs declared text-ref '{}' more than once",
                        lt.key,
                    )));
                }
                let mut translations = Vec::with_capacity(lt.translations.len());
                let mut seen_langs: HashSet<String> = HashSet::new();
                for t in lt.translations {
                    sanitize::validate_language(&t.language)?;
                    if !seen_langs.insert(t.language.clone()) {
                        return Err(wasmtime::Error::msg(format!(
                            "localized-text '{}' declares language '{}' more than once",
                            lt.key, t.language,
                        )));
                    }
                    if t.value.len() > MAX_TEXT_VALUE_HARD_BYTES {
                        return Err(wasmtime::Error::msg(format!(
                            "translation value for '{}' / '{}' exceeds {MAX_TEXT_VALUE_HARD_BYTES} bytes",
                            lt.key, t.language,
                        )));
                    }
                    let value = sanitize::sanitize_text_value(&t.value);
                    translations.push((t.language, value));
                }
                localized.push(LocalizedDecl {
                    key: lt.key,
                    translations,
                });
            }
        }
    }

    Ok(TextDecls { identifiers, localized })
}

/// Marker type bridging bindgen's `HasData` to `&mut HostState`. Host traits
/// are implemented directly on `HostState`, so the Data<'a> is just a
/// mutable reborrow.
struct HasHost;

impl wasmtime::component::HasData for HasHost {
    type Data<'a> = &'a mut HostState;
}

/// No-op listener used only by `extract_texts` — the
/// `prepare-localized-texts` export shouldn't trigger any host
/// calls, but the host machinery requires a listener to be present.
struct NoopListener;

impl SessionListener for NoopListener {
    fn on_session_change<'a>(
        &'a self,
        _change: SessionChange<'a>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = wasmtime::Result<()>> + Send + 'a>,
    > {
        Box::pin(async { Ok(()) })
    }
}
