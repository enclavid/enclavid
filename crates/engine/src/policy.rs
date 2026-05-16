//! Policy execution: run a session through the policy wasm.
//!
//! `EvalArgs` is re-exported from bindgen for callers constructing the
//! typed args passed to `policy.evaluate`.

use std::collections::HashSet;

use enclavid_host_bridge::{SessionState, suspended};
use wasmtime::component::Component;
use wasmtime::{Config, Engine, Store};

use crate::host_state::{HostResources, HostState};
use crate::limits::{MAX_TEXT_ENTRIES, POLICY_FUEL_BUDGET};
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
#[derive(Debug, Default)]
pub struct TextDecls {
    pub identifiers: Vec<String>,
    pub localized: Vec<LocalizedDecl>,
}

#[derive(Debug)]
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

/// Current policy manifest schema version. Engine accepts manifests
/// declaring `version: 1` (or omitting the field — back-compat with
/// pre-versioning early artifacts).
const POLICY_MANIFEST_VERSION_CURRENT: u32 = 1;

/// Parse the polici manifest blob (the plain JSON layer alongside the
/// encrypted wasm in the OCI artifact). Replaces the wasm-side
/// `prepare-text-refs` export: declarations are now static data, not
/// executed code.
///
/// Wire format:
///
/// ```json
/// {
///   "version": 1,
///   "disclosure_fields": ["passport_number", "risk_category"],
///   "localized": {
///     "passport_title":  { "en": "Your passport", "ru": "Ваш паспорт" },
///     "consent_reason":  { "en": "Identity verification...", "ru": "..." }
///   }
/// }
/// ```
///
/// `disclosure_fields` lists machine keys used as `prompt_disclosure`
/// `DisplayField.key`. `localized` carries translation rows for refs
/// that render as UI strings.
///
/// **Validation strategy: lazy.** Engine here enforces only what's
/// needed to bound memory (total entry count cap, plus schema
/// version dispatch). Per-entry format / language / length /
/// sanitisation checks happen at use time — `TextRegistry::resolve_string`
/// sanitises text values when actually returning them, and the
/// engine-side `sanitize::ensure_registered` validates ref format on
/// every polici-supplied key when polici invokes a host function.
///
/// Rationale: this is defence-in-depth, not primary validation.
/// Author-side `enclavid validate` and (future) push-time linting
/// catch malformed manifests before they reach the registry. TEE
/// just needs to bound resource use and trap if anything malformed
/// is actually exercised at evaluate time. Eager validation here
/// would also do work for declarations the polici never uses (replay
/// strategy means many entries may go unresolved per session).
pub fn load_manifest(bytes: &[u8]) -> wasmtime::Result<TextDecls> {
    use std::collections::BTreeMap;

    #[derive(serde::Deserialize)]
    struct PolicyManifest {
        /// Optional for forward/backward compat. Omitted = treat as
        /// current schema version. Future BREAKING schema changes
        /// will require dispatch on this field — additive changes
        /// (new optional top-level keys) don't.
        #[serde(default)]
        version: Option<u32>,
        #[serde(default)]
        disclosure_fields: Vec<String>,
        #[serde(default)]
        localized: BTreeMap<String, BTreeMap<String, String>>,
    }

    let manifest: PolicyManifest = serde_json::from_slice(bytes)
        .map_err(|e| wasmtime::Error::msg(format!("policy manifest JSON parse: {e}")))?;

    if let Some(v) = manifest.version {
        if v != POLICY_MANIFEST_VERSION_CURRENT {
            return Err(wasmtime::Error::msg(format!(
                "policy manifest version {v} not supported (engine knows version {POLICY_MANIFEST_VERSION_CURRENT})",
            )));
        }
    }

    // Memory bound — independent of per-entry validation. Stops a
    // malicious or malformed manifest from blowing up TextRegistry
    // state. Per-translation byte sizes bounded separately by the
    // transport-level cap on the assets layer in `policy_pull`.
    let total = manifest.disclosure_fields.len() + manifest.localized.len();
    if total > MAX_TEXT_ENTRIES {
        return Err(wasmtime::Error::msg(format!(
            "policy manifest declares {total} entries, max is {MAX_TEXT_ENTRIES}",
        )));
    }

    // Disclosure fields: dedupe within the list (JSON allows
    // duplicates in arrays — collapse here so the membership set
    // doesn't accidentally double-count). Overlap with `localized`
    // is permitted by design.
    let mut seen_disclosure: HashSet<String> = HashSet::new();
    let identifiers: Vec<String> = manifest
        .disclosure_fields
        .into_iter()
        .filter(|key| seen_disclosure.insert(key.clone()))
        .collect();

    // `manifest.localized` is a BTreeMap (JSON object keys unique by
    // construction). Push verbatim — format / language / length /
    // sanitisation deferred to `TextRegistry::resolve_string`.
    let localized: Vec<LocalizedDecl> = manifest
        .localized
        .into_iter()
        .map(|(key, translations)| LocalizedDecl {
            key,
            translations: translations.into_iter().collect(),
        })
        .collect();

    Ok(TextDecls { identifiers, localized })
}

/// Marker type bridging bindgen's `HasData` to `&mut HostState`. Host traits
/// are implemented directly on `HostState`, so the Data<'a> is just a
/// mutable reborrow.
struct HasHost;

impl wasmtime::component::HasData for HasHost {
    type Data<'a> = &'a mut HostState;
}

#[cfg(test)]
mod load_manifest_tests {
    use super::*;

    fn parse(json: &str) -> wasmtime::Result<TextDecls> {
        load_manifest(json.as_bytes())
    }

    #[test]
    fn happy_path() {
        let decls = parse(r#"{
            "version": 1,
            "disclosure_fields": ["passport_number", "risk_category"],
            "localized": {
                "passport_title": {
                    "en": "Your passport",
                    "ru": "Ваш паспорт"
                },
                "consent_reason": {
                    "en": "Identity verification."
                }
            }
        }"#).expect("parse");

        assert_eq!(
            decls.identifiers,
            vec!["passport_number".to_string(), "risk_category".to_string()],
        );
        // BTreeMap iteration is alphabetical by key — consent_reason
        // before passport_title.
        assert_eq!(decls.localized.len(), 2);
        assert_eq!(decls.localized[0].key, "consent_reason");
        assert_eq!(decls.localized[1].key, "passport_title");
        assert_eq!(decls.localized[1].translations.len(), 2);
    }

    #[test]
    fn version_optional_back_compat() {
        // Manifests without version field load as current schema.
        let decls = parse(r#"{ "disclosure_fields": ["a_key"] }"#).expect("parse");
        assert_eq!(decls.identifiers, vec!["a_key".to_string()]);
    }

    #[test]
    fn rejects_unknown_version() {
        let err = parse(r#"{ "version": 99 }"#).unwrap_err();
        assert!(err.to_string().contains("version 99"), "{err}");
    }

    #[test]
    fn defaults_when_sections_missing() {
        let decls = parse(r#"{ "disclosure_fields": ["only_this"] }"#).expect("parse");
        assert_eq!(decls.identifiers, vec!["only_this".to_string()]);
        assert!(decls.localized.is_empty());

        let decls = parse(r#"{}"#).expect("parse");
        assert!(decls.identifiers.is_empty());
        assert!(decls.localized.is_empty());
    }

    #[test]
    fn dedupes_duplicate_disclosure_fields() {
        // JSON arrays allow dupes; we dedupe in-place rather than
        // trapping. Membership set is still consistent.
        let decls = parse(r#"{
            "disclosure_fields": ["dup_key", "dup_key"]
        }"#).expect("parse");
        assert_eq!(decls.identifiers, vec!["dup_key".to_string()]);
    }

    #[test]
    fn allows_dual_use_in_disclosure_fields_and_localized() {
        // Same ref can be declared in both lists — polici may use it
        // as `field.key` (raw identifier) AND as a localized label
        // or reason. `TextRegistry` builds its `keys` set as a union.
        let decls = parse(r#"{
            "disclosure_fields": ["dual_use"],
            "localized": { "dual_use": { "en": "Dual use label" } }
        }"#).expect("parse");
        assert!(decls.identifiers.contains(&"dual_use".to_string()));
        assert_eq!(decls.localized.len(), 1);
        assert_eq!(decls.localized[0].key, "dual_use");
    }

    #[test]
    fn accepts_bad_key_format_lazily() {
        // Load doesn't validate per-key format — that happens at
        // use-time via `sanitize::ensure_registered` when polici
        // calls a host fn with the ref. A malformed declaration
        // here is harmless if polici never uses it.
        let decls = parse(r#"{
            "disclosure_fields": ["BadKeyWithCaps"]
        }"#).expect("parse");
        assert_eq!(decls.identifiers, vec!["BadKeyWithCaps".to_string()]);
    }

    #[test]
    fn accepts_bad_language_lazily() {
        // Same: language tag format isn't validated at load. A bad
        // tag just won't match any locale lookup, falls through to
        // en or first-available in `resolve_string`.
        let decls = parse(r#"{
            "localized": { "k": { "en_US": "Underscore-tag value" } }
        }"#).expect("parse");
        assert_eq!(decls.localized.len(), 1);
        assert_eq!(decls.localized[0].translations[0].0, "en_US");
    }

    #[test]
    fn accepts_oversized_translation_lazily() {
        // Per-value length cap is gone from load. Transport-level
        // cap in `policy_pull` bounds the aggregate manifest size.
        let huge = "x".repeat(MAX_TEXT_ENTRIES);
        let payload = format!(r#"{{
            "localized": {{ "k": {{ "en": {} }} }}
        }}"#, serde_json::to_string(&huge).unwrap());
        let decls = parse(&payload).expect("parse");
        assert_eq!(decls.localized.len(), 1);
        assert!(decls.localized[0].translations[0].1.len() >= MAX_TEXT_ENTRIES);
    }

    #[test]
    fn rejects_too_many_entries() {
        // Total-count cap is the one validation we DO eagerly,
        // because it bounds TextRegistry memory.
        let mut disclosure_fields: Vec<String> = Vec::new();
        for i in 0..=MAX_TEXT_ENTRIES {
            disclosure_fields.push(format!("k_{i}"));
        }
        let payload = serde_json::json!({
            "disclosure_fields": disclosure_fields,
        });
        let err = parse(&payload.to_string()).unwrap_err();
        assert!(err.to_string().contains("max is"), "{err}");
    }

    #[test]
    fn rejects_malformed_json() {
        let err = parse(r#"{ "disclosure_fields": [oops] }"#).unwrap_err();
        assert!(err.to_string().contains("JSON parse"), "{err}");
    }
}
