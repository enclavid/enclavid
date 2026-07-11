use std::collections::BTreeMap;
use std::sync::Arc;

use wasmtime::component::ResourceTable;
use wasmtime::{StoreLimits, StoreLimitsBuilder};

use crate::embedded::EmbeddedRegistry;
use crate::limits::{POLICY_MAX_MEMORY, POLICY_MAX_STATE_BYTES};
use crate::listener::SessionListener;
use crate::state::kv as codec;

/// Data placed into wasmtime `Store<HostState>` for the duration of one
/// `handle` call. The policy is a pure actor, so this state carries the
/// ambient read surfaces (`enclavid:host/session-context` props,
/// `enclavid:embedded/*` registry), the round's private storage map
/// (`enclavid:host/storage`), and the runtime plumbing (table, limits).
/// No replay log, no per-call disclosure buffer — the runner fires the
/// listener directly on a consent-disclosure accept, around the `handle`
/// call, not from a host-fn body.
pub struct HostState {
    /// Static consumer config (`metadata.input`), surfaced to the
    /// policy through `enclavid:host/session-context.props`. Constant for
    /// the session; the policy may read it any round.
    pub props: Vec<(String, crate::enclavid::host::types::Prop)>,
    /// The policy's private per-round `enclavid:host/storage` key/value
    /// map, decoded from the sealed `SessionState::state` blob at the top
    /// of the round. `get`/`set`/`delete` operate on this in-memory copy;
    /// the runner re-encodes + seals it only if `handle` returns cleanly,
    /// so mutations are STAGED and a trap rolls the round back.
    pub kv: BTreeMap<String, Vec<u8>>,
    /// Running encoded byte length of `kv` (== `kv::encoded_len(&kv)`),
    /// maintained incrementally by `set`/`delete`. `storage::set` rejects a
    /// write that would push it over `POLICY_MAX_STATE_BYTES`, so the host
    /// map is bounded DURING the round — closing the intra-round host-memory
    /// growth a post-round-only cap would miss (a policy could otherwise
    /// stage many large distinct keys before any check ran).
    kv_bytes: usize,
    /// Per-composition `enclavid:host/embedded-*` registry — one frozen
    /// index built from the policy's and every fused plugin's embedded
    /// sections. The embedded host fns resolve a key against it (first
    /// match across the merged catalogs, or strict against one catalog
    /// for a routed twin) and MINT a ref resource into [`table`](Self::
    /// table) carrying the resolved data. Frozen before any per-session
    /// input reaches the component; a component can only reference a key
    /// some catalog declared.
    pub embedded: Arc<EmbeddedRegistry>,
    /// Handle table backing the embedded ref resources
    /// (`localized-ref` / `icon-ref` / `disclosure-field-ref`). The host
    /// funcs push resolved data here and hand the component an
    /// unforgeable handle; the runner dereferences the handles the
    /// returned prompt carries at the action boundary. Fresh per run,
    /// dropped with the Store — refs never outlive the round.
    pub table: ResourceTable,
    /// Resource caps the wasmtime runtime consults via `Store::
    /// limiter`. Bounds linear-memory growth so the policy component
    /// can't OOM the enclave. Fuel (CPU-instruction budget) is set
    /// separately on the Store via `Store::set_fuel`.
    pub limits: StoreLimits,
}

/// Per-run inputs assembled by the api crate and handed to
/// [`HostState::new`]. Carries the listener that ties this run to the
/// caller's persistence layer plus the composition-wide
/// `EmbeddedRegistry` — constructed once at policy-cache build time from
/// policy + plugin embedded sections and shared by `Arc` with every
/// consumer (engine first-match resolve, engine use-site reverse-lookup,
/// api view-layer ref resolution).
pub struct RunInputs {
    pub listener: Arc<dyn SessionListener>,
    pub embedded: Arc<EmbeddedRegistry>,
}

impl HostState {
    pub(crate) fn new(
        props: Vec<(String, crate::enclavid::host::types::Prop)>,
        embedded: Arc<EmbeddedRegistry>,
        kv: BTreeMap<String, Vec<u8>>,
    ) -> Self {
        let kv_bytes = codec::encoded_len(&kv);
        Self {
            props,
            embedded,
            kv,
            kv_bytes,
            table: ResourceTable::new(),
            limits: StoreLimitsBuilder::new()
                .memory_size(POLICY_MAX_MEMORY)
                .build(),
        }
    }
}

/// `enclavid:host/session-context` — the policy's ambient `props`
/// getter. Referentially transparent: returns the same static consumer
/// config every call, no side effect, no replay concern.
impl crate::enclavid::host::session_context::Host for HostState {
    async fn props(
        &mut self,
    ) -> wasmtime::Result<Vec<(String, crate::enclavid::host::types::Prop)>> {
        Ok(self.props.clone())
    }
}

/// `enclavid:host/storage` — the policy's private per-round key/value
/// state. Operates on the in-memory map decoded from the sealed blob; the
/// runner re-encodes + seals it only on a clean `handle` return, so these
/// are STAGED writes with trap-rollback. A `get` after a `set`/`delete` in
/// the same round reflects the staged mutation.
///
/// `set` enforces `POLICY_MAX_STATE_BYTES` as a RUNNING bound (per write,
/// via the incrementally-tracked `kv_bytes`) rather than only at commit, so
/// a policy can't stage many large distinct keys and balloon host memory
/// before the round ends. A write that would breach the cap is rejected and
/// traps the round.
impl crate::enclavid::host::storage::Host for HostState {
    async fn get(&mut self, key: String) -> wasmtime::Result<Option<Vec<u8>>> {
        Ok(self.kv.get(&key).cloned())
    }

    async fn set(&mut self, key: String, value: Vec<u8>) -> wasmtime::Result<()> {
        let new_entry = codec::entry_len(&key, &value);
        // Overwriting an existing key reclaims its old entry's bytes.
        let old_entry = self.kv.get(&key).map_or(0, |v| codec::entry_len(&key, v));
        let prospective = self.kv_bytes - old_entry + new_entry;
        if prospective > POLICY_MAX_STATE_BYTES {
            return Err(wasmtime::Error::msg(format!(
                "storage.set would grow the policy state to {prospective} bytes, over \
                 the {POLICY_MAX_STATE_BYTES}-byte POLICY_MAX_STATE_BYTES cap — the \
                 write is rejected (host memory is bounded per write, not only at commit)"
            )));
        }
        self.kv_bytes = prospective;
        self.kv.insert(key, value);
        Ok(())
    }

    async fn delete(&mut self, key: String) -> wasmtime::Result<()> {
        if let Some(v) = self.kv.remove(&key) {
            self.kv_bytes -= codec::entry_len(&key, &v);
        }
        Ok(())
    }
}

// Pure-types interfaces (no host functions) still generate empty `Host`
// traits via `bindgen!`. Implementing them on `HostState` satisfies the
// linker bound — there's nothing to actually implement.
impl crate::enclavid::policy::types::Host for HostState {}
impl crate::enclavid::shared_types::capture::Host for HostState {}
impl crate::enclavid::shared_types::disclosure::Host for HostState {}
// `enclavid:host/types::Host` + the three ref-resource destructors live
// in `embedded::host`, next to the resolvers that mint them.
