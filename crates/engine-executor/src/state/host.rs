use std::sync::Arc;

use wasmtime::ResourceLimiter;
use wasmtime::component::ResourceTable;

use crate::embedded::EmbeddedRegistry;
use crate::limits::POLICY_MAX_MEMORY;
use crate::listener::SessionListener;
use crate::media_store::MediaStore;

/// Data placed into wasmtime `Store<HostState>` for the duration of one
/// `handle` call. The policy is a pure reducer, so this state carries
/// only ambient read surfaces (`enclavid:host/session-context` props,
/// `enclavid:embedded/*` registry) plus the runtime plumbing
/// (listener, limits). No replay log, no per-call disclosure buffer —
/// the runner fires the listener directly on a consent-disclosure
/// accept, around the `handle` call, not from a host-fn body.
pub struct HostState {
    /// Static consumer config (`metadata.input`), surfaced to the
    /// policy through `enclavid:host/session-context.props`. Constant for
    /// the session; the policy may read it any round.
    pub props: Vec<(String, crate::enclavid::host::types::Prop)>,
    /// Per-composition `enclavid:host/embedded-*` registry — one frozen
    /// index built from the policy's and every fused plugin's embedded
    /// sections. The embedded host fns resolve a key against it (first
    /// match across the merged catalogs, or strict against one catalog
    /// for a routed twin) and MINT a ref resource into [`table`](Self::
    /// table) carrying the resolved data. Frozen before any per-session
    /// input reaches the component; a component can only reference a key
    /// some catalog declared.
    pub embedded: Arc<EmbeddedRegistry>,
    /// Handle table backing the host-owned ref resources
    /// (`localized-ref` / `icon-ref` / `disclosure-field-ref`) and the
    /// `blob` resources. The host funcs push resolved data / capture
    /// blobs here and hand the component an unforgeable handle; the runner
    /// dereferences the ref handles the returned prompt carries at the
    /// action boundary. Fresh per run, dropped with the Store — handles
    /// never outlive the round.
    pub table: ResourceTable,
    /// Host-side sealed blob store, injected by the runtime's I/O layer.
    /// Backs `blob::from-blob-ref` — the policy rehydrates a stored capture
    /// blob by its content ref mid-`handle`. `Arc<dyn>` so the host fn can
    /// clone it out before the `.await` (releasing the borrow of `self`).
    pub media_store: Arc<dyn MediaStore>,
    /// Resource caps the wasmtime runtime consults via `Store::
    /// limiter`. Bounds linear-memory growth so the policy component
    /// can't OOM the enclave. Fuel (CPU-instruction budget) is set
    /// separately on the Store via `Store::set_fuel`.
    pub limits: AggregateMemory,
}

/// Per-run inputs handed to [`Executor::run`](crate::Executor::run) once per
/// round: the `listener` that ties this run to the caller's persistence layer
/// and the `media_store` that rehydrates stored blobs. The composition-wide
/// `EmbeddedRegistry` is NOT here — it is immutable across a composition's rounds,
/// so it is built into the [`PrimedComposition`](crate::PrimedComposition) at
/// [`prime`](crate::Executor::prime) time and read from there.
pub struct RunInputs {
    pub listener: Arc<dyn SessionListener>,
    pub media_store: Arc<dyn MediaStore>,
}

impl HostState {
    pub(crate) fn new(
        props: Vec<(String, crate::enclavid::host::types::Prop)>,
        embedded: Arc<EmbeddedRegistry>,
        media_store: Arc<dyn MediaStore>,
    ) -> Self {
        Self {
            props,
            embedded,
            table: ResourceTable::new(),
            media_store,
            limits: AggregateMemory::with_ceiling(POLICY_MAX_MEMORY),
        }
    }
}

/// One ceiling over every linear memory in the store, rather than one ceiling
/// applied to each of them.
///
/// `StoreLimits::memory_size` reads as a cap on the store and is not one:
/// wasmtime asks the limiter once per memory and its implementation ignores the
/// `current` argument, so each memory may reach the cap on its own. That is a
/// per-memory cap by construction, and a fused component is not one memory —
/// measured: a policy alone has 1, with one plugin 2, with five 6. The multiplier
/// is the pinned plugin count, which the consumer chooses, times the concurrent
/// child count. `POLICY_MAX_MEMORY` therefore bounded nothing a consumer could
/// not step around by pinning more plugins.
///
/// Capping the NUMBER of memories instead (`StoreLimitsBuilder::memories`) does
/// not fix it either: the product is still `ceiling x count`, and the count is
/// not knowable in advance.
///
/// So the charge is aggregate. Each grow is charged its increment against one
/// running total; whether that total is spread over one memory or twenty is not
/// something this has an opinion about, which is the point.
#[derive(Debug)]
pub struct AggregateMemory {
    ceiling: usize,
    total: usize,
}

impl AggregateMemory {
    pub fn with_ceiling(ceiling: usize) -> Self {
        Self { ceiling, total: 0 }
    }
}

impl ResourceLimiter for AggregateMemory {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        // `desired` is this memory's new size, so the charge is its increment.
        // Creation arrives as current = 0, which charges the initial size —
        // otherwise a store could hold any number of memories that never grow.
        let charge = desired.saturating_sub(current);
        match self.total.checked_add(charge) {
            Some(next) if next <= self.ceiling => {
                self.total = next;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Unbounded, which is what it was before this type existed —
    /// `StoreLimitsBuilder` was only ever given `memory_size`, so
    /// `table_elements` was never set. Left alone rather than quietly given a
    /// number: tables are a separate surface with their own sizing question,
    /// and the count of them is still bounded by the trait's default.
    fn table_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(true)
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

// Pure-types interfaces (no host functions) still generate empty `Host`
// traits via `bindgen!`. Implementing them on `HostState` satisfies the
// linker bound — there's nothing to actually implement.
impl crate::enclavid::policy::types::Host for HostState {}
impl crate::enclavid::shared_types::capture::Host for HostState {}
impl crate::enclavid::shared_types::disclosure::Host for HostState {}
// `enclavid:host/types::Host` + the three ref-resource destructors live
// in `embedded::host`, next to the resolvers that mint them.

#[cfg(test)]
mod tests {
    use super::AggregateMemory;
    use wasmtime::{Engine, Memory, MemoryType, Store, StoreLimits, StoreLimitsBuilder};

    /// What `memory_size` bounds, measured rather than read off a doc comment.
    ///
    /// `HostState::new` sets one cap and the store holds one limiter, which
    /// reads as a ceiling on the store. It is not: wasmtime consults the
    /// limiter once per linear memory and ignores the `current` argument, so
    /// every memory in the store may reach the cap on its own. A fused
    /// component is several core instances in one store, so the real ceiling
    /// multiplies by their number — and the plugin set is the consumer's to
    /// choose.
    ///
    /// Two host-created memories rather than a composed component: the
    /// multiplier comes from there being several memories, not from how they
    /// came to exist, and growth from the host goes through the same limiter.
    /// A wasmtime bump that made the cap aggregate would fail this, which is
    /// the point — it would quietly fix something this crate believes is broken.
    #[test]
    fn the_memory_cap_is_per_memory_and_not_per_store() {
        const PAGE: u64 = 64 * 1024;
        const CAP_PAGES: u64 = 16;
        const CAP: usize = (CAP_PAGES * PAGE) as usize;

        struct S {
            limits: StoreLimits,
        }

        let engine = Engine::default();
        let mut store = Store::new(
            &engine,
            S {
                limits: StoreLimitsBuilder::new().memory_size(CAP).build(),
            },
        );
        store.limiter(|s| &mut s.limits);

        let mut to_the_cap = |what: &str| {
            let mem = Memory::new(&mut store, MemoryType::new(1, None))
                .unwrap_or_else(|e| panic!("{what}: could not create a memory: {e}"));
            mem.grow(&mut store, CAP_PAGES - 1)
                .unwrap_or_else(|e| panic!("{what}: could not reach the cap: {e}"));
            assert_eq!(mem.size(&store), CAP_PAGES, "{what}: wrong size at the cap");
            // One page past it must fail, or the cap is not being applied and
            // the assertion above means nothing.
            assert!(
                mem.grow(&mut store, 1).is_err(),
                "{what}: grew past the cap, so nothing here is being limited"
            );
        };

        to_the_cap("first memory");
        to_the_cap("second memory");
        // Both reached CAP under a limiter configured with one CAP, so the
        // store now holds 2 x CAP.
    }

    /// And what `AggregateMemory` does instead: one budget, however many
    /// memories spend it.
    ///
    /// The second memory is the assertion. Under `StoreLimits` it reaches the
    /// ceiling on its own — that is the test above — so a store with N of them
    /// held N ceilings. Here the first one has already spent the budget.
    #[test]
    fn the_aggregate_limiter_charges_every_memory_to_one_budget() {
        const PAGE: u64 = 64 * 1024;
        const CAP_PAGES: u64 = 16;
        const CAP: usize = (CAP_PAGES * PAGE) as usize;

        struct S {
            limits: AggregateMemory,
        }

        let engine = Engine::default();
        let mut store = Store::new(
            &engine,
            S {
                limits: AggregateMemory::with_ceiling(CAP),
            },
        );
        store.limiter(|s| &mut s.limits);

        // One page of the budget goes on creation, so the first memory can
        // claim the rest and no more.
        let first = Memory::new(&mut store, MemoryType::new(1, None)).unwrap();
        first
            .grow(&mut store, CAP_PAGES - 1)
            .expect("the first memory should be able to spend the whole budget");
        assert_eq!(first.size(&store), CAP_PAGES);

        // Nothing left: a second memory cannot even be created, let alone grow.
        assert!(
            Memory::new(&mut store, MemoryType::new(1, None)).is_err(),
            "a second memory was created after the budget was spent — the charge \
             is still per-memory"
        );

        // Nor can the first grow further.
        assert!(first.grow(&mut store, 1).is_err());
    }
}
