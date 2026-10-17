use std::sync::Arc;

use wasmtime::component::{ResourceTable, Val};

use crate::embedded::EmbeddedRegistry;
use crate::listener::SessionListener;
use crate::media_store::MediaStore;
use crate::round::Round;

/// Data placed into wasmtime `Store<HostState>` for the duration of one
/// `handle` call. The policy is a pure reducer, so this state carries
/// only ambient read surfaces (the session's props, the
/// `enclavid:embedded/*` registry, the round's time and randomness) plus
/// the runtime plumbing (the media store). No replay log, no per-call
/// disclosure buffer — the
/// runner fires the listener once the round is over, not from a
/// host-fn body.
///
/// No memory limiter either. What the round may hold — its linear
/// memories and everything else in its process — is the kernel's to
/// hold it to (the round's max, `admission::DEFAULT_ROUND_MAX_BYTES`); fuel
/// is set on the Store directly.
pub struct HostState {
    /// The props the consumer gave the session, as the type the policy
    /// declares for them, which `enclavid:host-ext/policy-props.get`
    /// returns. Constant for the session; the policy may read it any round.
    /// `None` for a policy that declares none.
    pub props: Option<Val>,
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
    /// The WASI the round is served: its clocks, its random stream, and the
    /// empty rest. See [`crate::round`].
    pub round: Round,
}

/// Per-run inputs handed to [`Executor::run`](crate::Executor::run) once per
/// round: the `listener` that ties this run to the caller's persistence layer,
/// the `media_store` that rehydrates stored blobs, the `fuel` the round may
/// burn ([`DEFAULT_ROUND_FUEL`](crate::DEFAULT_ROUND_FUEL) unless the host says
/// otherwise), and the `seed` its randomness is drawn from. The
/// composition-wide `EmbeddedRegistry` is NOT here — it is immutable across a
/// composition's rounds, so it is built into the
/// [`PrimedComposition`](crate::PrimedComposition) at
/// [`prime`](crate::Executor::prime) time and read from there.
pub struct RunInputs {
    pub listener: Arc<dyn SessionListener>,
    pub media_store: Arc<dyn MediaStore>,
    pub fuel: u64,
    /// What api derived for this session and round; see [`crate::round`].
    pub seed: [u8; 32],
}

impl HostState {
    pub(crate) fn new(
        props: Option<Val>,
        embedded: Arc<EmbeddedRegistry>,
        media_store: Arc<dyn MediaStore>,
        round: Round,
    ) -> Self {
        Self {
            props,
            embedded,
            table: ResourceTable::new(),
            media_store,
            round,
        }
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
