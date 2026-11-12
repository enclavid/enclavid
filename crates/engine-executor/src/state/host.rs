use std::sync::Arc;

use engine_types::picture::PictureBounds;
use wasmtime::component::{ResourceTable, Val};

use crate::embedded::EmbeddedRegistry;
use crate::image::{Decodes, MediaStarter};
use crate::listener::SessionListener;
use crate::media_store::MediaStore;
use crate::models::{ModelStarter, Started};
use crate::round::Round;

/// Data placed into wasmtime `Store<HostState>` for the duration of one
/// `handle` call. The policy is a pure reducer, so this state carries
/// only ambient read surfaces (the session's props, the
/// `enclavid:embedded/*` registry, the round's time and randomness) plus
/// the runtime plumbing (the media store, the processes of the models and of
/// the captures' decoding). No replay log, no per-call disclosure buffer — the
/// runner fires the listener once the round is over, not from a host-fn body.
///
/// No memory limiter either. What the round may hold — its linear
/// memories and everything else in its process — is the kernel's to hold it
/// to (the composition's max, `admission::DEFAULT_COMPOSITION_MAX_BYTES`);
/// fuel is set on the Store directly.
pub struct HostState {
    /// The props the consumer gave the session, as the type the policy
    /// declares for them, which `enclavid-ext:policy/props.get`
    /// returns. Constant for the session; the policy may read it any round.
    /// `None` for a policy that declares none.
    pub props: Option<Val>,
    /// Per-composition embedded registry — one frozen index built from the
    /// policy's and every fused plugin's embedded sections. The embedded
    /// host fns resolve a key against it (first match across the catalogs
    /// for a disclosure field, or against the one catalog a component's
    /// slot names for a text) and MINT a ref resource into [`table`](Self::
    /// table) carrying the resolved data. Frozen before any per-session
    /// input reaches the component; a component can only reference a key
    /// some catalog declared.
    pub embedded: Arc<EmbeddedRegistry>,
    /// Handle table backing the host-owned ref resources
    /// (`localized-ref` / `icon-ref` / `disclosure-field-ref`) and the media
    /// resources (`photo` / `video`, and their pictures' `image`s). The
    /// host funcs push resolved data / captures here and hand the component
    /// an unforgeable handle; the runner dereferences the ref handles the
    /// returned prompt carries at the action boundary. Fresh per run, dropped
    /// with the Store — handles never outlive the round.
    pub table: ResourceTable,
    /// Host-side sealed capture store, injected by the runtime's I/O layer.
    /// Backs the media constructors — the policy rehydrates a stored capture
    /// by its content hash mid-`handle`. `Arc<dyn>` so the host fn can clone
    /// it out before the `.await` (releasing the borrow of `self`).
    pub media_store: Arc<dyn MediaStore>,
    /// Where the composition's models run — what a slot's model function
    /// has started the first time the round calls it.
    pub models: Arc<dyn ModelStarter>,
    /// The models the round has started, each once.
    pub(crate) started: Started,
    /// Where the round's captures are decoded — what `photo.image` and
    /// `video.frames` start, once a capture.
    pub media: Arc<dyn MediaStarter>,
    /// What the pictures of the round's captures, and the regions read of
    /// them, are held to.
    pub(crate) picture_bounds: PictureBounds,
    /// The captures the round decodes, each as its open found it, and the
    /// socket to the process decoding it.
    pub(crate) decodes: Decodes,
    /// The WASI the round is served: its clocks, its random streams, and the
    /// empty rest. See [`crate::round`].
    pub round: Round,
}

/// Per-run inputs handed to [`Executor::run`](crate::Executor::run) once per
/// round. The composition-wide `EmbeddedRegistry` is NOT here — it is
/// immutable across a composition's rounds, so it is built into the
/// [`PrimedComposition`](crate::PrimedComposition) at
/// [`prime`](crate::Executor::prime) time and read from there.
pub struct RunInputs {
    /// Ties this run to the caller's persistence layer.
    pub listener: Arc<dyn SessionListener>,
    /// Rehydrates stored captures.
    pub media_store: Arc<dyn MediaStore>,
    /// Starts the processes the composition's models run in.
    pub models: Arc<dyn ModelStarter>,
    /// Starts the processes the round's captures are decoded in.
    pub media: Arc<dyn MediaStarter>,
    /// The fuel the round may burn:
    /// [`DEFAULT_ROUND_FUEL`](crate::DEFAULT_ROUND_FUEL) unless the host says
    /// otherwise.
    pub fuel: u64,
    /// What the pictures of the round's captures are held to:
    /// [`PictureBounds::DEFAULT`] unless the host says otherwise.
    pub picture_bounds: PictureBounds,
}

impl HostState {
    pub(crate) fn new(
        props: Option<Val>,
        embedded: Arc<EmbeddedRegistry>,
        media_store: Arc<dyn MediaStore>,
        models: Arc<dyn ModelStarter>,
        media: Arc<dyn MediaStarter>,
        picture_bounds: PictureBounds,
        round: Round,
    ) -> Self {
        Self {
            props,
            embedded,
            table: ResourceTable::new(),
            media_store,
            models,
            started: Started::default(),
            media,
            picture_bounds,
            decodes: Decodes::default(),
            round,
        }
    }
}

impl crate::enclavid::host_capture::constants::Host for HostState {
    async fn oval_aspect(&mut self) -> wasmtime::Result<f32> {
        Ok(crate::limits::GUIDE_OVAL_ASPECT)
    }
}

// Pure-types interfaces (no host functions) still generate empty `Host`
// traits via `bindgen!`. Implementing them on `HostState` satisfies the
// linker bound — there's nothing to actually implement.
impl crate::enclavid::policy::types::Host for HostState {}
impl crate::enclavid::host_capture::capture::Host for HostState {}
impl crate::enclavid::host_capture::photo::Host for HostState {}
impl crate::enclavid::host_capture::video::Host for HostState {}
impl crate::enclavid::host_disclosure::disclosure::Host for HostState {}
// `enclavid:host/refs::Host` + the three ref-resource destructors live
// in `embedded::host`, next to the resolvers that mint them.
