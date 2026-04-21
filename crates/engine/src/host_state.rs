use enclavid_session_store::{DisclosureStore, SessionState};

use crate::replay::Replay;

/// Data placed into wasmtime `Store<HostState>` for the duration of one run.
/// Owns the replay machinery and per-session handles that host functions
/// need (stores, identifiers, keys). Constructed fresh at each run start,
/// consumed back into `SessionState` at run end.
pub struct HostState {
    pub replay: Replay,
    pub disclosure_store: DisclosureStore,
    pub session_id: String,
    pub client_pk: Vec<u8>,
}

/// Per-run resources assembled by `Runner` and handed to `HostState`.
pub struct HostResources {
    pub disclosure_store: DisclosureStore,
    pub session_id: String,
    pub client_pk: Vec<u8>,
}

impl HostState {
    pub(crate) fn new(session: SessionState, resources: HostResources) -> Self {
        Self {
            replay: Replay::new(session),
            disclosure_store: resources.disclosure_store,
            session_id: resources.session_id,
            client_pk: resources.client_pk,
        }
    }

    pub(crate) fn into_session(self) -> SessionState {
        self.replay.into_session()
    }
}
