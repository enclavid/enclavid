use std::sync::Arc;

use enclavid_host_bridge::SessionState;

use crate::listener::SessionListener;
use crate::replay::Replay;

/// Data placed into wasmtime `Store<HostState>` for the duration of
/// one run. Owns the replay machinery, the per-call disclosure buffer,
/// and the listener.
///
/// Engine never talks to the host and holds no keys: every committed
/// CallEvent fires `SessionListener::on_session_change`, the listener (api
/// crate) does whatever encryption + persistence the destination
/// requires (`tee_key`/`applicant_key` AEAD for state via the bridge;
/// `client_pk` age-encrypt for disclosures inside the listener
/// itself). Symmetric with how state and metadata are already sealed
/// transparently inside host-bridge.
pub struct HostState {
    pub replay: Replay,
    /// Disclosure entries staged during the current host call body.
    /// Plaintext payloads (encoded `ConsentRequest`) — listener seals
    /// them to the recipient pubkey before persisting. Drained and
    /// handed to the listener after each successful event commit;
    /// per-call lifetime, never accumulated across calls.
    pub pending_disclosures: Vec<Vec<u8>>,
    /// Hook fired after each committed CallEvent. Stored as Arc so the
    /// shim can clone it cheaply across the await point that calls it.
    pub listener: Arc<dyn SessionListener>,
}

/// Per-run resources assembled by the api crate and handed to
/// `HostState`. Carries the listener that ties this run to the
/// caller's persistence layer.
pub struct HostResources {
    pub listener: Arc<dyn SessionListener>,
}

impl HostState {
    pub(crate) fn new(session: SessionState, resources: HostResources) -> Self {
        Self {
            replay: Replay::new(session),
            pending_disclosures: Vec::new(),
            listener: resources.listener,
        }
    }

    pub(crate) fn into_session(self) -> SessionState {
        self.replay.into_session()
    }
}
