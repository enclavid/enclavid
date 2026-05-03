use enclavid_host_bridge::{AppendDisclosure, SessionState};

use crate::replay::Replay;

/// Data placed into wasmtime `Store<HostState>` for the duration of
/// one run. Owns the replay machinery and per-session handles that
/// host functions need (identifiers, keys, pending disclosure
/// buffer). Constructed fresh at each run start; consumed back into
/// `(SessionState, pending disclosures)` at run end.
///
/// Engine never talks to the host directly — it stages all
/// would-be-host-side effects into in-memory buffers (today: pending
/// disclosure list). The API harvests them after the run and merges
/// into the next `SessionStore::commit` call so state + disclosures
/// publish atomically.
pub struct HostState {
    pub replay: Replay,
    /// Client-disclosure recipient pubkey. Used by `prompt_disclosure`
    /// to age-encrypt entries before staging them in
    /// `pending_disclosures`. Engine doesn't otherwise touch this.
    pub client_pk: Vec<u8>,
    /// Disclosure entries staged by `prompt_disclosure` during this
    /// run. Already age-encrypted to `client_pk` (encryption is the
    /// engine's responsibility — the host only stores opaque bytes).
    /// Drained by `Runner::run` and returned alongside the updated
    /// SessionState.
    pub pending_disclosures: Vec<AppendDisclosure>,
}

/// Per-run resources assembled by `Runner` and handed to `HostState`.
/// No host-bridge handle: the engine doesn't write anywhere on its own.
pub struct HostResources {
    pub client_pk: Vec<u8>,
}

impl HostState {
    pub(crate) fn new(session: SessionState, resources: HostResources) -> Self {
        Self {
            replay: Replay::new(session),
            client_pk: resources.client_pk,
            pending_disclosures: Vec::new(),
        }
    }

    pub(crate) fn into_parts(self) -> (SessionState, Vec<AppendDisclosure>) {
        (self.replay.into_session(), self.pending_disclosures)
    }
}
