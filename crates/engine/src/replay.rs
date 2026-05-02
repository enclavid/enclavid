use serde::de::DeserializeOwned;
use serde::Serialize;

use enclavid_host_bridge::{
    call_event, suspended, CallEvent, Completed, SessionState, Suspended,
};

/// Replay/record state for the intercept protocol. Walks the session event
/// log forward, returning cached results on Completed hits and yielding to
/// host-function bodies on Suspended/past-end. Strictly forward-only —
/// construct fresh from a persisted `SessionState` each run.
pub struct Replay {
    session: SessionState,
    cursor: usize,
}

/// Describes one host call — the key by which the replay log identifies it.
/// Built by the caller (shim) once, passed to both `next` and `write`.
pub struct CallRequest {
    pub fn_name: String,
    pub args_hash: Vec<u8>,
}

/// Reponse of `next`: cache hit returns the decoded value; otherwise the
/// body must run and be finalized with `write` (passing the same request).
pub enum CallResponse<R> {
    Cached(R),
    Live,
}

impl Replay {
    pub(crate) fn new(session: SessionState) -> Self {
        Self { session, cursor: 0 }
    }

    pub(crate) fn into_session(self) -> SessionState {
        self.session
    }

    /// Advance the call stream by one step. Completed cache hit advances the
    /// cursor and returns `Cached(value)`. Anything else (Suspended status,
    /// absent status, past end of log) returns `Live` — body must run, and
    /// `write` will finalize + advance the cursor atomically.
    pub fn next<R: DeserializeOwned>(
        &mut self,
        req: &CallRequest,
    ) -> wasmtime::Result<CallResponse<R>> {
        let idx = self.cursor;

        if let Some(ev) = self.session.events.get(idx) {
            if ev.fn_name != req.fn_name {
                return Err(wasmtime::Error::msg(format!(
                    "replay divergence: expected fn {}, got {}",
                    ev.fn_name, req.fn_name
                )));
            }
            if ev.args_hash != req.args_hash {
                return Err(wasmtime::Error::msg(format!(
                    "replay divergence: args_hash mismatch for {}",
                    req.fn_name
                )));
            }
            if let Some(call_event::Status::Completed(c)) = &ev.status {
                let decoded = bincode::deserialize(&c.result).map_err(wasmtime::Error::from)?;
                self.cursor += 1;
                return Ok(CallResponse::Cached(decoded));
            }
        }

        debug_assert!(idx <= self.session.events.len());
        Ok(CallResponse::Live)
    }

    /// Returns the Suspended record at the current cursor, if the event
    /// exists and is Suspended. Used by host-function bodies to read typed
    /// user response data the API attached between rounds.
    pub fn current_suspended(&self) -> Option<&Suspended> {
        self.session
            .events
            .get(self.cursor)
            .and_then(|ev| ev.status.as_ref())
            .and_then(|s| match s {
                call_event::Status::Suspended(sus) => Some(sus),
                _ => None,
            })
    }

    /// The pending suspension request for this session, if any. Suspended
    /// status can only appear at the last event (a suspend terminates the
    /// run), so we check just that slot. Used by `Runner` to distinguish
    /// our suspend-signalling trap from a real bug-trap.
    pub fn pending(&self) -> Option<&suspended::Request> {
        match self.session.events.last()?.status.as_ref()? {
            call_event::Status::Suspended(s) => s.request.as_ref(),
            _ => None,
        }
    }

    /// Write the response of the current live call to the log. On Ok: stores
    /// Completed, replacing any Suspended-in-place (resume) or appending a
    /// fresh event (past-end). On Err(Suspended): stores Suspended (new
    /// request, data cleared). Advances the cursor. A non-Suspend Err leaves
    /// state unchanged and propagates the trap to end the run.
    pub fn write<R: Serialize>(
        &mut self,
        req: CallRequest,
        result: &wasmtime::Result<R>,
    ) -> wasmtime::Result<()> {
        let status = match result {
            Ok(r) => {
                let bytes = bincode::serialize(r).map_err(wasmtime::Error::from)?;
                call_event::Status::Completed(Completed { result: bytes })
            }
            Err(e) => match e.downcast_ref::<suspended::Request>() {
                Some(sreq) => call_event::Status::Suspended(Suspended {
                    request: Some(sreq.clone()),
                }),
                None => return Ok(()),
            },
        };

        let idx = self.cursor;
        if idx < self.session.events.len() {
            // In-place transition: Suspended → Completed, or Suspended → new Suspended.
            // fn_name / args_hash validated equal in `next`; preserved here.
            self.session.events[idx].status = Some(status);
        } else {
            debug_assert_eq!(idx, self.session.events.len());
            self.session.events.push(CallEvent {
                fn_name: req.fn_name,
                args_hash: req.args_hash,
                status: Some(status),
            });
        }
        self.cursor += 1;
        Ok(())
    }
}

/// Hash args for event args_hash field.
pub fn hash_args<A: Serialize>(args: &A) -> wasmtime::Result<Vec<u8>> {
    let bytes = bincode::serialize(args).map_err(wasmtime::Error::from)?;
    Ok(blake3::hash(&bytes).as_bytes().to_vec())
}
