use crate::enclavid::disclosure::disclosure::Host;
use enclavid_session_store::SessionState;

impl Host for SessionState {
    fn request_disclosure(
        &mut self,
        _fields: Vec<crate::enclavid::disclosure::disclosure::DisplayField>,
    ) -> wasmtime::Result<bool> {
        // TODO: yield to client, show consent UI, wait for response
        // For now: auto-approve
        Ok(true)
    }
}
