use enclavid_session_store::{biometric_request, suspended, LivenessMode};

use crate::enclavid::form::biometrics::{Host, LivenessData, LivenessParams};
use crate::host_state::HostState;

impl Host for HostState {
    async fn prompt_liveness(
        &mut self,
        _params: LivenessParams,
    ) -> wasmtime::Result<LivenessData> {
        let kind = self
            .replay
            .current_suspended()
            .and_then(|s| s.request.as_ref())
            .and_then(|r| match r {
                suspended::Request::Biometric(bio) => bio.kind.as_ref(),
                _ => None,
            });

        match kind {
            Some(biometric_request::Kind::Liveness(l)) => match &l.frames {
                Some(f) => Ok(LivenessData::SelfieVideo(f.frames.clone())),
                None => Err(suspended::Request::liveness(LivenessMode::SelfieVideo).into()),
            },
            None => Err(suspended::Request::liveness(LivenessMode::SelfieVideo).into()),
        }
    }
}
