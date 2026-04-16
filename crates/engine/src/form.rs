use crate::enclavid::form::form::{Host, Image};
use crate::suspend::{MediaRequest, Suspend};
use enclavid_session_store::SessionState;

impl Host for SessionState {
    fn capture_passport(&mut self) -> wasmtime::Result<Image> {
        self.passport
            .clone()
            .ok_or_else(|| Suspend { request: MediaRequest::Passport }.into())
    }

    fn capture_id_card(&mut self) -> wasmtime::Result<(Image, Image)> {
        self.id_card
            .as_ref()
            .map(|d| (d.front.clone(), d.back.clone()))
            .ok_or_else(|| Suspend { request: MediaRequest::IdCard }.into())
    }

    fn capture_drivers_license(&mut self) -> wasmtime::Result<(Image, Image)> {
        self.drivers_license
            .as_ref()
            .map(|d| (d.front.clone(), d.back.clone()))
            .ok_or_else(|| Suspend { request: MediaRequest::DriversLicense }.into())
    }

    fn capture_liveness(&mut self) -> wasmtime::Result<Vec<Image>> {
        if self.liveness_frames.is_empty() {
            Err(Suspend { request: MediaRequest::Liveness }.into())
        } else {
            Ok(self.liveness_frames.clone())
        }
    }
}
