use enclavid_session_store::{document_request, suspended};

use crate::enclavid::form::documents::{Host, Image};
use crate::host_state::HostState;

impl Host for HostState {
    async fn prompt_passport(&mut self) -> wasmtime::Result<Image> {
        match document_kind(self)? {
            Some(document_request::Kind::Passport(p)) => match &p.image {
                Some(bytes) => Ok(bytes.clone()),
                None => Err(suspended::Request::passport().into()),
            },
            Some(_) => Err(wasmtime::Error::msg("document kind mismatch")),
            None => Err(suspended::Request::passport().into()),
        }
    }

    async fn prompt_id_card(&mut self) -> wasmtime::Result<(Image, Image)> {
        match document_kind(self)? {
            Some(document_request::Kind::IdCard(c)) => match &c.images {
                Some(img) => Ok((img.front.clone(), img.back.clone())),
                None => Err(suspended::Request::id_card().into()),
            },
            Some(_) => Err(wasmtime::Error::msg("document kind mismatch")),
            None => Err(suspended::Request::id_card().into()),
        }
    }

    async fn prompt_drivers_license(&mut self) -> wasmtime::Result<(Image, Image)> {
        match document_kind(self)? {
            Some(document_request::Kind::DriversLicense(c)) => match &c.images {
                Some(img) => Ok((img.front.clone(), img.back.clone())),
                None => Err(suspended::Request::drivers_license().into()),
            },
            Some(_) => Err(wasmtime::Error::msg("document kind mismatch")),
            None => Err(suspended::Request::drivers_license().into()),
        }
    }
}

fn document_kind(state: &HostState) -> wasmtime::Result<Option<&document_request::Kind>> {
    let Some(sus) = state.replay.current_suspended() else {
        return Ok(None);
    };
    let Some(suspended::Request::Document(doc)) = sus.request.as_ref() else {
        return Err(wasmtime::Error::msg(
            "prompt-document called while non-document request is suspended",
        ));
    };
    Ok(doc.kind.as_ref())
}
