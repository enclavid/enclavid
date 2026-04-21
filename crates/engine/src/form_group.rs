use enclavid_session_store::{
    capture_item as proto_capture_item, suspended, CaptureGroup as ProtoCaptureGroup,
    CaptureItem as ProtoCaptureItem, DriversLicense as ProtoDriversLicense, IdCard as ProtoIdCard,
    Liveness as ProtoLiveness, LivenessMode, Passport as ProtoPassport,
};

use crate::enclavid::form::biometrics::{LivenessData, LivenessParams};
use crate::enclavid::form::form_group::{AllOf, GroupParams, GroupResult, Host};
use crate::host_state::HostState;

impl Host for HostState {
    async fn prompt_any_of(
        &mut self,
        any_of: Vec<AllOf>,
    ) -> wasmtime::Result<Vec<GroupResult>> {
        let data = self
            .replay
            .current_suspended()
            .and_then(|s| s.request.as_ref())
            .and_then(|r| match r {
                suspended::Request::VerificationSet(vs) => vs.data.as_ref(),
                _ => None,
            });

        if let Some(data) = data {
            let results = data
                .items
                .iter()
                .map(item_to_wit)
                .collect::<wasmtime::Result<Vec<_>>>()?;
            return Ok(results);
        }

        let proto_any_of = any_of.into_iter().map(group_to_proto).collect();
        Err(suspended::Request::verification_set(proto_any_of).into())
    }
}

fn group_to_proto(g: AllOf) -> ProtoCaptureGroup {
    ProtoCaptureGroup {
        items: g.items.into_iter().map(param_to_proto).collect(),
    }
}

fn param_to_proto(item: GroupParams) -> ProtoCaptureItem {
    let item = match item {
        GroupParams::Passport => proto_capture_item::Item::Passport(ProtoPassport { image: None }),
        GroupParams::IdCard => proto_capture_item::Item::IdCard(ProtoIdCard { images: None }),
        GroupParams::DriversLicense => {
            proto_capture_item::Item::DriversLicense(ProtoDriversLicense { images: None })
        }
        GroupParams::Liveness(p) => {
            let mode = match p {
                LivenessParams::SelfieVideo => LivenessMode::SelfieVideo,
            };
            proto_capture_item::Item::Liveness(ProtoLiveness { mode: mode as i32, frames: None })
        }
    };
    ProtoCaptureItem { item: Some(item) }
}

fn item_to_wit(item: &ProtoCaptureItem) -> wasmtime::Result<GroupResult> {
    let Some(item) = item.item.as_ref() else {
        return Err(wasmtime::Error::msg("verification-set item has no kind"));
    };
    match item {
        proto_capture_item::Item::Passport(p) => match &p.image {
            Some(bytes) => Ok(GroupResult::Passport(bytes.clone())),
            None => Err(wasmtime::Error::msg("verification-set passport missing image")),
        },
        proto_capture_item::Item::IdCard(c) => match &c.images {
            Some(img) => Ok(GroupResult::IdCard((img.front.clone(), img.back.clone()))),
            None => Err(wasmtime::Error::msg("verification-set id_card missing images")),
        },
        proto_capture_item::Item::DriversLicense(c) => match &c.images {
            Some(img) => Ok(GroupResult::DriversLicense((img.front.clone(), img.back.clone()))),
            None => Err(wasmtime::Error::msg("verification-set drivers_license missing images")),
        },
        proto_capture_item::Item::Liveness(l) => match &l.frames {
            Some(f) => Ok(GroupResult::Liveness(LivenessData::SelfieVideo(f.frames.clone()))),
            None => Err(wasmtime::Error::msg("verification-set liveness missing frames")),
        },
    }
}
