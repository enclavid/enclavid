//! JSON-serializable view types and converters for the run-triggering
//! handlers (`/connect`, `/input`). Keep purely data-shape — no I/O, no
//! AppState. Everything here is used by both connect.rs and input.rs.

use serde::Serialize;

use enclavid_engine::policy::Decision;
use enclavid_engine::RunStatus;
use enclavid_host_bridge::{
    biometric_request, capture_item, document_request, suspended, CaptureItem, DisplayField,
    LivenessMode,
};

/// Response for run-triggering endpoints (`init`, `input`). Internally-tagged
/// enum — the `status` field carries the variant discriminator, other fields
/// carry variant-specific payload.
#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SessionProgress {
    Completed { decision: DecisionView },
    AwaitingInput { request: RequestView },
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionView {
    Approved,
    Rejected,
    RejectedRetryable,
    Review,
}

/// JSON-friendly view of a pending suspension request. Mirrors the proto
/// `suspended::Request` variants but in a shape the frontend can consume
/// without prost decoding.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RequestView {
    Passport,
    IdCard,
    DriversLicense,
    Liveness { mode: LivenessModeView },
    Consent { fields: Vec<DisplayFieldView> },
    VerificationSet { alternatives: Vec<Vec<CaptureItemView>> },
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LivenessModeView {
    SelfieVideo,
    Unknown,
}

#[derive(Serialize)]
pub struct DisplayFieldView {
    pub label: String,
    pub value: String,
}

/// CaptureItem with data fields stripped — only the "ask" shape, for
/// rendering alternatives in verification-set flows.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CaptureItemView {
    Passport,
    IdCard,
    DriversLicense,
    Liveness { mode: LivenessModeView },
}

pub(super) fn progress_from(status: RunStatus) -> SessionProgress {
    match status {
        RunStatus::Completed(decision) => SessionProgress::Completed {
            decision: decision_view(decision),
        },
        RunStatus::Suspended(req) => SessionProgress::AwaitingInput {
            request: request_view(&req),
        },
    }
}

fn decision_view(d: Decision) -> DecisionView {
    match d {
        Decision::Approved => DecisionView::Approved,
        Decision::Rejected => DecisionView::Rejected,
        Decision::RejectedRetryable => DecisionView::RejectedRetryable,
        Decision::Review => DecisionView::Review,
    }
}

fn request_view(req: &suspended::Request) -> RequestView {
    match req {
        suspended::Request::Document(doc) => match doc.kind.as_ref() {
            Some(document_request::Kind::Passport(_)) => RequestView::Passport,
            Some(document_request::Kind::IdCard(_)) => RequestView::IdCard,
            Some(document_request::Kind::DriversLicense(_)) => RequestView::DriversLicense,
            None => RequestView::Passport, // unreachable under normal flow
        },
        suspended::Request::Biometric(bio) => match bio.kind.as_ref() {
            Some(biometric_request::Kind::Liveness(l)) => RequestView::Liveness {
                mode: liveness_mode_view(l.mode),
            },
            None => RequestView::Liveness { mode: LivenessModeView::Unknown },
        },
        suspended::Request::Consent(c) => RequestView::Consent {
            fields: c.fields.iter().map(display_field_view).collect(),
        },
        suspended::Request::VerificationSet(vs) => RequestView::VerificationSet {
            alternatives: vs
                .alternatives
                .iter()
                .map(|g| g.items.iter().map(capture_item_view).collect())
                .collect(),
        },
    }
}

fn liveness_mode_view(mode: i32) -> LivenessModeView {
    if mode == LivenessMode::SelfieVideo as i32 {
        LivenessModeView::SelfieVideo
    } else {
        LivenessModeView::Unknown
    }
}

fn display_field_view(f: &DisplayField) -> DisplayFieldView {
    DisplayFieldView {
        label: f.label.clone(),
        value: f.value.clone(),
    }
}

fn capture_item_view(item: &CaptureItem) -> CaptureItemView {
    match item.item.as_ref() {
        Some(capture_item::Item::Passport(_)) => CaptureItemView::Passport,
        Some(capture_item::Item::IdCard(_)) => CaptureItemView::IdCard,
        Some(capture_item::Item::DriversLicense(_)) => CaptureItemView::DriversLicense,
        Some(capture_item::Item::Liveness(l)) => CaptureItemView::Liveness {
            mode: liveness_mode_view(l.mode),
        },
        None => CaptureItemView::Passport, // unreachable under normal flow
    }
}
