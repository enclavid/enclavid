//! `photo`: the capture specs of the documents and a selfie.

use crate::WellKnown;
use crate::enclavid::host::refs::IconRef;
use crate::enclavid::host_capture::capture::{CameraFacing, CaptureKind, CaptureStep, MediaSpec};
use crate::enclavid::host_capture::photo::{FaceGuide, Guide, PhotoSpec, Shape, ShapeGuide};
use crate::enclavid::host_icons::icons;
use crate::enclavid_ext::well_known::i18n::{Key, localized};
use crate::exports::enclavid::well_known::photo::Guest;
use crate::shapes::{CARD_FRAME, PASSPORT_FRAME, SELFIE_WIDTH};

/// The texts of a document's capture step.
struct StepTexts {
    instructions: Key,
    label: Key,
    guide_label: Key,
    review_hint: Key,
}

/// Build a document's photo step, in `shape` on the rear camera, minting its
/// texts through the host.
fn document_step(texts: StepTexts, icon: IconRef, shape: Shape) -> CaptureStep {
    CaptureStep {
        icon: Some(icon),
        instructions: localized(texts.instructions),
        label: localized(texts.label),
        camera: CameraFacing::Rear,
        kind: CaptureKind::Photo(PhotoSpec {
            guide: Some(Guide::Shape(ShapeGuide {
                shape,
                label: localized(texts.guide_label),
            })),
            review_hint: Some(localized(texts.review_hint)),
        }),
    }
}

fn passport_step() -> CaptureStep {
    document_step(
        StepTexts {
            instructions: Key::PassportInstructions,
            label: Key::PassportStep,
            guide_label: Key::PassportGuide,
            review_hint: Key::PassportReviewHint,
        },
        icons::passport(),
        PASSPORT_FRAME,
    )
}

fn id_card_front_step_inner() -> CaptureStep {
    document_step(
        StepTexts {
            instructions: Key::IdCardFrontInstructions,
            label: Key::IdCardFrontStep,
            guide_label: Key::IdCardFrontGuide,
            review_hint: Key::IdCardFrontReviewHint,
        },
        icons::id_card(),
        CARD_FRAME,
    )
}

fn id_card_back_step_inner() -> CaptureStep {
    document_step(
        StepTexts {
            instructions: Key::IdCardBackInstructions,
            label: Key::IdCardBackStep,
            guide_label: Key::IdCardBackGuide,
            review_hint: Key::IdCardBackReviewHint,
        },
        icons::id_card(),
        CARD_FRAME,
    )
}

fn drivers_license_front_step_inner() -> CaptureStep {
    document_step(
        StepTexts {
            instructions: Key::DriversLicenseFrontInstructions,
            label: Key::DriversLicenseFrontStep,
            guide_label: Key::DriversLicenseFrontGuide,
            review_hint: Key::DriversLicenseFrontReviewHint,
        },
        icons::drivers_license(),
        CARD_FRAME,
    )
}

fn drivers_license_back_step_inner() -> CaptureStep {
    document_step(
        StepTexts {
            instructions: Key::DriversLicenseBackInstructions,
            label: Key::DriversLicenseBackStep,
            guide_label: Key::DriversLicenseBackGuide,
            review_hint: Key::DriversLicenseBackReviewHint,
        },
        icons::drivers_license(),
        CARD_FRAME,
    )
}

/// A selfie the page takes once the face fills its oval, kept or taken again
/// on a review screen.
fn selfie_step_inner() -> CaptureStep {
    CaptureStep {
        icon: Some(icons::selfie()),
        instructions: localized(Key::SelfieInstructions),
        label: localized(Key::SelfieStep),
        camera: CameraFacing::Front,
        kind: CaptureKind::Photo(PhotoSpec {
            guide: Some(Guide::Face(FaceGuide {
                width: SELFIE_WIDTH,
            })),
            review_hint: Some(localized(Key::SelfieReviewHint)),
        }),
    }
}

impl Guest for WellKnown {
    fn passport() -> MediaSpec {
        MediaSpec {
            label: localized(Key::PassportTitle),
            captures: vec![passport_step()],
            time_limit_secs: None,
        }
    }

    fn id_card() -> MediaSpec {
        MediaSpec {
            label: localized(Key::IdCardTitle),
            captures: vec![id_card_front_step_inner(), id_card_back_step_inner()],
            time_limit_secs: None,
        }
    }

    fn drivers_license() -> MediaSpec {
        MediaSpec {
            label: localized(Key::DriversLicenseTitle),
            captures: vec![
                drivers_license_front_step_inner(),
                drivers_license_back_step_inner(),
            ],
            time_limit_secs: None,
        }
    }

    fn selfie() -> MediaSpec {
        MediaSpec {
            label: localized(Key::SelfieTitle),
            captures: vec![selfie_step_inner()],
            time_limit_secs: None,
        }
    }

    fn id_card_front_step() -> CaptureStep {
        id_card_front_step_inner()
    }
    fn id_card_back_step() -> CaptureStep {
        id_card_back_step_inner()
    }
    fn drivers_license_front_step() -> CaptureStep {
        drivers_license_front_step_inner()
    }
    fn drivers_license_back_step() -> CaptureStep {
        drivers_license_back_step_inner()
    }
}
