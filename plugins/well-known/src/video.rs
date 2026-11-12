//! `video`: the liveness video's capture spec.

use crate::WellKnown;
use crate::enclavid::host_capture::capture::{CameraFacing, CaptureKind, CaptureStep, MediaSpec};
use crate::enclavid::host_capture::video::{Guide, VideoSpec};
use crate::enclavid::host_icons::icons;
use crate::enclavid_ext::well_known::i18n::{Key, localized};
use crate::exports::enclavid::well_known::video::Guest;

/// The seconds a liveness video's guides are given together.
const LIVENESS_TIME_LIMIT_SECS: u16 = 60;

impl Guest for WellKnown {
    fn liveness(guides: Vec<Guide>) -> MediaSpec {
        MediaSpec {
            label: localized(Key::LivenessTitle),
            captures: vec![CaptureStep {
                icon: Some(icons::selfie()),
                instructions: localized(Key::LivenessInstructions),
                label: localized(Key::LivenessStep),
                camera: CameraFacing::Front,
                kind: CaptureKind::Video(VideoSpec { guides }),
            }],
            time_limit_secs: Some(LIVENESS_TIME_LIMIT_SECS),
        }
    }
}
