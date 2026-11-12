//! `video-guides`: ready sets of video guides, of the values [`sets`] draws.

use crate::WellKnown;
use crate::enclavid::host_capture::video::{
    FaceFlashesGuide, FaceGuide, Guide, HeadTurnGuide, Rgb,
};
use crate::exports::enclavid::well_known::video_guides::Guest;
use crate::sets;

/// How long the face is held in its oval, in milliseconds.
const FACE_HOLD_MS: u16 = 800;
/// How long each colour is flashed, in milliseconds.
const FLASH_MS: u16 = 300;
/// How long a turn of the head is held, in milliseconds.
const TURN_HOLD_MS: u16 = 500;
/// The longest break in a guide's hold the page forgives, in milliseconds.
const GRACE_MS: u16 = 300;

impl Guest for WellKnown {
    fn liveness_turns(seed: u32) -> Vec<Guide> {
        let sets::Turns { width, turns } = sets::turns(seed);
        let mut guides = vec![face(width)];
        guides.extend(turns.map(|degrees| {
            Guide::HeadTurn(HeadTurnGuide {
                degrees,
                hold_ms: TURN_HOLD_MS,
                grace_ms: GRACE_MS,
            })
        }));
        guides
    }

    fn liveness_colors(seed: u32) -> Vec<Guide> {
        let sets::Colors { width, colors } = sets::colors(seed);
        let colors = colors
            .into_iter()
            .map(|(red, green, blue)| Rgb { red, green, blue })
            .collect();
        vec![
            face(width),
            Guide::FaceFlashes(FaceFlashesGuide {
                width,
                colors,
                flash_ms: FLASH_MS,
                grace_ms: GRACE_MS,
            }),
        ]
    }
}

/// The face held in an oval `width` of the frame's shorter side wide.
fn face(width: f32) -> Guide {
    Guide::Face(FaceGuide {
        width,
        hold_ms: FACE_HOLD_MS,
        grace_ms: GRACE_MS,
    })
}
