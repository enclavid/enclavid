//! `shapes`: the frames of documents and a selfie's oval.

use crate::WellKnown;
use crate::enclavid::host_capture::photo::{OvalShape, RectShape, Shape};
use crate::exports::enclavid::well_known::shapes::Guest;

/// The frame of an ICAO TD3 passport photo page (125x88mm → ~1.42).
pub const PASSPORT_FRAME: Shape = Shape::Rect(RectShape { aspect: 1.42 });
/// The frame of an ICAO TD1 ID-1 card (85.6x54mm → ~1.585).
pub const CARD_FRAME: Shape = Shape::Rect(RectShape { aspect: 1.585 });
/// A selfie's oval: half the frame's shorter side wide.
pub const SELFIE_WIDTH: f32 = 0.5;

impl Guest for WellKnown {
    fn passport_frame() -> Shape {
        PASSPORT_FRAME
    }
    fn card_frame() -> Shape {
        CARD_FRAME
    }
    fn selfie_oval() -> Shape {
        Shape::Oval(OvalShape {
            width: SELFIE_WIDTH,
        })
    }
}
