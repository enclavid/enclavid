//! face-age as the engine's tests run it, where there is no model: an age
//! from the face's mean brightness, from 0 for black to 60 for white, so a
//! gray frame reads 30.

wit_bindgen::generate!({
    path: "wit",
    world: "test:face-age/implementation@0.1.0",
    generate_all,
});

use enclavid::host::media::{Image, PixelsOptions, Rect, Resize, ResizeMode, Size};
use exports::enclavid::face_age::image::Guest;
use exports::enclavid::face_age::types::{AgeEstimate, Face};

struct Brightness;

impl Guest for Brightness {
    fn estimate(image: &Image, face: Face) -> Option<AgeEstimate> {
        let rgb = image.pixels(PixelsOptions {
            crop: Some(covered(&face, &image.size())?),
            resize: Some(Resize {
                size: Size {
                    width: 8,
                    height: 8,
                },
                mode: ResizeMode::Average,
            }),
        })?;
        let mean = rgb.iter().map(|&v| f32::from(v)).sum::<f32>() / rgb.len().max(1) as f32;
        Some(AgeEstimate {
            age: mean / 255.0 * 60.0,
        })
    }
}

/// The pixels the face's box covers in a picture of `size`; `None` where it
/// covers none.
fn covered(face: &Face, size: &Size) -> Option<Rect> {
    let span = |start: f32, length: f32, side: u32| {
        let side = side as f32;
        let from = start.floor().clamp(0.0, side);
        let to = (start + length).ceil().clamp(0.0, side);
        (to > from).then_some((from as u32, (to - from) as u32))
    };
    let b = &face.bounding_box;
    let (x, width) = span(b.x, b.width, size.width)?;
    let (y, height) = span(b.y, b.height, size.height)?;
    Some(Rect {
        x,
        y,
        size: Size { width, height },
    })
}

export!(Brightness);
