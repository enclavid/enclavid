//! face-liveness as the engine's tests run it, where there is no model: a
//! score from the face's mean brightness, from 0 for black to 1 for white, so
//! a gray frame reads about a half; a video's, the mean of its faces'.

wit_bindgen::generate!({
    path: "wit",
    world: "test:face-liveness/implementation@0.1.0",
    generate_all,
});

use enclavid::host::media::{Image, PixelsOptions, Rect, Resize, ResizeMode, Size, Video};
use exports::enclavid::face_liveness::image::Guest as ImageGuest;
use exports::enclavid::face_liveness::types::{Face, FrameFace, LivenessEstimate};
use exports::enclavid::face_liveness::video::Guest as VideoGuest;

struct Brightness;

impl ImageGuest for Brightness {
    fn estimate(image: &Image, face: Face) -> Option<LivenessEstimate> {
        Some(LivenessEstimate {
            liveness: brightness(image, &face)?,
        })
    }
}

impl VideoGuest for Brightness {
    fn estimate(video: &Video, faces: Vec<FrameFace>) -> Option<LivenessEstimate> {
        let frames = video.frames(0, u32::MAX);
        let scores: Vec<f32> = faces
            .iter()
            .filter_map(|found| {
                let frame = frames.iter().find(|frame| frame.index == found.index)?;
                brightness(&frame.image, &found.face)
            })
            .collect();
        if scores.is_empty() {
            return None;
        }
        Some(LivenessEstimate {
            liveness: scores.iter().sum::<f32>() / scores.len() as f32,
        })
    }
}

/// The mean brightness of `face` in `image`, from 0 to 1; `None` where it
/// covers no pixel, or the image does not decode.
fn brightness(image: &Image, face: &Face) -> Option<f32> {
    let rgb = image.pixels(PixelsOptions {
        crop: Some(covered(face, &image.size())?),
        resize: Some(Resize {
            size: Size {
                width: 8,
                height: 8,
            },
            mode: ResizeMode::Average,
        }),
    })?;
    let mean = rgb.iter().map(|&v| f32::from(v)).sum::<f32>() / rgb.len().max(1) as f32;
    Some(mean / 255.0)
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
