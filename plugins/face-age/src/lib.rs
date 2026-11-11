//! `enclavid:face-age` — facial age estimation from a detected face.
//!
//! The pipeline is split: the host decodes the capture — the `image` the
//! policy hands on — the face-detect plugin locates the face (`face`
//! geometry), and this plugin pulls its OWN crop from the image (`face.bbox`
//! grown by the model's margin, via `pixels`) and runs the age model. The
//! pixels stay with the host; face-age reads only the face patch at its model
//! resolution. Inference lives in [`infer`]: the per-model profile — a
//! placeholder with no model, or, built with `mivolo`, MiVOLO run by the host
//! from the model files beside this component.

mod infer;

#[cfg(not(feature = "mivolo"))]
wit_bindgen::generate!({
    path: "wit",
    world: "enclavid:face-age/face-age@0.1.0",
    generate_all,
});
#[cfg(feature = "mivolo")]
wit_bindgen::generate!({
    path: "wit",
    world: "enclavid:face-age/with-models@0.1.0",
    generate_all,
});

use enclavid::host::media::{Image, PixelsOptions, Rect, Resize, ResizeMode, Size};
use enclavid::vision::types::{Bbox, Face};
use exports::enclavid::face_age::check::{AgeEstimate, Guest};

struct FaceAge;

/// `bbox` grown by `margin` about its center, cut to a picture of `size`: the
/// pixels it touches. `None` where it touches none.
fn grown(bbox: &Bbox, margin: f32, size: &Size) -> Option<Rect> {
    let (x, width) = spanned(bbox.x + bbox.w / 2.0, bbox.w * margin, size.width)?;
    let (y, height) = spanned(bbox.y + bbox.h / 2.0, bbox.h * margin, size.height)?;
    Some(Rect {
        x,
        y,
        size: Size { width, height },
    })
}

/// The pixels of a side of `side` that `length` about `center` touches: the
/// first, on the pixel the span starts in, and how many, to the pixel past
/// its end — none past the side. `None` where it touches none.
fn spanned(center: f32, length: f32, side: u32) -> Option<(u32, u32)> {
    let side = side as f32;
    let from = (center - length / 2.0).floor().clamp(0.0, side);
    let to = (center + length / 2.0).ceil().clamp(0.0, side);
    (to > from).then_some((from as u32, (to - from) as u32))
}

impl Guest for FaceAge {
    fn estimate(image: &Image, face: Face) -> Option<AgeEstimate> {
        let rect = grown(&face.bbox, infer::MARGIN, &image.size())?;
        // Pull the face patch at the size the model's profile asks for — one
        // decode, the host's, the crop averaged down by the platform's
        // process that holds it.
        infer::estimate((rect.size.width, rect.size.height), |out_w, out_h| {
            image
                .pixels(PixelsOptions {
                    crop: Some(rect),
                    resize: Some(Resize {
                        size: Size {
                            width: out_w,
                            height: out_h,
                        },
                        mode: ResizeMode::Average,
                    }),
                })
                .ok()
        })
        .map(|age| AgeEstimate { age })
    }
}

export!(FaceAge);

#[cfg(test)]
mod tests {
    use super::spanned;

    /// A span takes the pixels it touches, from the one its start falls in to
    /// the one its end does, cut to the side; none where it touches none.
    #[test]
    fn a_span_takes_the_pixels_it_touches() {
        assert_eq!(spanned(50.0, 20.0, 100), Some((40, 20)));
        assert_eq!(spanned(50.5, 20.0, 100), Some((40, 21)));
        assert_eq!(spanned(5.0, 20.0, 100), Some((0, 15)));
        assert_eq!(spanned(95.0, 20.0, 100), Some((85, 15)));
        assert_eq!(spanned(50.0, 300.0, 100), Some((0, 100)));
        assert_eq!(spanned(150.0, 20.0, 100), None);
        assert_eq!(spanned(50.0, 0.0, 100), None);
        assert_eq!(spanned(50.0, -4.0, 100), None);
        assert_eq!(spanned(f32::NAN, 20.0, 100), None);
    }
}
