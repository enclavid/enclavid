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

use enclavid::host::media::{Crop, Image, PixelsOptions, Rect, Resize, ResizeMode, Size};
use enclavid::vision::types::{Bbox, Face};
use exports::enclavid::face_age::check::{AgeEstimate, Guest};

struct FaceAge;

/// `bbox` grown by `margin` about its center, held to the picture: a part of
/// it in fractions of its width and height, as `bbox` is.
fn grown(bbox: &Bbox, margin: f32) -> Rect {
    let cx = bbox.x + bbox.w / 2.0;
    let cy = bbox.y + bbox.h / 2.0;
    let width = (bbox.w * margin).clamp(0.0, 1.0);
    let height = (bbox.h * margin).clamp(0.0, 1.0);
    Rect {
        x: (cx - width / 2.0).clamp(0.0, 1.0),
        y: (cy - height / 2.0).clamp(0.0, 1.0),
        width,
        height,
    }
}

impl Guest for FaceAge {
    fn estimate(image: &Image, face: Face) -> Option<AgeEstimate> {
        let dim = image.size();
        if dim.width == 0 || dim.height == 0 {
            return None;
        }
        // Pull the face patch at the size the model's profile asks for — one
        // decode, the host's, the crop averaged down by the platform's
        // process that holds it.
        let rect = grown(&face.bbox, infer::MARGIN);
        // About as many of the picture's pixels as the crop spans: the shape
        // the model's profile asks for its pixels in.
        let spanned = (
            (rect.width * dim.width as f32).max(1.0) as u32,
            (rect.height * dim.height as f32).max(1.0) as u32,
        );
        infer::estimate(spanned, |out_w, out_h| {
            image
                .pixels(PixelsOptions {
                    crop: Some(Crop {
                        rect,
                        min_width: infer::MIN,
                        min_height: infer::MIN,
                    }),
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
