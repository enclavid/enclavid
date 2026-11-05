//! `enclavid:face-age` — facial age estimation from a detected face.
//!
//! The pipeline is split: the host decodes the capture — the `image` the
//! policy hands on — the face-detect plugin locates the face (`face`
//! geometry), and this plugin pulls its OWN crop from the image (`face.bbox`
//! grown by the model's margin, via `region`) and runs the age model. The
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

/// Grow `bbox` by `margin` about its center, then map to a clamped
/// SOURCE-pixel rect for `image.region`.
fn crop_px(bbox: &Bbox, fw: u32, fh: u32, margin: f32) -> (u32, u32, u32, u32) {
    let cx = bbox.x + bbox.w / 2.0;
    let cy = bbox.y + bbox.h / 2.0;
    let bw = (bbox.w * margin).clamp(0.0, 1.0);
    let bh = (bbox.h * margin).clamp(0.0, 1.0);
    let x0 = (cx - bw / 2.0).clamp(0.0, 1.0);
    let y0 = (cy - bh / 2.0).clamp(0.0, 1.0);
    let px = (x0 * fw as f32) as u32;
    let py = (y0 * fh as f32) as u32;
    let pw = (bw * fw as f32).max(1.0) as u32;
    let ph = (bh * fh as f32).max(1.0) as u32;
    (px, py, pw, ph)
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
        let (x, y, w, h) = crop_px(&face.bbox, dim.width, dim.height, infer::MARGIN);
        infer::estimate((w, h), |out_w, out_h| {
            image.pixels(PixelsOptions {
                crop: Some(Rect {
                    x,
                    y,
                    width: w,
                    height: h,
                }),
                resize: Some(Resize {
                    size: Size {
                        width: out_w,
                        height: out_h,
                    },
                    mode: ResizeMode::Average,
                }),
            })
        })
        .map(|age| AgeEstimate { age })
    }
}

export!(FaceAge);
