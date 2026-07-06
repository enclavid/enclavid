//! `enclavid:face-age` — facial age estimation from a detected face.
//!
//! The pipeline is now split across plugins: the preprocess plugin decodes
//! the capture into a `decoded-frame`, the face-detect plugin locates the
//! face (`face` geometry), and this plugin pulls its OWN crop from the frame
//! (`face.bbox` grown by the model's margin, via `region`) and runs the age
//! model. The pixels stay in the preprocess sandbox; face-age reads only the
//! face patch at its model resolution. Inference lives in [`infer`]: the
//! per-model profile (normalize + model + decode).

mod infer;

// getrandom has no backend on wasm32-unknown-unknown (no OS, no WASI, no
// JS). tract pulls it only for hashmap seeding over trusted (embedded
// model) keys, so a deterministic no-op is safe. Wasm-only; native builds
// (unit tests) use the OS backend.
#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(no_entropy);
#[cfg(target_arch = "wasm32")]
fn no_entropy(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    buf.fill(0);
    Ok(())
}

wit_bindgen::generate!({
    path: "wit",
    world: "enclavid:face-age/face-age@0.1.0",
    generate_all,
});

use enclavid::vision::types::{Bbox, DecodedFrame, Face};
use exports::enclavid::face_age::check::{AgeEstimate, Guest};

struct FaceAge;

/// Grow `bbox` by `margin` about its center, then map to a clamped
/// SOURCE-pixel rect for `decoded-frame.region`.
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
    fn estimate(frame: &DecodedFrame, face: Face) -> Option<AgeEstimate> {
        let dim = frame.size();
        if dim.width == 0 || dim.height == 0 {
            return None;
        }
        // Pull the face patch at the model's input size — one shared decode
        // (owned by preprocess), the crop resampled in that sandbox.
        let s = infer::INPUT as u32;
        let (x, y, w, h) = crop_px(&face.bbox, dim.width, dim.height, infer::MARGIN);
        let rgb = frame.region(x, y, w, h, s, s);
        infer::estimate_from_rgb(&rgb).map(|age| AgeEstimate { age })
    }
}

export!(FaceAge);
