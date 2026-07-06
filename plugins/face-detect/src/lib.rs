//! `enclavid:face-detect` — locate the face in a `decoded-frame` → `face`
//! geometry the crop consumers (age, liveness, face-match) reuse.
//!
//! Detection runs ONCE here; the pixels stay in the preprocess sandbox (this
//! plugin pulls the detector input via `decoded-frame.region`), and only
//! WHERE the face is (bbox + landmarks) crosses the boundary — each consumer
//! derives its own crop. The detector lives in [`detect`]: a compile-time
//! profile (placeholder / blazeface). Default builds run the weightless
//! placeholder (whole frame as the face); `--features blazeface` embeds
//! MediaPipe BlazeFace.

mod detect;

// getrandom has no backend on wasm32-unknown-unknown. Only the blazeface
// profile pulls tract (which seeds hashmaps over trusted model keys), so a
// deterministic no-op is safe there; the placeholder build pulls no tract, so
// the registration is gated on the feature. Wasm-only; native tests use the
// OS backend.
#[cfg(all(target_arch = "wasm32", feature = "blazeface"))]
getrandom::register_custom_getrandom!(no_entropy);
#[cfg(all(target_arch = "wasm32", feature = "blazeface"))]
fn no_entropy(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    buf.fill(0);
    Ok(())
}

wit_bindgen::generate!({
    path: "wit",
    world: "enclavid:face-detect/face-detect@0.1.0",
    generate_all,
});

use enclavid::vision::types::{Bbox, DecodedFrame, Face, Point};
use exports::enclavid::face_detect::detect::Guest;

struct FaceDetect;

impl Guest for FaceDetect {
    fn detect(frame: &DecodedFrame) -> Option<Face> {
        let dim = frame.size();
        if dim.width == 0 || dim.height == 0 {
            return None;
        }
        // The whole frame stretched to the detector's input — a stretch
        // preserves normalized coords, so the box maps 1:1 back onto the
        // frame. `region(0,0,w,h, INPUT, INPUT)` == a whole-frame stretch.
        let s = detect::INPUT as u32;
        let rgb = frame.region(0, 0, dim.width, dim.height, s, s);
        let d = detect::detect(&rgb)?;
        Some(Face {
            bbox: Bbox {
                x: d.bbox[0],
                y: d.bbox[1],
                w: d.bbox[2],
                h: d.bbox[3],
            },
            landmarks: d
                .landmarks
                .into_iter()
                .map(|(x, y)| Point { x, y })
                .collect(),
            score: d.score,
        })
    }
}

export!(FaceDetect);
