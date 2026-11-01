//! `enclavid:face-detect` — locate the face in a `decoded-frame` → `face`
//! geometry the crop consumers (age, liveness, face-match) reuse.
//!
//! Detection runs ONCE here; the pixels stay in the vision plugin (this
//! plugin pulls the detector input via `decoded-frame.region`), and only
//! WHERE the face is (bbox + landmarks) crosses the boundary — each consumer
//! derives its own crop. The detector lives in [`detect`]: a compile-time
//! profile. Default builds run the weightless placeholder (whole frame as the
//! face); built with `blazeface`, MediaPipe's BlazeFace is run by the host from
//! the model file beside this component.

mod detect;

#[cfg(not(feature = "blazeface"))]
wit_bindgen::generate!({
    path: "wit",
    world: "enclavid:face-detect/face-detect@0.1.0",
    generate_all,
});
#[cfg(feature = "blazeface")]
wit_bindgen::generate!({
    path: "wit",
    world: "enclavid:face-detect/with-models@0.1.0",
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
        // The whole frame, at the size the profile asks for it.
        let d = detect::detect((dim.width, dim.height), |w, h| {
            frame.region(0, 0, dim.width, dim.height, w, h)
        })?;
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
