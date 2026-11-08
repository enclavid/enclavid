//! `enclavid:face-detect` — locate the face in an `image` → `face` geometry
//! the crop consumers (age, liveness, face-match) reuse.
//!
//! Detection runs ONCE here; the pixels stay with the host (this plugin pulls
//! the detector input via `image.pixels`), and only WHERE the face is (bbox +
//! landmarks, in the image's pixels) crosses the boundary — each consumer
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

use enclavid::host::media::{Image, PixelsOptions, Resize, ResizeMode, Size};
use enclavid::vision::types::{Bbox, Face, Point};
use exports::enclavid::face_detect::detect::Guest;

struct FaceDetect;

impl Guest for FaceDetect {
    fn detect(image: &Image) -> Option<Face> {
        let dim = image.size();
        if dim.width == 0 || dim.height == 0 {
            return None;
        }
        // The whole image, averaged down to the size the profile asks for it.
        let d = detect::detect((dim.width, dim.height), |w, h| {
            image
                .pixels(PixelsOptions {
                    crop: None,
                    resize: Some(Resize {
                        size: Size {
                            width: w,
                            height: h,
                        },
                        mode: ResizeMode::Average,
                    }),
                })
                .ok()
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
