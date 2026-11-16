//! face-detect as the engine's tests run it, where there is no model: the
//! whole frame is the face, its pixels not read.

wit_bindgen::generate!({
    path: "wit",
    world: "test:face-detect/implementation@0.1.0",
    generate_all,
});

use enclavid::host::media::Image;
use exports::enclavid::face_detect::detect::Guest;
use exports::enclavid::face_detect::types::{BoundingBox, Face};

struct WholeFrame;

impl Guest for WholeFrame {
    fn detect(image: &Image) -> Option<Face> {
        let size = image.size();
        Some(Face {
            bounding_box: BoundingBox {
                x: 0.0,
                y: 0.0,
                width: size.width as f32,
                height: size.height as f32,
            },
            score: None,
            keypoints: None,
        })
    }
}

export!(WholeFrame);
