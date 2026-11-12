//! `enclavid:face-liveness` — whether a detected face is a live person's, in
//! one picture (`image`) or over frames of a video (`video`).
//!
//! The pipeline is split as face-age's is: the host decodes the capture — the
//! image or video the policy hands on — the face-detect plugin locates the face
//! (`face` geometry), and this plugin pulls its OWN crops from the picture (the
//! face and what is around it, at its model's resolution, via `pixels`) and
//! runs the models. Inference lives in [`infer`]: the per-model profile — a
//! placeholder with no model, or, built with `minifasnet`, MiniFASNet run by
//! the host from the model files beside this component. MiniFASNet reads
//! single pictures, so a video's estimate is the mean of its frames'.

mod infer;

#[cfg(not(feature = "minifasnet"))]
wit_bindgen::generate!({
    path: "wit",
    world: "enclavid:face-liveness/face-liveness@0.1.0",
    generate_all,
});
#[cfg(feature = "minifasnet")]
wit_bindgen::generate!({
    path: "wit",
    world: "enclavid:face-liveness/with-models@0.1.0",
    generate_all,
});

use enclavid::host::media::{Image, PixelsOptions, Rect, Resize, ResizeMode, Size, Video};
use enclavid::vision::types::{Face, FrameFace};
use exports::enclavid::face_liveness::image::Guest as ImageGuest;
use exports::enclavid::face_liveness::types::LivenessEstimate;
use exports::enclavid::face_liveness::video::Guest as VideoGuest;

struct FaceLiveness;

impl ImageGuest for FaceLiveness {
    fn estimate(image: &Image, face: Face) -> Option<LivenessEstimate> {
        let live = live(&infer::Models::new(), image, &face)?;
        Some(LivenessEstimate { live })
    }
}

impl VideoGuest for FaceLiveness {
    fn estimate(video: &Video, mut faces: Vec<FrameFace>) -> Option<LivenessEstimate> {
        faces.sort_by_key(|f| f.index);
        let first = faces.first()?.index;
        let frames = video.frames(first, faces.last()?.index);
        let models = infer::Models::new();
        let lives: Vec<f32> = faces
            .iter()
            .filter_map(|f| {
                // The list holds the frames from `first` on, and ends early
                // where the video does.
                let frame = frames
                    .get((f.index - first) as usize)
                    .filter(|frame| frame.index == f.index)?;
                live(&models, &frame.image, &f.face)
            })
            .collect();
        if lives.is_empty() {
            return None;
        }
        let live = lives.iter().sum::<f32>() / lives.len() as f32;
        Some(LivenessEstimate { live })
    }
}

/// How live `face` in `image` looks, by `models`.
fn live(models: &infer::Models, image: &Image, face: &Face) -> Option<f32> {
    let size = image.size();
    let b = &face.bbox;
    models.estimate(
        (size.width, size.height),
        [b.x, b.y, b.w, b.h],
        |crop, side| crop_of(image, crop, side),
    )
}

/// `crop` of `image` at a square of `side`, resampled as the models'
/// training crops were, by the platform's process that holds the decode; none
/// where the image does not decode.
fn crop_of(image: &Image, [x, y, width, height]: infer::Crop, side: u32) -> Option<Vec<u8>> {
    image
        .pixels(PixelsOptions {
            crop: Some(Rect {
                x,
                y,
                size: Size { width, height },
            }),
            resize: Some(Resize {
                size: Size {
                    width: side,
                    height: side,
                },
                mode: ResizeMode::Bilinear,
            }),
        })
        .ok()
}

export!(FaceLiveness);
