//! `enclavid:face-detect` — locate the face in an `image` → `face` geometry
//! the crop consumers (age, liveness, face-match) reuse, and read the face
//! against the guides of a capture: a photo's static guide, a video's guides.
//!
//! Detection runs ONCE here; the pixels stay with the host (this plugin pulls
//! the detector input via `image.pixels`), and only WHERE the face is (bbox +
//! landmarks, in the image's pixels) crosses the boundary — each consumer
//! derives its own crop. The detector lives in [`detect`]: a compile-time
//! profile. Default builds run the weightless placeholder (whole frame as the
//! face); built with `blazeface`, MediaPipe's BlazeFace is run by the host from
//! the model file beside this component. What the keypoints say of the head's
//! pose is [`pose`]'s; where a face sits against a shape, [`shape`]'s; how a
//! video's frames hold its guides, [`hold`]'s, by the page's rules.

mod detect;
mod hold;
mod pose;
mod shape;

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

use std::collections::HashMap;

use enclavid::host::media::{Image, PixelsOptions, Resize, ResizeMode, Size, Video};
use enclavid::host_capture::photo::StaticGuide;
use enclavid::host_capture::video::VideoGuide;
use enclavid::policy::types::FrameRange;
use enclavid::vision::types::{Bbox, Face, FrameFace, Point};
use exports::enclavid::face_detect::detect::Guest as DetectGuest;
use exports::enclavid::face_detect::photo::{self, Guest as PhotoGuest};
use exports::enclavid::face_detect::pose::Guest as PoseGuest;
use exports::enclavid::face_detect::video::{self, Guest as VideoGuest};

use detect::Detection;
use hold::{Ask, Status};
use shape::{Fit, Shape};

struct FaceDetect;

impl DetectGuest for FaceDetect {
    fn detect(image: &Image) -> Option<Face> {
        faces_in(image).first().map(face)
    }
}

impl PoseGuest for FaceDetect {
    fn head_turn(faces: Vec<Face>) -> Option<f32> {
        let keypoints: Vec<Vec<(f32, f32)>> = faces
            .iter()
            .map(|face| face.landmarks.iter().map(|p| (p.x, p.y)).collect())
            .collect();
        pose::head_turn(keypoints.iter().map(Vec::as_slice))
    }
}

impl PhotoGuest for FaceDetect {
    fn read(image: &Image, guide: StaticGuide) -> photo::Reading {
        let size = image.size();
        let faces = faces_in(image);
        let (at, fit) = shape::fit(&faces, shape_of(&guide), (size.width, size.height));
        photo::Reading {
            face: at.map(|i| face(&faces[i])),
            status: match fit {
                Fit::Followed => photo::Status::Followed,
                Fit::NoFace => photo::Status::NoFace,
                Fit::ExtraFace => photo::Status::ExtraFace,
                Fit::OffOval => photo::Status::OffOval,
            },
        }
    }
}

impl VideoGuest for FaceDetect {
    fn read(video: &Video, guides: Vec<FrameRange>) -> Vec<video::Reading> {
        // Each frame is found in once: the video keeps only the frame read
        // last decoded, and the frames before a guide may be another's.
        let mut found: HashMap<u32, hold::Frame> = HashMap::new();
        // The first frame no guide before has taken in.
        let mut after = 0;
        let ranges: Vec<hold::Range> = guides
            .iter()
            .map(|range| {
                let (ask, hold_ms) = ask_of(&range.guide);
                let from = if ask.reads_head() {
                    range.first.saturating_sub(hold::BEFORE).max(after)
                } else {
                    range.first
                };
                after = after.max(range.last.saturating_add(1));
                let (before, frames): (Vec<_>, Vec<_>) =
                    frames_of(video, from.min(range.first), range.last, &mut found)
                        .into_iter()
                        .partition(|frame| frame.index < range.first);
                let whole = range
                    .last
                    .checked_sub(range.first)
                    .is_some_and(|n| frames.len() as u64 == u64::from(n) + 1);
                hold::Range {
                    ask,
                    hold_ms,
                    before,
                    frames,
                    whole,
                }
            })
            .collect();
        guides
            .into_iter()
            .zip(hold::read(&ranges))
            .map(|(range, reading)| video::Reading {
                guide: range.guide,
                faces: reading
                    .faces
                    .iter()
                    .map(|(index, found)| FrameFace {
                        index: *index,
                        face: face(found),
                    })
                    .collect(),
                status: match reading.status {
                    Status::Followed => video::Status::Followed,
                    Status::NoFace => video::Status::NoFace,
                    Status::ExtraFace => video::Status::ExtraFace,
                    Status::OffOval => video::Status::OffOval,
                    Status::WrongTurn => video::Status::WrongTurn,
                    Status::ShortHold => video::Status::ShortHold,
                },
            })
            .collect()
    }
}

/// What `guide` asks of the face in its frames, and how long it is held, in
/// milliseconds: flashes through all their colours.
fn ask_of(guide: &VideoGuide) -> (Ask, u32) {
    match guide {
        VideoGuide::StaticGuide(still) => (
            Ask::Shape {
                shape: shape_of(&still.guide),
                head: false,
            },
            u32::from(still.hold_ms),
        ),
        VideoGuide::Face(face) => (
            Ask::Shape {
                shape: Shape::Oval { width: face.width },
                head: true,
            },
            u32::from(face.hold_ms),
        ),
        VideoGuide::HeadTurn(turn) => (
            Ask::Turn {
                degrees: turn.degrees,
            },
            u32::from(turn.hold_ms),
        ),
        VideoGuide::FaceFlashes(flashes) => (
            Ask::Shape {
                shape: Shape::Oval {
                    width: flashes.width,
                },
                head: true,
            },
            flashes.colors.len() as u32 * u32::from(flashes.flash_ms),
        ),
    }
}

fn shape_of(guide: &StaticGuide) -> Shape {
    match guide {
        StaticGuide::Rect(rect) => Shape::Rect {
            aspect: rect.aspect,
        },
        StaticGuide::Oval(oval) => Shape::Oval { width: oval.width },
    }
}

/// Frames `first` to `last` of `video` as far as it has them, each with the
/// faces found in it, found once into `found`.
fn frames_of(
    video: &Video,
    first: u32,
    last: u32,
    found: &mut HashMap<u32, hold::Frame>,
) -> Vec<hold::Frame> {
    if first > last {
        return Vec::new();
    }
    video
        .frames(first, last)
        .into_iter()
        .map(|frame| {
            found
                .entry(frame.index)
                .or_insert_with(|| {
                    let size = frame.image.size();
                    hold::Frame {
                        index: frame.index,
                        ms: frame.timestamp_ms,
                        size: (size.width, size.height),
                        faces: faces_in(&frame.image),
                    }
                })
                .clone()
        })
        .collect()
}

/// Every face in `image`, the largest first: the whole image averaged down to
/// the size the profile asks for it. None where it does not decode.
fn faces_in(image: &Image) -> Vec<Detection> {
    let dim = image.size();
    if dim.width == 0 || dim.height == 0 {
        return Vec::new();
    }
    detect::detect_all((dim.width, dim.height), |w, h| {
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
    })
}

fn face(d: &Detection) -> Face {
    Face {
        bbox: Bbox {
            x: d.bbox[0],
            y: d.bbox[1],
            w: d.bbox[2],
            h: d.bbox[3],
        },
        landmarks: d.landmarks.iter().map(|&(x, y)| Point { x, y }).collect(),
        score: d.score,
    }
}

export!(FaceDetect);
