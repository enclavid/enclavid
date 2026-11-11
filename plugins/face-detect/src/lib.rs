//! `enclavid:face-detect` — locate the face in an `image` → `face` geometry
//! the crop consumers (age, liveness, face-match) reuse, and read the face
//! against the guides of a capture — a photo's static guide, a video's guides
//! — in this package's copies of the platform's.
//!
//! Detection runs ONCE here; the pixels stay with the host (this plugin pulls
//! the detector input via `image.pixels`), and only WHERE the face is (bbox +
//! landmarks, in the image's pixels) crosses the boundary — each consumer
//! derives its own crop. The detector lives in [`detect`]: a compile-time
//! profile. Default builds run the weightless placeholder (whole frame as the
//! face); built with `blazeface`, MediaPipe's BlazeFace is run by the host from
//! the model file beside this component. What the keypoints say of the head's
//! pose is [`pose`]'s; where a face sits against a region, [`shape`]'s; how a
//! picture or a video's frames follow a guide, [`hold`]'s, by the page's rules.

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
use enclavid::host_capture::constants::oval_aspect;
use enclavid::vision::types::{Bbox, Face, FrameFace, Point};
use exports::enclavid::face_detect::detect::Guest as DetectGuest;
use exports::enclavid::face_detect::guides::{StaticGuide, VideoGuide};
use exports::enclavid::face_detect::photo::{self, Guest as PhotoGuest};
use exports::enclavid::face_detect::pose::Guest as PoseGuest;
use exports::enclavid::face_detect::video::{self, FrameRange, Guest as VideoGuest};

use detect::Detection;
use hold::Status;
use shape::{Place, Region};

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
        let expect = still(&guide, oval_aspect());
        let (found, status) = hold::picture(&faces, (size.width, size.height), expect);
        photo::Reading {
            face: found.map(face),
            status: match status {
                Status::Followed => photo::Status::Followed,
                Status::NoFace => photo::Status::NoFace,
                Status::ExtraFace => photo::Status::ExtraFace,
                Status::OffRegion => photo::Status::OffOval,
                Status::WrongTurn | Status::ShortHold => {
                    unreachable!("a static guide asks no turn, and a picture holds for no time")
                }
            },
        }
    }
}

impl VideoGuest for FaceDetect {
    fn read(video: &Video, ranges: Vec<FrameRange>) -> Vec<video::Reading> {
        let aspect = oval_aspect();
        // Each frame is found in once: the video keeps only the frame read
        // last decoded, and the frames before a range may be another's.
        let mut found: HashMap<u32, hold::Frame> = HashMap::new();
        // The first frame no range before has taken in.
        let mut after = 0;
        let held: Vec<hold::Range> = ranges
            .iter()
            .map(|range| {
                let (expect, hold_ms, grace_ms) = expect_of(&range.guide, aspect);
                let from = if expect.reads_head() {
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
                    expect,
                    hold_ms,
                    grace_ms,
                    before,
                    frames,
                    whole,
                }
            })
            .collect();
        ranges
            .into_iter()
            .zip(hold::read(&held))
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
                    Status::OffRegion => video::Status::OffOval,
                    Status::WrongTurn => video::Status::WrongTurn,
                    Status::ShortHold => video::Status::ShortHold,
                },
            })
            .collect()
    }
}

/// What `guide` asks of the face, as the page reads it, how long it is held
/// and the longest break in it forgiven, in milliseconds; the page's ovals
/// `aspect` wide for their height.
fn expect_of(guide: &VideoGuide, aspect: f32) -> (hold::Expect, u32, u32) {
    match guide {
        VideoGuide::StaticGuide(s) => (
            still(&s.guide, aspect),
            u32::from(s.hold_ms),
            hold::GRACE_MS,
        ),
        VideoGuide::Face(f) => (
            face_oval(f.width, aspect),
            u32::from(f.hold_ms),
            u32::from(f.grace_ms),
        ),
        VideoGuide::HeadTurn(t) => (
            hold::Expect::Turn { degrees: t.degrees },
            u32::from(t.hold_ms),
            u32::from(t.grace_ms),
        ),
        VideoGuide::FaceFlashes(f) => {
            let flashes = u32::try_from(f.colors.len()).unwrap_or(u32::MAX);
            (
                face_oval(f.width, aspect),
                flashes.saturating_mul(u32::from(f.flash_ms)),
                u32::from(f.grace_ms),
            )
        }
    }
}

/// A face guide's oval, `width` of the frame's shorter side wide: filled, the
/// head read in it.
fn face_oval(width: f32, aspect: f32) -> hold::Expect {
    hold::Expect::Region {
        region: oval(width, aspect),
        place: Place::Fill,
        head: true,
    }
}

/// What a static guide asks of the face: to fill its oval, or to lie inside
/// its rect, as large as fits; the head is read in neither.
fn still(guide: &StaticGuide, aspect: f32) -> hold::Expect {
    match guide {
        StaticGuide::Oval(o) => hold::Expect::Region {
            region: oval(o.width, aspect),
            place: Place::Fill,
            head: false,
        },
        StaticGuide::Rect(r) => hold::Expect::Region {
            region: Region {
                aspect: r.aspect,
                width: None,
                oval: false,
            },
            place: Place::Inside,
            head: false,
        },
    }
}

fn oval(width: f32, aspect: f32) -> Region {
    Region {
        aspect,
        width: Some(width),
        oval: true,
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
