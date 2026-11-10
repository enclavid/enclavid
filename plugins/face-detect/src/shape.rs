//! Where a face sits against a shape the page draws over the camera: an oval
//! it fills, read as the page reads a video's face guides, or a rect it is
//! inside. Bindgen-free.

use crate::detect::Detection;

/// An oval's height over its width, as the page draws it.
pub const OVAL_ASPECT: f32 = 1.618;
/// How far the face's box overlaps the oval's — their intersection over their
/// union — where the page takes the face as filling it.
const OVAL_OVERLAP: f32 = 0.6;
/// How much less overlap still counts here: the page reads a frame before the
/// video's encoder, this detector after it, and at the page's lowest bitrate
/// the encoder moves a frame's overlap by up to about this much.
const OVERLAP_MARGIN: f32 = 0.06;

/// A shape drawn at the centre of the frame.
#[derive(Clone, Copy, Debug)]
pub enum Shape {
    /// An oval `width` of the frame's shorter side wide, [`OVAL_ASPECT`] times
    /// as tall.
    Oval { width: f32 },
    /// A rect of `aspect`, its width over its height.
    Rect { aspect: f32 },
}

/// How a picture's face fits a shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fit {
    Followed,
    NoFace,
    ExtraFace,
    OffOval,
}

/// Which of `faces` — those of a picture of `size` pixels, the largest first —
/// `shape` is read by, and how it fits: in an oval, the largest, which fills
/// it where it is alone; in a rect, the largest inside it, alone there.
pub fn fit(faces: &[Detection], shape: Shape, size: (u32, u32)) -> (Option<usize>, Fit) {
    match shape {
        Shape::Oval { width } => {
            let fit = match faces {
                [] => Fit::NoFace,
                [face] if fills(face, width, size) => Fit::Followed,
                [_] => Fit::OffOval,
                _ => Fit::ExtraFace,
            };
            ((!faces.is_empty()).then_some(0), fit)
        }
        Shape::Rect { aspect } => {
            let rect = rect(aspect, size);
            let mut inside = (0..faces.len()).filter(|&i| within(&faces[i], &rect));
            let first = inside.next();
            let fit = match (first, inside.next()) {
                (None, _) => Fit::NoFace,
                (Some(_), None) => Fit::Followed,
                (Some(_), Some(_)) => Fit::ExtraFace,
            };
            (first, fit)
        }
    }
}

/// A region of a frame, by its edges in pixels.
#[derive(Clone, Copy, Debug)]
struct Bounds {
    left: f32,
    top: f32,
    right: f32,
    bottom: f32,
}

/// Whether `face` fills an oval `width` of the shorter side of a frame of
/// `size` wide.
fn fills(face: &Detection, width: f32, (w, h): (u32, u32)) -> bool {
    let (fw, fh) = (w as f32, h as f32);
    let shorter = fw.min(fh);
    let (ow, oh) = (width * shorter, width * OVAL_ASPECT * shorter);
    let oval = Bounds {
        left: (fw - ow) / 2.0,
        top: (fh - oh) / 2.0,
        right: (fw + ow) / 2.0,
        bottom: (fh + oh) / 2.0,
    };
    overlap(&face_bounds(face), &oval) > OVAL_OVERLAP - OVERLAP_MARGIN
}

/// The face's box as the page builds it from the keypoints, as AWS's liveness
/// page does: as wide as the eyes and the eyes-to-mouth height say, of the
/// oval's shape, and out to the ears. The detector's own box where it places
/// no keypoints.
fn face_bounds(face: &Detection) -> Bounds {
    let &[right_eye, left_eye, nose, mouth, right_ear, left_ear, ..] = face.landmarks.as_slice()
    else {
        let [x, y, w, h] = face.bbox;
        return Bounds {
            left: x,
            top: y,
            right: x + w,
            bottom: y + h,
        };
    };
    let eyes = mid(left_eye, right_eye);
    let width = (2.0 * dist(left_eye, right_eye) + 1.8 * dist(eyes, mouth)) / 2.0;
    let height = OVAL_ASPECT * width;
    let centre = mid(eyes, nose);
    Bounds {
        left: (centre.0 - width / 2.0).min(right_ear.0),
        top: centre.1 - height / 2.0,
        right: (centre.0 + width / 2.0).max(left_ear.0),
        bottom: centre.1 + height / 2.0,
    }
}

/// A rect of `aspect` at the centre of a frame of `size`, as large as fits it.
/// The page draws it smaller — at most 86% of the camera's area, and no wider
/// than fits the screen — so a face inside the one it shows is inside this.
fn rect(aspect: f32, (w, h): (u32, u32)) -> Bounds {
    let (fw, fh) = (w as f32, h as f32);
    let (rw, rh) = if fw / fh > aspect {
        (fh * aspect, fh)
    } else {
        (fw, fw / aspect)
    };
    Bounds {
        left: (fw - rw) / 2.0,
        top: (fh - rh) / 2.0,
        right: (fw + rw) / 2.0,
        bottom: (fh + rh) / 2.0,
    }
}

/// Whether the detector's box of `face` lies inside `rect`.
fn within(face: &Detection, rect: &Bounds) -> bool {
    let [x, y, w, h] = face.bbox;
    x >= rect.left && y >= rect.top && x + w <= rect.right && y + h <= rect.bottom
}

/// The intersection of `a` and `b` over their union.
fn overlap(a: &Bounds, b: &Bounds) -> f32 {
    let w = (a.right.min(b.right) - a.left.max(b.left)).max(0.0);
    let h = (a.bottom.min(b.bottom) - a.top.max(b.top)).max(0.0);
    let both = w * h;
    if both == 0.0 {
        return 0.0;
    }
    let area = |r: &Bounds| (r.right - r.left) * (r.bottom - r.top);
    both / (area(a) + area(b) - both)
}

fn mid(a: (f32, f32), b: (f32, f32)) -> (f32, f32) {
    ((a.0 + b.0) / 2.0, (a.1 + b.1) / 2.0)
}

fn dist(a: (f32, f32), b: (f32, f32)) -> f32 {
    (a.0 - b.0).hypot(a.1 - b.1)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A frame of 1280×720.
    pub const FRAME: (u32, u32) = (1280, 720);

    /// A face as BlazeFace places it, centred at `(cx, cy)`, `scale` times
    /// the face whose box from its keypoints is the oval half the frame's
    /// shorter side wide, its nose `offset` eye distances toward its own left.
    pub fn face(cx: f32, cy: f32, scale: f32, offset: f32) -> Detection {
        let at = |x: f32, y: f32| (cx + x * scale, cy + y * scale);
        Detection {
            bbox: [
                cx - 170.0 * scale,
                cy - 200.0 * scale,
                340.0 * scale,
                400.0 * scale,
            ],
            landmarks: vec![
                at(-90.0, -40.0),
                at(90.0, -40.0),
                at(180.0 * offset, 40.0),
                at(0.0, 160.0),
                at(-170.0, 0.0),
                at(170.0, 0.0),
            ],
            score: 1.0,
        }
    }

    /// A face at the centre at `scale`.
    pub fn centred(scale: f32) -> Detection {
        face(640.0, 360.0, scale, 0.0)
    }

    const OVAL: Shape = Shape::Oval { width: 0.5 };

    /// A face whose box matches the oval fills it; one a little smaller still
    /// does; one much smaller, or well off the centre, does not.
    #[test]
    fn a_face_fills_an_oval_by_its_box_from_the_keypoints() {
        assert_eq!(fit(&[centred(1.0)], OVAL, FRAME), (Some(0), Fit::Followed));
        assert_eq!(fit(&[centred(0.85)], OVAL, FRAME), (Some(0), Fit::Followed));
        assert_eq!(fit(&[centred(0.6)], OVAL, FRAME), (Some(0), Fit::OffOval));
        let aside = face(840.0, 360.0, 1.0, 0.0);
        assert_eq!(fit(&[aside], OVAL, FRAME), (Some(0), Fit::OffOval));
    }

    /// No face is none; two are one too many, the larger taken.
    #[test]
    fn an_oval_holds_one_face() {
        assert_eq!(fit(&[], OVAL, FRAME), (None, Fit::NoFace));
        let two = [centred(1.0), face(200.0, 200.0, 0.4, 0.0)];
        assert_eq!(fit(&two, OVAL, FRAME), (Some(0), Fit::ExtraFace));
    }

    /// A face without keypoints is read by the detector's box.
    #[test]
    fn a_face_without_keypoints_is_read_by_its_box() {
        let oh = 360.0 * OVAL_ASPECT;
        let boxed = Detection {
            bbox: [460.0, 360.0 - oh / 2.0, 360.0, oh],
            landmarks: Vec::new(),
            score: 1.0,
        };
        assert_eq!(fit(&[boxed], OVAL, FRAME), (Some(0), Fit::Followed));
    }

    /// In a rect, the face inside it counts, and those outside it do not; two
    /// inside are one too many.
    #[test]
    fn a_rect_holds_the_face_inside_it() {
        let card = Shape::Rect { aspect: 1.585 };
        let small = face(640.0, 360.0, 0.3, 0.0);
        let outside = face(60.0, 360.0, 0.3, 0.0);
        assert_eq!(fit(&[small.clone()], card, FRAME), (Some(0), Fit::Followed));
        assert_eq!(
            fit(&[outside.clone(), small.clone()], card, FRAME),
            (Some(1), Fit::Followed)
        );
        assert_eq!(fit(&[outside], card, FRAME), (None, Fit::NoFace));
        let another = face(500.0, 360.0, 0.25, 0.0);
        assert_eq!(
            fit(&[small, another], card, FRAME),
            (Some(0), Fit::ExtraFace)
        );
    }
}
