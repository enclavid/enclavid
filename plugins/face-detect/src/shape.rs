//! Where a face sits against a region drawn at the centre of a frame: filling
//! it, read as the page reads a video's face guides, or lying inside it.
//! Bindgen-free.

use crate::detect::Detection;

/// How far the face's box overlaps the region's — their intersection over
/// their union — where the page takes the face as filling it.
const FILL_OVERLAP: f32 = 0.6;
/// How much less overlap still counts here: the page reads a frame before the
/// video's encoder, this detector after it, and at the page's lowest bitrate
/// the encoder moves a frame's overlap by up to about this much.
const OVERLAP_MARGIN: f32 = 0.06;

/// A region drawn at the centre of a frame.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Region {
    /// Its width over its height.
    pub aspect: f32,
    /// Its width as a fraction of the frame's shorter side; none: as large as
    /// fits the frame.
    pub width: Option<f32>,
    /// The oval inside the box, rather than the box itself.
    pub oval: bool,
}

/// What a picture's face is to do in a region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    /// Fill it, the only face in the picture.
    Fill,
    /// Lie inside it, the only face there.
    Inside,
}

/// How a picture's face fits a region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fit {
    Followed,
    NoFace,
    ExtraFace,
    OffRegion,
}

/// Which of `faces` — those of a picture of `size` pixels, the largest first —
/// the region is read by, and how it fits: to fill it, the largest, alone in
/// the picture; to lie inside it, the largest inside it, alone there.
pub fn fit(
    faces: &[Detection],
    region: Region,
    place: Place,
    size: (u32, u32),
) -> (Option<usize>, Fit) {
    let bounds = region.bounds(size);
    match place {
        Place::Fill => {
            let fit = match faces {
                [] => Fit::NoFace,
                [face] if fills(face, &bounds, region.aspect) => Fit::Followed,
                [_] => Fit::OffRegion,
                _ => Fit::ExtraFace,
            };
            ((!faces.is_empty()).then_some(0), fit)
        }
        Place::Inside => {
            let mut inside = (0..faces.len()).filter(|&i| within(&faces[i], &bounds, region.oval));
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

impl Region {
    /// The region's box in a frame of `size`, at its centre.
    fn bounds(self, (w, h): (u32, u32)) -> Bounds {
        let (fw, fh) = (w as f32, h as f32);
        let (rw, rh) = match self.width {
            Some(width) => {
                let rw = width * fw.min(fh);
                (rw, rw / self.aspect)
            }
            None if fw / fh > self.aspect => (fh * self.aspect, fh),
            None => (fw, fw / self.aspect),
        };
        Bounds {
            left: (fw - rw) / 2.0,
            top: (fh - rh) / 2.0,
            right: (fw + rw) / 2.0,
            bottom: (fh + rh) / 2.0,
        }
    }
}

/// Whether `face` fills `region`, a box `aspect` wide for its height.
fn fills(face: &Detection, region: &Bounds, aspect: f32) -> bool {
    overlap(&face_bounds(face, 1.0 / aspect), region) > FILL_OVERLAP - OVERLAP_MARGIN
}

/// The face's box as the page builds it from the keypoints, as AWS's liveness
/// page does: as wide as the eyes and the eyes-to-mouth height say, `shape`
/// times as tall, and out to the ears. The detector's own box where it places
/// no keypoints.
fn face_bounds(face: &Detection, shape: f32) -> Bounds {
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
    let height = shape * width;
    let centre = mid(eyes, nose);
    Bounds {
        left: (centre.0 - width / 2.0).min(right_ear.0),
        top: centre.1 - height / 2.0,
        right: (centre.0 + width / 2.0).max(left_ear.0),
        bottom: centre.1 + height / 2.0,
    }
}

/// Whether the detector's box of `face` lies inside `region`: its box, or the
/// oval inside it.
fn within(face: &Detection, region: &Bounds, oval: bool) -> bool {
    let [x, y, w, h] = face.bbox;
    let corners = [(x, y), (x + w, y), (x, y + h), (x + w, y + h)];
    if oval {
        let (cx, cy) = (
            (region.left + region.right) / 2.0,
            (region.top + region.bottom) / 2.0,
        );
        let (rx, ry) = (
            (region.right - region.left) / 2.0,
            (region.bottom - region.top) / 2.0,
        );
        corners
            .iter()
            .all(|&(px, py)| ((px - cx) / rx).powi(2) + ((py - cy) / ry).powi(2) <= 1.0)
    } else {
        corners.iter().all(|&(px, py)| {
            px >= region.left && px <= region.right && py >= region.top && py <= region.bottom
        })
    }
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

    /// The oval of a face guide half the frame's shorter side wide, 1.618
    /// times as tall.
    pub const OVAL: Region = Region {
        aspect: 1.0 / 1.618,
        width: Some(0.5),
        oval: true,
    };

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

    /// A face whose box matches the oval fills it; one a little smaller still
    /// does; one much smaller, or well off the centre, does not.
    #[test]
    fn a_face_fills_a_region_by_its_box_from_the_keypoints() {
        let fill = |faces: &[Detection]| fit(faces, OVAL, Place::Fill, FRAME);
        assert_eq!(fill(&[centred(1.0)]), (Some(0), Fit::Followed));
        assert_eq!(fill(&[centred(0.85)]), (Some(0), Fit::Followed));
        assert_eq!(fill(&[centred(0.6)]), (Some(0), Fit::OffRegion));
        assert_eq!(
            fill(&[face(840.0, 360.0, 1.0, 0.0)]),
            (Some(0), Fit::OffRegion)
        );
    }

    /// No face is none; two are one too many, the larger taken.
    #[test]
    fn a_region_to_fill_holds_one_face() {
        assert_eq!(fit(&[], OVAL, Place::Fill, FRAME), (None, Fit::NoFace));
        let two = [centred(1.0), face(200.0, 200.0, 0.4, 0.0)];
        assert_eq!(
            fit(&two, OVAL, Place::Fill, FRAME),
            (Some(0), Fit::ExtraFace)
        );
    }

    /// A face without keypoints is read by the detector's box.
    #[test]
    fn a_face_without_keypoints_is_read_by_its_box() {
        let oh = 360.0 * 1.618;
        let boxed = Detection {
            bbox: [460.0, 360.0 - oh / 2.0, 360.0, oh],
            landmarks: Vec::new(),
            score: 1.0,
        };
        assert_eq!(
            fit(&[boxed], OVAL, Place::Fill, FRAME),
            (Some(0), Fit::Followed)
        );
    }

    /// Inside a card's rect, as large as fits, the face inside it counts and
    /// those outside it do not; two inside are one too many.
    #[test]
    fn a_rect_holds_the_face_inside_it() {
        let card = Region {
            aspect: 1.585,
            width: None,
            oval: false,
        };
        let inside = |faces: &[Detection]| fit(faces, card, Place::Inside, FRAME);
        let small = face(640.0, 360.0, 0.3, 0.0);
        let outside = face(60.0, 360.0, 0.3, 0.0);
        assert_eq!(
            inside(std::slice::from_ref(&small)),
            (Some(0), Fit::Followed)
        );
        assert_eq!(
            inside(&[outside.clone(), small.clone()]),
            (Some(1), Fit::Followed)
        );
        assert_eq!(inside(&[outside]), (None, Fit::NoFace));
        let another = face(500.0, 360.0, 0.25, 0.0);
        assert_eq!(inside(&[small, another]), (Some(0), Fit::ExtraFace));
    }

    /// Inside an oval, a face in its corner of the box is outside the oval.
    #[test]
    fn an_oval_holds_the_face_inside_the_oval_not_its_box() {
        let inside = |faces: &[Detection]| fit(faces, OVAL, Place::Inside, FRAME);
        assert_eq!(
            inside(&[face(640.0, 360.0, 0.3, 0.0)]),
            (Some(0), Fit::Followed)
        );
        assert_eq!(inside(&[face(500.0, 130.0, 0.2, 0.0)]), (None, Fit::NoFace));
    }
}
