//! How the face in a picture does as expected of it, and how the frames of a
//! video hold it, by the page's own rules: the frames show it, but for breaks
//! no longer than are forgiven, for as long as asked. The head's turn is read
//! as the page reads it: the median of its latest frames against how it read
//! when the face last filled a face guide's oval. Bindgen-free.

use std::collections::VecDeque;

use crate::detect::Detection;
use crate::pose;
use crate::shape::{self, Fit, Place, Region};

/// How long a break is forgiven where the guide sets none, in milliseconds.
pub const GRACE_MS: u32 = 300;
/// How many of the latest frames the page reads a turn from.
const TURN_FRAMES: usize = 5;
/// How many frames before a range's the head is read in for it too: enough
/// to fill its window of the latest frames.
pub const BEFORE: u32 = TURN_FRAMES as u32 - 1;
/// How many degrees short of a turn's still count here: the page reads a
/// frame before the video's encoder, this detector after it, and at the page's
/// lowest bitrate the encoder moves a frame's turn by up to about this much.
const TURN_MARGIN: f32 = 5.0;

/// What is expected of the face.
#[derive(Clone, Copy, Debug)]
pub enum Expect {
    /// To fill a region, or to lie inside it.
    Region {
        region: Region,
        place: Place,
        /// Whether the head is read in it, as the page reads it in a face
        /// guide's oval: a face that fills it looks straight on.
        head: bool,
    },
    /// To turn the head `degrees`, negative to its own left.
    Turn { degrees: i8 },
}

impl Expect {
    /// Whether the head is read in the frames.
    pub fn reads_head(self) -> bool {
        matches!(
            self,
            Expect::Turn { .. } | Expect::Region { head: true, .. }
        )
    }
}

/// A frame of the video, as this detector found it.
#[derive(Clone, Debug)]
pub struct Frame {
    pub index: u32,
    /// When it is shown, in milliseconds from the video's first frame, as the
    /// page's encoder stamped it.
    pub ms: u32,
    /// Its size in pixels.
    pub size: (u32, u32),
    /// The faces found in it, the largest first.
    pub faces: Vec<Detection>,
}

/// A range of frames, and what is expected of the face in them.
#[derive(Debug)]
pub struct Range {
    pub expect: Expect,
    /// How long the frames must span, in milliseconds.
    pub hold_ms: u32,
    /// The longest stretch within them the face may not do as expected, in
    /// milliseconds.
    pub grace_ms: u32,
    /// The frames just before it — after the range before it — that the head
    /// is read in for it.
    pub before: Vec<Frame>,
    /// Its frames, as many as the video has.
    pub frames: Vec<Frame>,
    /// Whether the video has every frame of the range.
    pub whole: bool,
}

/// Whether the face did as expected, or how it did not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Followed,
    NoFace,
    ExtraFace,
    OffRegion,
    WrongTurn,
    /// Only of a range.
    ShortHold,
}

/// One range's reading: the face in each of its frames where one is found,
/// and how the range was held.
#[derive(Debug)]
pub struct Reading {
    pub faces: Vec<(u32, Detection)>,
    pub status: Status,
}

/// The face of a picture of `size` pixels, among `faces`, the largest first,
/// read against `expect`, and how it did.
pub fn picture(
    faces: &[Detection],
    size: (u32, u32),
    expect: Expect,
) -> (Option<&Detection>, Status) {
    let (face, held) = judge(expect, faces, size, &mut Head::default());
    (face, held.err().unwrap_or(Status::Followed))
}

/// Each of `ranges` read in order: a turn is read against how the head read
/// when the face last filled a face guide's oval.
pub fn read(ranges: &[Range]) -> Vec<Reading> {
    let mut head = Head::default();
    ranges.iter().map(|range| range.read(&mut head)).collect()
}

impl Range {
    fn read(&self, head: &mut Head) -> Reading {
        // The frames before the range's only take the head in.
        for frame in &self.before {
            let _ = judge(self.expect, &frame.faces, frame.size, head);
        }
        let start = self.frames.first().map_or(0, |frame| frame.ms);
        let mut faces = Vec::new();
        // When a frame last did as expected; how the first that did not
        // missed, and the first that missed past the grace.
        let mut held_at = None;
        let mut missed = None;
        let mut broken = None;
        for frame in &self.frames {
            let (face, held) = judge(self.expect, &frame.faces, frame.size, head);
            if let Some(face) = face {
                faces.push((frame.index, face.clone()));
            }
            match held {
                Ok(()) => held_at = Some(frame.ms),
                Err(why) => {
                    missed.get_or_insert(why);
                    // A break before any frame did as expected counts from
                    // the range's first.
                    if frame.ms.saturating_sub(held_at.unwrap_or(start)) > self.grace_ms {
                        broken.get_or_insert(why);
                    }
                }
            }
        }
        // A range no frame of which did as expected is broken, however short.
        if held_at.is_none() {
            broken = broken.or(missed);
        }
        let span = match (self.frames.first(), self.frames.last()) {
            (Some(first), Some(last)) => last.ms.saturating_sub(first.ms),
            _ => 0,
        };
        // The range is the frames inside the hold, within half a frame either
        // way.
        let frame_ms = match self.frames.len() {
            0 | 1 => 0,
            n => span / (n as u32 - 1),
        };
        let short = span.saturating_add(frame_ms) < self.hold_ms;
        let status = if !self.whole || self.frames.is_empty() || short {
            Status::ShortHold
        } else {
            broken.unwrap_or(Status::Followed)
        };
        Reading { faces, status }
    }
}

/// The face of a picture of `size` pixels, among `faces`, read against
/// `expect`, and whether it does as expected or how it does not; the head
/// taken in where it is read.
fn judge<'a>(
    expect: Expect,
    faces: &'a [Detection],
    size: (u32, u32),
    head: &mut Head,
) -> (Option<&'a Detection>, Result<(), Status>) {
    match expect {
        Expect::Region {
            region,
            place,
            head: reads,
        } => {
            let (at, fit) = shape::fit(faces, region, place, size);
            if reads {
                if let [face] = faces {
                    head.see(face);
                }
                if fit == Fit::Followed {
                    head.settle();
                }
            }
            let held = match fit {
                Fit::Followed => Ok(()),
                Fit::NoFace => Err(Status::NoFace),
                Fit::ExtraFace => Err(Status::ExtraFace),
                Fit::OffRegion => Err(Status::OffRegion),
            };
            (at.map(|i| &faces[i]), held)
        }
        Expect::Turn { degrees } => {
            let held = match faces {
                [] => Err(Status::NoFace),
                [face] => {
                    head.see(face);
                    if turned(head.turn(), degrees) {
                        Ok(())
                    } else {
                        Err(Status::WrongTurn)
                    }
                }
                _ => Err(Status::ExtraFace),
            };
            (faces.first(), held)
        }
    }
}

/// A head followed from frame to frame, as the page follows it: where its nose
/// sat in the latest frames, and where it sat when the face last filled a face
/// guide's oval — straight on by the keypoints before it did.
#[derive(Default)]
struct Head {
    recent: VecDeque<f32>,
    straight: f32,
}

impl Head {
    /// Take a frame's face in.
    fn see(&mut self, face: &Detection) {
        if let Some(offset) = pose::offset(&face.landmarks) {
            self.recent.push_back(offset);
            if self.recent.len() > TURN_FRAMES {
                self.recent.pop_front();
            }
        }
    }

    /// Take the head as looking straight on now.
    fn settle(&mut self) {
        if let Some(median) = pose::median(self.recent.iter().copied()) {
            self.straight = median;
        }
    }

    /// How far the head is turned, in degrees, negative to its own left.
    fn turn(&self) -> f32 {
        pose::median(self.recent.iter().copied()).map_or(0.0, |m| pose::degrees(m - self.straight))
    }
}

/// Whether a head turned `turn` degrees has turned as far as `degrees` asks,
/// to its side.
fn turned(turn: f32, degrees: i8) -> bool {
    let asked = f32::from(degrees);
    let toward = if turn * asked > 0.0 { turn.abs() } else { 0.0 };
    toward >= asked.abs() - TURN_MARGIN
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shape::tests::{FRAME, OVAL, centred, face};

    /// A face guide's oval: filled, the head read in it.
    const FACE: Expect = Expect::Region {
        region: OVAL,
        place: Place::Fill,
        head: true,
    };

    /// A static guide's oval of the same size: filled, the head not read.
    const STILL: Expect = Expect::Region {
        region: OVAL,
        place: Place::Fill,
        head: false,
    };

    /// A card's rect, as large as fits the frame.
    const CARD: Expect = Expect::Region {
        region: Region {
            aspect: 1.585,
            width: None,
            oval: false,
        },
        place: Place::Inside,
        head: false,
    };

    /// Frames from `index` on, one for each of `faces`, 15 a second.
    fn frames(index: u32, faces: Vec<Vec<Detection>>) -> Vec<Frame> {
        faces
            .into_iter()
            .zip(index..)
            .map(|(faces, index)| Frame {
                index,
                ms: index * 1000 / 15,
                size: FRAME,
                faces,
            })
            .collect()
    }

    fn range(expect: Expect, hold_ms: u32, frames: Vec<Frame>) -> Range {
        Range {
            expect,
            hold_ms,
            grace_ms: GRACE_MS,
            before: Vec::new(),
            frames,
            whole: true,
        }
    }

    /// The status of one range read alone.
    fn status(range: Range) -> Status {
        read(&[range])[0].status
    }

    /// `n` frames of the face in the oval.
    fn held(n: usize) -> Vec<Vec<Detection>> {
        vec![vec![centred(1.0)]; n]
    }

    /// A head `offset` eye distances toward its own left, in the oval.
    fn turned_by(offset: f32) -> Vec<Detection> {
        vec![face(640.0, 360.0, 1.0, offset)]
    }

    /// A nose offset that reads as `degrees`.
    fn offset_of(degrees: f32) -> f32 {
        -(degrees.to_radians().tan()) * 0.64
    }

    /// A face held in the oval through the hold follows it, with the face of
    /// every frame.
    #[test]
    fn a_face_held_through_its_hold_follows_it() {
        let got = read(&[range(FACE, 800, frames(0, held(13)))]);
        assert_eq!(got[0].status, Status::Followed);
        assert_eq!(got[0].faces.len(), 13);
        assert_eq!(got[0].faces[4].0, 4);
    }

    /// A face lost for a few frames is forgiven; lost for longer than the
    /// grace, the range is not held, and how says why.
    #[test]
    fn a_break_counts_past_its_grace() {
        let mut faces = held(13);
        for frame in &mut faces[5..9] {
            frame.clear();
        }
        let got = read(&[range(FACE, 800, frames(0, faces.clone()))]);
        assert_eq!(got[0].status, Status::Followed);
        assert_eq!(got[0].faces.len(), 9);

        faces[9].clear();
        assert_eq!(status(range(FACE, 800, frames(0, faces))), Status::NoFace);

        let mut faces = held(13);
        for frame in &mut faces[3..9] {
            frame.push(face(200.0, 200.0, 0.4, 0.0));
        }
        assert_eq!(
            status(range(FACE, 800, frames(0, faces))),
            Status::ExtraFace
        );

        let mut faces = held(13);
        for frame in &mut faces[3..9] {
            *frame = vec![centred(0.5)];
        }
        assert_eq!(
            status(range(FACE, 800, frames(0, faces))),
            Status::OffRegion
        );
    }

    /// The grace is the range's own: the same break is forgiven by a longer
    /// one, and not by none.
    #[test]
    fn the_grace_is_the_ranges_own() {
        let mut faces = held(13);
        for frame in &mut faces[5..10] {
            frame.clear();
        }
        let mut long = range(FACE, 800, frames(0, faces.clone()));
        long.grace_ms = 500;
        assert_eq!(status(long), Status::Followed);
        let mut none = range(FACE, 800, frames(0, faces));
        none.grace_ms = 0;
        assert_eq!(status(none), Status::NoFace);
    }

    /// A break at the start counts from the range's first frame; a range no
    /// frame of which does as expected is not held, however long the grace.
    #[test]
    fn a_range_never_followed_is_not_held() {
        let mut faces = held(13);
        for frame in &mut faces[..5] {
            frame.clear();
        }
        assert_eq!(
            status(range(FACE, 800, frames(0, faces.clone()))),
            Status::Followed
        );
        faces[5].clear();
        assert_eq!(status(range(FACE, 800, frames(0, faces))), Status::NoFace);

        let mut lenient = range(FACE, 200, frames(0, vec![Vec::new(); 4]));
        lenient.grace_ms = 1000;
        assert_eq!(status(lenient), Status::NoFace);
    }

    /// Frames that span less than the hold, or a range the video does not
    /// have whole, do not hold it.
    #[test]
    fn a_short_range_does_not_hold() {
        assert_eq!(
            status(range(FACE, 800, frames(0, held(6)))),
            Status::ShortHold
        );
        let mut cut = range(FACE, 300, frames(0, held(6)));
        cut.whole = false;
        assert_eq!(status(cut), Status::ShortHold);
        assert_eq!(status(range(FACE, 0, Vec::new())), Status::ShortHold);
        assert_eq!(status(range(FACE, 0, frames(0, held(1)))), Status::Followed);
    }

    /// A turn is read against how the head read in the oval: as far as asked
    /// follows, most of the way does not, the other way does not.
    #[test]
    fn a_turn_is_read_against_the_oval_before_it() {
        // Straight on, the head reads a little turned already.
        let straight = offset_of(4.0);
        let oval = frames(0, vec![turned_by(straight); 13]);
        let turn = |degrees: f32| {
            let faces = vec![turned_by(offset_of(4.0 + degrees)); 8];
            let mut turn = range(Expect::Turn { degrees: -25 }, 500, frames(17, faces));
            turn.before = frames(13, vec![turned_by(offset_of(4.0 + degrees)); 4]);
            read(&[range(FACE, 800, oval.clone()), turn])[1].status
        };
        assert_eq!(turn(-25.0), Status::Followed);
        assert_eq!(turn(-23.0), Status::Followed);
        assert_eq!(turn(-15.0), Status::WrongTurn);
        assert_eq!(turn(20.0), Status::WrongTurn);
    }

    /// With no face guide's oval filled before it, a turn is read from
    /// straight on.
    #[test]
    fn a_turn_with_no_oval_before_reads_from_straight() {
        let faces = vec![turned_by(offset_of(30.0)); 8];
        let turn = range(Expect::Turn { degrees: 30 }, 500, frames(0, faces));
        assert_eq!(status(turn), Status::Followed);
    }

    /// A static guide does not move the head, as the page does not read the
    /// face in it: a head tilted in a static oval, or a portrait in a card,
    /// between the face guide and the turn leaves the turn read against the
    /// face guide's oval.
    #[test]
    fn a_static_guide_does_not_move_the_head() {
        let oval = range(FACE, 800, frames(0, held(13)));
        let tilted = range(STILL, 500, frames(13, vec![turned_by(offset_of(-20.0)); 8]));
        let portrait = vec![vec![face(640.0, 360.0, 0.3, offset_of(-20.0))]; 8];
        let card = range(CARD, 500, frames(21, portrait));
        let turn = range(
            Expect::Turn { degrees: -20 },
            500,
            frames(29, vec![turned_by(offset_of(-20.0)); 8]),
        );
        let got = read(&[oval, tilted, card, turn]);
        assert_eq!(got[1].status, Status::Followed);
        assert_eq!(got[2].status, Status::Followed);
        assert_eq!(got[3].status, Status::Followed);
    }

    /// A picture is read as a frame alone: its face fills the oval or lies
    /// inside the card.
    #[test]
    fn a_picture_is_read_as_a_frame_alone() {
        let one = [centred(1.0)];
        assert_eq!(
            picture(&one, FRAME, STILL),
            (Some(&one[0]), Status::Followed)
        );
        let small = [centred(0.5)];
        assert_eq!(picture(&small, FRAME, STILL).1, Status::OffRegion);
        assert_eq!(picture(&small, FRAME, CARD).1, Status::Followed);
        assert_eq!(picture(&[], FRAME, STILL), (None, Status::NoFace));
    }

    /// A turn follows as far to its side as asked, short by the margin at
    /// most; the other way does not.
    #[test]
    fn a_turn_counts_to_its_side() {
        assert!(turned(-22.5, -25) && !turned(22.5, -25));
        assert!(turned(30.0, 25) && !turned(0.0, 10));
    }
}
