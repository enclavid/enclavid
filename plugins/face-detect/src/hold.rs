//! How the frames of a video hold its guides, by the page's own rules: a
//! guide's frames show what the page held it to, but for breaks no longer than
//! it forgives, for as long as the guide asks. The head's turn is read as the
//! page reads it: the median of its latest frames against how it read in the
//! oval. Bindgen-free.

use std::collections::VecDeque;

use crate::detect::Detection;
use crate::pose;
use crate::shape::{self, Fit, Shape};

/// How long the page lets frames break a guide before it no longer holds it,
/// in milliseconds.
const GRACE_MS: u32 = 300;
/// The time between the page's frames, at its 15 a second, in milliseconds,
/// rounded up.
const FRAME_MS: u32 = 67;
/// As many frames as the page draws in [`GRACE_MS`]: a break of more is
/// longer, whatever the frames' times say — the page stamped them.
const GRACE_FRAMES: u32 = GRACE_MS / FRAME_MS;
/// How many of the latest frames the page reads a turn from.
const TURN_FRAMES: usize = 5;
/// How many frames before a guide's the page reads the head in for it too:
/// enough to fill its window of the latest frames.
pub const BEFORE: u32 = TURN_FRAMES as u32 - 1;
/// How far from straight on a head still reads straight, in degrees.
const STRAIGHT_DEGREES: f32 = 8.0;
/// How many degrees short of a turn's still count here: the page reads a
/// frame before the video's encoder, this detector after it, and at the page's
/// lowest bitrate the encoder moves a frame's turn by up to about this much.
const TURN_MARGIN: f32 = 5.0;

/// What a guide asks of the face in its frames.
#[derive(Clone, Copy, Debug)]
pub enum Ask {
    /// To fit `shape`: a face guide's oval, with its flashes or without,
    /// which the page reads the head in (`head`), or a static guide's, which
    /// it does not.
    Shape { shape: Shape, head: bool },
    /// To turn the head `degrees`, negative to its own left.
    Turn { degrees: i8 },
}

impl Ask {
    /// Whether the page reads the head in this guide's frames.
    pub fn reads_head(self) -> bool {
        matches!(self, Ask::Turn { .. } | Ask::Shape { head: true, .. })
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

/// One guide, and the frames it was held in.
#[derive(Debug)]
pub struct Range {
    pub ask: Ask,
    /// How long it is held, in milliseconds.
    pub hold_ms: u32,
    /// The frames just before it — after the guide before it — which the page
    /// read the head in for it.
    pub before: Vec<Frame>,
    /// Its frames, as many as the video has.
    pub frames: Vec<Frame>,
    /// Whether the video has every frame of its range.
    pub whole: bool,
}

/// How a guide was held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Followed,
    NoFace,
    ExtraFace,
    OffOval,
    WrongTurn,
    ShortHold,
}

/// One guide's reading: the face in each of its frames where one is found,
/// and how the guide was held.
#[derive(Debug)]
pub struct Reading {
    pub faces: Vec<(u32, Detection)>,
    pub status: Status,
}

/// Each of `ranges` read in order: a turn is read against how the head read
/// in the ovals before it.
pub fn read(ranges: &[Range]) -> Vec<Reading> {
    let mut head = Head::default();
    ranges.iter().map(|range| range.read(&mut head)).collect()
}

impl Range {
    fn read(&self, head: &mut Head) -> Reading {
        // The frames before the guide's only take the head in.
        for frame in &self.before {
            let _ = self.frame(frame, head);
        }
        let mut faces = Vec::new();
        let mut broken = None;
        // When a frame last held the guide, and how many have not since.
        let mut held_at = self.frames.first().map_or(0, |frame| frame.ms);
        let mut run = 0;
        for frame in &self.frames {
            let (face, held) = self.frame(frame, head);
            if let Some(face) = face {
                faces.push((frame.index, face.clone()));
            }
            match held {
                Ok(()) => {
                    held_at = frame.ms;
                    run = 0;
                }
                Err(why) => {
                    run += 1;
                    let long = frame.ms.saturating_sub(held_at) > GRACE_MS || run > GRACE_FRAMES;
                    if long && broken.is_none() {
                        broken = Some(why);
                    }
                }
            }
        }
        let span = match (self.frames.first(), self.frames.last()) {
            (Some(first), Some(last)) => last.ms.saturating_sub(first.ms),
            _ => 0,
        };
        // The page's range is the frames inside its hold, within half a frame
        // either way.
        let status = if !self.whole || self.frames.is_empty() || span + FRAME_MS < self.hold_ms {
            Status::ShortHold
        } else {
            broken.unwrap_or(Status::Followed)
        };
        Reading { faces, status }
    }

    /// The face `frame` is read by, and whether the frame holds the guide or
    /// how it breaks it; the head taken in where the page reads it.
    fn frame<'a>(
        &self,
        frame: &'a Frame,
        head: &mut Head,
    ) -> (Option<&'a Detection>, Result<(), Status>) {
        match self.ask {
            Ask::Shape { shape, head: reads } => {
                let (at, fit) = shape::fit(&frame.faces, shape, frame.size);
                if reads {
                    if let [face] = frame.faces.as_slice() {
                        head.see(face);
                    }
                    // A face in the oval looks straight on.
                    if fit == Fit::Followed {
                        head.settle();
                    }
                }
                let held = match fit {
                    Fit::Followed => Ok(()),
                    Fit::NoFace => Err(Status::NoFace),
                    Fit::ExtraFace => Err(Status::ExtraFace),
                    Fit::OffOval => Err(Status::OffOval),
                };
                (at.map(|i| &frame.faces[i]), held)
            }
            Ask::Turn { degrees } => {
                let held = match frame.faces.as_slice() {
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
                (frame.faces.first(), held)
            }
        }
    }
}

/// A head followed from frame to frame, as the page follows it: where its nose
/// sat in the latest frames, and where it sat when the head last looked
/// straight on — none of it before an oval.
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

/// Whether a head turned `turn` degrees follows a guide asking `degrees`: as
/// far to its side, or, for none, about straight on.
fn turned(turn: f32, degrees: i8) -> bool {
    let asked = f32::from(degrees);
    if degrees == 0 {
        return turn.abs() <= STRAIGHT_DEGREES + TURN_MARGIN;
    }
    let toward = if turn * asked > 0.0 { turn.abs() } else { 0.0 };
    toward >= asked.abs() - TURN_MARGIN
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shape::tests::{FRAME, centred, face};

    const OVAL: Ask = Ask::Shape {
        shape: Shape::Oval { width: 0.5 },
        head: true,
    };

    /// Frames from `index` on, one for each of `faces`, at the page's 15 a
    /// second.
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

    fn range(ask: Ask, hold_ms: u32, frames: Vec<Frame>) -> Range {
        Range {
            ask,
            hold_ms,
            before: Vec::new(),
            frames,
            whole: true,
        }
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

    /// The status of one range read alone.
    fn status(range: Range) -> Status {
        read(&[range])[0].status
    }

    /// A face held in the oval through the hold follows it, with the face of
    /// every frame.
    #[test]
    fn a_face_held_through_its_hold_follows_it() {
        let got = read(&[range(OVAL, 800, frames(0, held(13)))]);
        assert_eq!(got[0].status, Status::Followed);
        assert_eq!(got[0].faces.len(), 13);
        assert_eq!(got[0].faces[4].0, 4);
    }

    /// A face lost for a few frames is forgiven, as the page forgives it; lost
    /// for longer, the guide is not followed, and how says why.
    #[test]
    fn a_break_counts_past_the_page_s_grace() {
        let mut faces = held(13);
        for frame in &mut faces[5..9] {
            frame.clear();
        }
        let got = read(&[range(OVAL, 800, frames(0, faces.clone()))]);
        assert_eq!(got[0].status, Status::Followed);
        assert_eq!(got[0].faces.len(), 9);

        faces[9].clear();
        assert_eq!(status(range(OVAL, 800, frames(0, faces))), Status::NoFace);

        let mut faces = held(13);
        for frame in &mut faces[3..9] {
            frame.push(face(200.0, 200.0, 0.4, 0.0));
        }
        assert_eq!(
            status(range(OVAL, 800, frames(0, faces))),
            Status::ExtraFace
        );

        let mut faces = held(13);
        for frame in &mut faces[3..9] {
            *frame = vec![centred(0.5)];
        }
        assert_eq!(status(range(OVAL, 800, frames(0, faces))), Status::OffOval);
    }

    /// A break is counted in frames too: times stamped closer than the page
    /// draws frames do not stretch the grace.
    #[test]
    fn a_break_is_counted_in_frames_too() {
        let mut list = frames(0, held(13));
        for (i, frame) in list.iter_mut().enumerate() {
            frame.ms = i as u32 * 20;
            if (3..9).contains(&i) {
                frame.faces.clear();
            }
        }
        assert_eq!(status(range(OVAL, 200, list)), Status::NoFace);
    }

    /// Frames that span less than the hold, or a range the video does not
    /// have whole, do not hold it.
    #[test]
    fn a_short_range_does_not_hold_its_guide() {
        assert_eq!(
            status(range(OVAL, 800, frames(0, held(6)))),
            Status::ShortHold
        );
        let mut cut = range(OVAL, 300, frames(0, held(6)));
        cut.whole = false;
        assert_eq!(status(cut), Status::ShortHold);
        assert_eq!(status(range(OVAL, 0, Vec::new())), Status::ShortHold);
        assert_eq!(status(range(OVAL, 0, frames(0, held(1)))), Status::Followed);
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
            let mut turn = range(Ask::Turn { degrees: -25 }, 500, frames(17, faces));
            turn.before = frames(13, vec![turned_by(offset_of(4.0 + degrees)); 4]);
            read(&[range(OVAL, 800, oval.clone()), turn])[1].status
        };
        assert_eq!(turn(-25.0), Status::Followed);
        assert_eq!(turn(-23.0), Status::Followed);
        assert_eq!(turn(-15.0), Status::WrongTurn);
        assert_eq!(turn(20.0), Status::WrongTurn);
    }

    /// With no oval before it, a turn is read from straight on.
    #[test]
    fn a_turn_with_no_oval_before_reads_from_straight() {
        let faces = vec![turned_by(offset_of(30.0)); 8];
        let turn = range(Ask::Turn { degrees: 30 }, 500, frames(0, faces));
        assert_eq!(status(turn), Status::Followed);
    }

    /// A static guide's frames do not move the head: a static oval between
    /// the face guide and the turn leaves the turn read against the face's.
    #[test]
    fn a_static_guide_does_not_move_the_head() {
        let oval = range(OVAL, 800, frames(0, held(13)));
        let still = Ask::Shape {
            shape: Shape::Oval { width: 0.5 },
            head: false,
        };
        let tilted = range(still, 500, frames(13, vec![turned_by(offset_of(-20.0)); 8]));
        let turn = range(
            Ask::Turn { degrees: -20 },
            500,
            frames(21, vec![turned_by(offset_of(-20.0)); 8]),
        );
        let got = read(&[oval, tilted, turn]);
        assert_eq!(got[1].status, Status::Followed);
        assert_eq!(got[2].status, Status::Followed);
    }

    /// A face held still in the oval reads straight: a guide of no degrees
    /// follows it.
    #[test]
    fn no_degrees_asks_the_head_straight() {
        assert!(turned(7.0, 0) && turned(-12.0, 0));
        assert!(!turned(14.0, 0));
        assert!(turned(-22.5, -25) && !turned(22.5, -25));
        assert!(!turned(0.0, 10));
    }
}
