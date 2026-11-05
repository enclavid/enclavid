//! What a round and the coprocess decoding one of its captures say to each
//! other over their channel (`coprocess-channel`). The round opens the capture
//! once — a photo or a video — and then asks for regions of its pictures: the
//! photo's, or a frame's of the video, by its index. The coprocess decodes what
//! a region needs when it is asked for, and nothing before.
//!
//! What the coprocess answers is taken as the applicant's bytes are: held to
//! what a decode can give before the round makes anything of it — an open's to
//! [`Opened::fits`], a region's pixels to exactly as many as [`Region::rgb_len`].
//!
//! A failure ends the coprocess, but for a picture that does not decode: that
//! is answered, and the next request read.

use engine_types::limits::{MAX_PICTURE_LONG_SIDE, MAX_PICTURE_SHORT_SIDE, MAX_VIDEO_FRAMES};
use serde::{Deserialize, Serialize};
pub use serde_bytes::{ByteBuf, Bytes};

#[cfg(test)]
mod tests;

/// The most bytes one open carries: the applicant's upload, held to the media
/// budget where it arrives, with room above it.
pub const MAX_OPEN_BYTES: usize = 16 << 20;

/// The most bytes a request is, as the channel carries it: an open at its
/// bound, and room for the rest of it.
pub const MAX_REQUEST_BYTES: usize = MAX_OPEN_BYTES + 1024;

/// The most pixels one region gives: a picture at its bounds.
pub const MAX_REGION_PIXELS: u64 = MAX_PICTURE_LONG_SIDE as u64 * MAX_PICTURE_SHORT_SIDE as u64;

/// The most bytes a response is, as the channel carries it: a region at its
/// bound, and room for the rest of it — more than a video's frames take.
pub const MAX_RESPONSE_BYTES: usize = MAX_REGION_PIXELS as usize * 3 + 1024;

/// What a capture is, as the round opens it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Kind {
    /// A JPEG.
    Photo,
    /// A WebM of VP8 frames.
    Video,
}

/// A region of a picture, and the size it is resampled to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Region {
    /// The crop's left edge, in the picture's pixels.
    pub x: u32,
    /// The crop's top edge, in the picture's pixels.
    pub y: u32,
    /// The crop's width.
    pub w: u32,
    /// The crop's height.
    pub h: u32,
    /// The width it is resampled to.
    pub out_w: u32,
    /// The height it is resampled to.
    pub out_h: u32,
    /// How it is resampled.
    pub mode: ResizeMode,
}

/// How a region is brought to the size it is resampled to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResizeMode {
    /// Each output pixel is the source pixel nearest its place.
    Nearest,
    /// Each output pixel is the mean of the source pixels it covers.
    Average,
}

impl Region {
    /// The bytes of RGB8 the region gives — at least a pixel each way — or
    /// `None` past [`MAX_REGION_PIXELS`].
    pub fn rgb_len(&self) -> Option<usize> {
        let pixels = u64::from(self.out_w.max(1)) * u64::from(self.out_h.max(1));
        (pixels <= MAX_REGION_PIXELS).then(|| pixels as usize * 3)
    }

    /// The region with its crop held inside a picture of `width` × `height`:
    /// its corner inside the picture, its far edges no farther than the
    /// picture's, and a pixel at least each way.
    pub fn held(&self, width: u32, height: u32) -> Region {
        let x = self.x.min(width.saturating_sub(1));
        let y = self.y.min(height.saturating_sub(1));
        Region {
            x,
            y,
            w: self.w.clamp(1, (width - x).max(1)),
            h: self.h.clamp(1, (height - y).max(1)),
            ..*self
        }
    }
}

/// What the round asks. `B` is the capture's bytes in an open: the round sends
/// them from where it holds them, as [`Bytes`], and the coprocess reads them
/// into a [`ByteBuf`] of its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request<B = ByteBuf> {
    /// The capture to decode, of its kind: the first request, and the only
    /// one of its kind.
    Open { kind: Kind, bytes: B },
    /// A region of a picture, as RGB8.
    Region {
        /// Which: a video's frame by its index, from 0; 0 for a photo.
        frame: u32,
        /// The region.
        region: Region,
    },
}

/// The coprocess's response to a request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    /// To an open: what the capture holds.
    Opened(Opened),
    /// To a region: its RGB8.
    Pixels(#[serde(with = "serde_bytes")] Vec<u8>),
    /// To either: why it is answered with nothing but this.
    Failed(Failure),
}

/// A picture's size in pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Size {
    pub width: u32,
    pub height: u32,
}

impl Size {
    /// Whether a decode gives a picture of this size: a pixel at least, its
    /// longer side no more than [`MAX_PICTURE_LONG_SIDE`] and its shorter no
    /// more than [`MAX_PICTURE_SHORT_SIDE`], whichever way it is turned.
    pub fn within_bounds(&self) -> bool {
        let (long, short) = if self.width >= self.height {
            (self.width, self.height)
        } else {
            (self.height, self.width)
        };
        short >= 1 && long <= MAX_PICTURE_LONG_SIDE && short <= MAX_PICTURE_SHORT_SIDE
    }
}

/// What a video's container says of one of its frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameInfo {
    /// When it is shown, in milliseconds from the video's first frame.
    pub timestamp_ms: u32,
    /// Whether the encoder wrote it whole, not as a change to the frames
    /// before it.
    pub keyframe: bool,
}

/// What the open of a capture tells of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Opened {
    /// A photo, and the size it decodes at.
    Photo(Size),
    /// A video: the size of its frames, and its frames, in order.
    Video { size: Size, frames: Vec<FrameInfo> },
}

impl Opened {
    /// Whether a decode can tell this of a capture of `kind`: of that kind, a
    /// size within the bounds, and no more frames than a decode reads.
    pub fn fits(&self, kind: Kind) -> bool {
        match (self, kind) {
            (Opened::Photo(size), Kind::Photo) => size.within_bounds(),
            (Opened::Video { size, frames }, Kind::Video) => {
                size.within_bounds() && frames.len() <= MAX_VIDEO_FRAMES as usize
            }
            _ => false,
        }
    }
}

/// Why a request is answered with nothing but this. Fixed cases: what the
/// decoder made of the applicant's bytes crosses as one of these, never in its
/// own words.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Failure {
    /// Not what its kind is: not a JPEG, or not a WebM with a VP8 track.
    NotMedia,
    /// Past a bound: a picture too large, a region too large.
    PastBounds,
    /// A picture that does not decode.
    Corrupt,
    /// A request out of turn: an open after the first, anything before it, a
    /// frame the capture does not have.
    OutOfTurn,
}
