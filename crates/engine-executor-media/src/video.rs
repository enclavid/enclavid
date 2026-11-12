//! A video: the applicant's WebM, read once when it opens — its VP8 track
//! found, the track's frames listed and each of its blocks' frames kept — and
//! decoded by libvpx when a region first asks for a frame: on from the frame
//! decoded last where the frames between lead to it, else from the nearest
//! keyframe before it.

use std::io::Cursor;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};

use enclavid_media::protocol::{Failure, FrameInfo, PictureBounds, Region, Size};
use engine_types::limits::MAX_VIDEO_FRAMES;
use webm_iterable::WebmIterator;
use webm_iterable::matroska_spec::{Block, Master, MatroskaSpec, SimpleBlock};

use crate::picture::{self, Planes, Rgb};

unsafe extern "C" {
    fn enclavid_vpx_keyframe_size(
        data: *const u8,
        size: u32,
        width: *mut u32,
        height: *mut u32,
    ) -> i32;
    fn enclavid_vpx_start() -> i32;
    fn enclavid_vpx_decode(data: *const u8, size: u32) -> i32;
    #[allow(clippy::too_many_arguments)]
    fn enclavid_vpx_picture(
        width: *mut u32,
        height: *mut u32,
        y: *mut *const u8,
        u: *mut *const u8,
        v: *mut *const u8,
        y_stride: *mut i32,
        u_stride: *mut i32,
        v_stride: *mut i32,
    ) -> i32;
    fn enclavid_vpx_end();
}

/// The most blocks of the track the reading keeps: a decode reads every block
/// from a keyframe, shown or not, so frames the encoder hides are bounded too.
const MAX_BLOCKS: usize = 2 * MAX_VIDEO_FRAMES as usize;

/// A track of video, as a track entry says its type.
const VIDEO_TRACK: u64 = 1;

/// The nanoseconds a tick of the container's clock is where it does not say.
const DEFAULT_TICK_NS: u64 = 1_000_000;

/// Whether this process has opened a video: the shim holds one decoder a
/// process, so one opens.
static OPENED: AtomicBool = AtomicBool::new(false);

/// One frame of the video, as the container lists it.
struct Listed {
    info: FrameInfo,
    /// The block of the track it is, counted from 0.
    block: usize,
    /// The block of the nearest keyframe at or before it; `None` for a frame
    /// before the track's first keyframe, which nothing decodes.
    key: Option<usize>,
}

/// A video, opened.
pub struct Video {
    /// The size of its frames.
    pub size: Size,
    /// What the regions of its frames are held to.
    bounds: PictureBounds,
    listed: Vec<Listed>,
    /// The frames of the track's blocks, one after another.
    data: Vec<u8>,
    /// Where each block's frame lies in `data`.
    blocks: Vec<Range<usize>>,
    /// The block the decoder decodes next.
    next: usize,
    /// Whether the decoder decoded every block before `next` since the
    /// keyframe it last started at, so a decode can go on from `next`.
    on_track: bool,
    /// The frame whose picture the decoder holds.
    holding: Option<u32>,
    /// That picture as RGB8, and its size, once a region of it was asked.
    rgb: Option<(Size, Vec<u8>)>,
    /// Whether the decoder is started.
    started: bool,
}

impl Video {
    /// Read `webm` once: its first VP8 track — its frames within `bounds` —
    /// and the frames of that track's blocks, up to the first the reading
    /// cannot take.
    pub fn open(webm: Vec<u8>, bounds: PictureBounds) -> Result<Self, Failure> {
        if OPENED.swap(true, Ordering::Relaxed) {
            return Err(Failure::OutOfTurn);
        }
        let mut tags = WebmIterator::new(Cursor::new(webm.as_slice()), &[]);
        // A tag's bytes are held before they are read: never more of them
        // than the file has.
        tags.set_max_allowable_tag_size(Some(webm.len()));
        let mut reading = Reading::new(bounds);
        for tag in tags {
            let Ok(tag) = tag else {
                break;
            };
            if !reading.take(&tag)? {
                break;
            }
        }
        let (_, size) = reading.track.ok_or(Failure::NotMedia)?;
        Ok(Self {
            size,
            bounds,
            listed: reading.listed,
            data: reading.data,
            blocks: reading.blocks,
            next: 0,
            on_track: false,
            holding: None,
            rgb: None,
            started: false,
        })
    }

    /// Its frames, as the container lists them.
    pub fn frames(&self) -> Vec<FrameInfo> {
        self.listed.iter().map(|listed| listed.info).collect()
    }

    /// `region` of frame `frame` as RGB8, decoding the frame first where the
    /// decoder does not hold it.
    pub fn region(&mut self, frame: u32, region: &Region) -> Result<Vec<u8>, Failure> {
        let listed = self.listed.get(frame as usize).ok_or(Failure::OutOfTurn)?;
        if region.rgb_len(self.bounds).is_none() {
            return Err(Failure::PastBounds);
        }
        if self.holding != Some(frame) {
            let (block, key) = (listed.block, listed.key.ok_or(Failure::Corrupt)?);
            self.holding = None;
            self.rgb = None;
            self.decode_to(block, key)?;
            self.holding = Some(frame);
        }
        if self.rgb.is_none() {
            let planes = self.planes().ok_or(Failure::Corrupt)?;
            let size = Size {
                width: planes.width,
                height: planes.height,
            };
            let rgb = picture::rgb_of(&planes).ok_or(Failure::Corrupt)?;
            self.rgb = Some((size, rgb));
        }
        let (size, rgb) = self.rgb.as_ref().ok_or(Failure::Corrupt)?;
        let picture = Rgb {
            width: size.width,
            height: size.height,
            pixels: rgb,
        };
        picture::rgb_region(&picture, region).ok_or(Failure::Corrupt)
    }

    /// Have the decoder hold the picture of the track's block `block`, whose
    /// nearest keyframe at or before it is block `key`.
    fn decode_to(&mut self, block: usize, key: usize) -> Result<(), Failure> {
        let goes_on = self.started && self.on_track && key <= self.next && self.next <= block;
        if !goes_on {
            self.restart()?;
            self.next = key;
        }
        let mut shown = false;
        while self.next <= block {
            shown = self
                .decode(self.next)
                .inspect_err(|_| self.on_track = false)?;
            self.next += 1;
        }
        let planes = self.planes().ok_or(Failure::Corrupt)?;
        if !shown || (planes.width, planes.height) != (self.size.width, self.size.height) {
            return Err(Failure::Corrupt);
        }
        Ok(())
    }

    /// Decode the track's block `block`: whether it shows a picture.
    fn decode(&mut self, block: usize) -> Result<bool, Failure> {
        let frame = self
            .blocks
            .get(block)
            .and_then(|range| self.data.get(range.clone()))
            .ok_or(Failure::Corrupt)?;
        let length = u32::try_from(frame.len()).map_err(|_| Failure::Corrupt)?;
        // SAFETY: `frame` is `length` bytes of `data`, which stays as it is
        // while the decoder lives; the decoder reads them during the call
        // alone.
        match unsafe { enclavid_vpx_decode(frame.as_ptr(), length) } {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(Failure::Corrupt),
        }
    }

    /// Start the decoder afresh, for the keyframe it is given next.
    fn restart(&mut self) -> Result<(), Failure> {
        if self.started {
            // SAFETY: ends the one decoder this process started.
            unsafe { enclavid_vpx_end() }
            self.started = false;
        }
        // SAFETY: starts the one decoder this process has, none being started.
        if unsafe { enclavid_vpx_start() } != 0 {
            return Err(Failure::Corrupt);
        }
        self.started = true;
        self.on_track = true;
        Ok(())
    }

    /// The picture the decoder gave last, as planes over its own buffers:
    /// borrowed from `self`, so no decode — which needs `&mut self` — can
    /// replace it while they are read. `None` when there is none, or its
    /// strides are not of an I420 picture of its size.
    fn planes(&self) -> Option<Planes<'_>> {
        if !self.started {
            return None;
        }
        let (mut width, mut height) = (0u32, 0u32);
        let (mut y, mut u, mut v) = (std::ptr::null(), std::ptr::null(), std::ptr::null());
        let (mut y_stride, mut u_stride, mut v_stride) = (0i32, 0i32, 0i32);
        // SAFETY: writes the picture's fields through pointers to these locals
        // and keeps none of them.
        let read = unsafe {
            enclavid_vpx_picture(
                &mut width,
                &mut height,
                &mut y,
                &mut u,
                &mut v,
                &mut y_stride,
                &mut u_stride,
                &mut v_stride,
            )
        };
        if read != 0 || width == 0 || height == 0 || y.is_null() || u.is_null() || v.is_null() {
            return None;
        }
        let (w, h) = (width as usize, height as usize);
        let (cw, ch) = (w.div_ceil(2), h.div_ceil(2));
        let y_stride = usize::try_from(y_stride).ok().filter(|&s| s >= w)?;
        let uv_stride = usize::try_from(u_stride)
            .ok()
            .filter(|&s| s >= cw && i32::try_from(s) == Ok(v_stride))?;
        let y_len = y_stride.checked_mul(h - 1)?.checked_add(w)?;
        let uv_len = uv_stride.checked_mul(ch - 1)?.checked_add(cw)?;
        // SAFETY: libvpx's I420 picture holds `stride` bytes a row for each
        // row of each plane — at least its width, as just checked — so each
        // slice lies inside its plane; and the picture stays as it is until
        // the next decode, which the borrow of `self` rules out. The stride's
        // padding past a row's border, which libvpx never writes, lies inside
        // the slices too; nothing reads it, a row being read to its width.
        let (y, u, v) = unsafe {
            (
                std::slice::from_raw_parts(y, y_len),
                std::slice::from_raw_parts(u, uv_len),
                std::slice::from_raw_parts(v, uv_len),
            )
        };
        Some(Planes {
            width,
            height,
            y,
            y_stride,
            u,
            v,
            uv_stride,
        })
    }

    pub fn end(self) {
        if self.started {
            // SAFETY: ends the one decoder, after its last decode.
            unsafe { enclavid_vpx_end() }
        }
    }
}

/// A track entry, as far as it has been read.
#[derive(Default)]
struct Entry {
    /// The number its blocks name it by.
    number: u64,
    /// What it carries: [`VIDEO_TRACK`] for video.
    kind: u64,
    /// Its codec.
    codec: String,
    /// Its pictures' width in pixels.
    width: u64,
    /// Its pictures' height in pixels.
    height: u64,
}

/// What reading a WebM has found so far.
struct Reading {
    /// What the video's frames are held to.
    bounds: PictureBounds,
    /// The nanoseconds a tick of the container's clock is.
    tick_ns: u64,
    /// The track entry being read.
    entry: Entry,
    /// The track taken as the video's: its number and its pictures' size.
    track: Option<(u64, Size)>,
    /// The time of the cluster being read, in ticks.
    cluster: u64,
    /// The time of the first frame shown, in ticks.
    first: Option<i64>,
    /// The block of the nearest keyframe so far.
    key: Option<usize>,
    listed: Vec<Listed>,
    /// The frames of the track's blocks, one after another.
    data: Vec<u8>,
    /// Where each block's frame lies in `data`.
    blocks: Vec<Range<usize>>,
}

impl Reading {
    fn new(bounds: PictureBounds) -> Self {
        Self {
            bounds,
            tick_ns: DEFAULT_TICK_NS,
            entry: Entry::default(),
            track: None,
            cluster: 0,
            first: None,
            key: None,
            listed: Vec::new(),
            data: Vec::new(),
            blocks: Vec::new(),
        }
    }

    /// Take the file's next tag: `false` where the reading ends there — its
    /// bounds met, or a block of the track that does not hold a frame it
    /// decodes. A track past the bounds refuses the file.
    fn take(&mut self, tag: &MatroskaSpec) -> Result<bool, Failure> {
        match tag {
            MatroskaSpec::TimestampScale(ns) => self.tick_ns = *ns,
            MatroskaSpec::TrackEntry(Master::Start) => self.entry = Entry::default(),
            MatroskaSpec::TrackNumber(number) => self.entry.number = *number,
            MatroskaSpec::TrackType(kind) => self.entry.kind = *kind,
            MatroskaSpec::CodecID(codec) => self.entry.codec.clone_from(codec),
            MatroskaSpec::PixelWidth(width) => self.entry.width = *width,
            MatroskaSpec::PixelHeight(height) => self.entry.height = *height,
            MatroskaSpec::TrackEntry(Master::End) => self.end_entry()?,
            MatroskaSpec::Timestamp(ticks) => self.cluster = *ticks,
            MatroskaSpec::SimpleBlock(_) => {
                let Ok(block) = SimpleBlock::try_from(tag) else {
                    return Ok(false);
                };
                return Ok(self.block(
                    block.track,
                    block.timestamp,
                    block.lacing.is_some(),
                    block.raw_frame_data(),
                ));
            }
            MatroskaSpec::Block(_) => {
                let Ok(block) = Block::try_from(tag) else {
                    return Ok(false);
                };
                return Ok(self.block(
                    block.track,
                    block.timestamp,
                    block.lacing.is_some(),
                    block.raw_frame_data(),
                ));
            }
            _ => {}
        }
        Ok(true)
    }

    /// The track entry just read, taken as the video's where it is the first
    /// VP8 track to say its pictures' size.
    fn end_entry(&mut self) -> Result<(), Failure> {
        let entry = &self.entry;
        if self.track.is_some()
            || entry.kind != VIDEO_TRACK
            || entry.codec != "V_VP8"
            || entry.width == 0
            || entry.height == 0
        {
            return Ok(());
        }
        let size = Size {
            width: u32::try_from(entry.width).map_err(|_| Failure::PastBounds)?,
            height: u32::try_from(entry.height).map_err(|_| Failure::PastBounds)?,
        };
        if !size.within(self.bounds) {
            return Err(Failure::PastBounds);
        }
        self.track = Some((entry.number, size));
        Ok(())
    }

    /// A block of track `track`, `relative` ticks from its cluster's time,
    /// whose frame is `frame` — or several, where it is `laced`: `false`
    /// where the reading ends there. A keyframe that says its picture is of
    /// another size than the track's ends it, so the decoder never allocates
    /// for a picture of another size than the one the bounds were checked on.
    fn block(&mut self, track: u64, relative: i16, laced: bool, frame: &[u8]) -> bool {
        let Some((number, size)) = self.track else {
            return true;
        };
        if track != number {
            return true;
        }
        if laced
            || self.listed.len() >= MAX_VIDEO_FRAMES as usize
            || self.blocks.len() >= MAX_BLOCKS
        {
            return false;
        }
        let Some(tag) = Tag::of(frame) else {
            return false;
        };
        let block = self.blocks.len();
        if tag.keyframe {
            if keyframe_size(frame) != Some(size) {
                return false;
            }
            self.key = Some(block);
        }
        let start = self.data.len();
        self.data.extend_from_slice(frame);
        self.blocks.push(start..self.data.len());
        if tag.shown {
            let ticks = i64::try_from(self.cluster)
                .unwrap_or(i64::MAX)
                .saturating_add(i64::from(relative));
            let first = *self.first.get_or_insert(ticks);
            let ms = u64::try_from(ticks.saturating_sub(first))
                .unwrap_or(0)
                .saturating_mul(self.tick_ns)
                / 1_000_000;
            self.listed.push(Listed {
                info: FrameInfo {
                    timestamp_ms: u32::try_from(ms).unwrap_or(u32::MAX),
                    keyframe: tag.keyframe,
                },
                block,
                key: self.key,
            });
        }
        true
    }
}

/// The size keyframe `data` says its picture is, read as the decoder reads it
/// before it allocates for one; `None` where the decoder does not read a
/// keyframe there.
fn keyframe_size(data: &[u8]) -> Option<Size> {
    let length = u32::try_from(data.len()).ok()?;
    let (mut width, mut height) = (0u32, 0u32);
    // SAFETY: reads no more than the first ten of the `length` bytes `data`
    // holds, writes the two locals, and keeps nothing.
    let read =
        unsafe { enclavid_vpx_keyframe_size(data.as_ptr(), length, &mut width, &mut height) };
    (read == 1).then_some(Size { width, height })
}

/// What a VP8 frame's tag — its first three bytes — says of it.
struct Tag {
    /// Whether it is written whole.
    keyframe: bool,
    /// Whether it is shown, not only decoded for the frames after it.
    shown: bool,
}

impl Tag {
    /// The tag `data` begins with; `None` for fewer than its three bytes.
    fn of(data: &[u8]) -> Option<Self> {
        let &[first, _, _, ..] = data else {
            return None;
        };
        Some(Self {
            keyframe: first & 1 == 0,
            shown: (first >> 4) & 1 == 1,
        })
    }
}
