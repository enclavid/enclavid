//! The pictures of the applicant's captures, served: `photo.image` and
//! `video.frames` have the capture decoded in a process of its own beside the
//! round's — the media coprocess — started the first time the round asks for
//! the capture's pictures, once a capture; an `image`'s `pixels` ask that
//! process for them, and it decodes the picture then.
//!
//! The coprocess is where the applicant's media is parsed and decoded, so what
//! it answers is taken as the applicant's bytes are: bounded as it is read,
//! and what it says of them — not a photo, not a video, a picture that does
//! not decode — is what the component sees: no image, no frames, `none`. Its
//! end is taken so too, since the applicant's bytes can end it: a coprocess
//! gone before it answers leaves its capture undecoded from there on, and the
//! round goes on. A kill for memory is such an end as well: the coprocesses
//! decoding a round's captures are the platform's, held to a limit of their
//! own beside the round's composition, and the first the kernel takes, alone,
//! where that or the guest's memory runs out
//! (`engine_supervisor::CoprocessKind`). What no coprocess answers — bytes
//! that are no response, a response to another request — traps the round as
//! [`DecoderFailed`]: the platform's failure, not the policy's.

use std::collections::HashMap;
use std::future::Future;
use std::os::unix::net::UnixStream;
use std::pin::Pin;
use std::sync::Arc;

use coprocess_channel::{Channel, ChannelError};
use enclavid_media::protocol::{
    Bytes, Failure, FrameInfo, Kind, MAX_OPEN_BYTES, Opened, Region, Request, ResizeMode, Response,
    Size, max_response_bytes,
};
use engine_types::limits::MAX_MEDIA_DECODES;
use wasmtime::component::Resource;

use crate::enclavid::host::media::{self, HostImage};
use crate::state::HostState;

/// Where a round's captures are decoded: each in a process of its own.
pub trait MediaStarter: Send + Sync {
    /// Start the process the round's capture `decode` is decoded in — counted
    /// from 0, below [`MAX_MEDIA_DECODES`] — and hand back the socket to it.
    /// Asked once per capture.
    fn start(
        &self,
        decode: u32,
    ) -> Pin<Box<dyn Future<Output = wasmtime::Result<UnixStream>> + Send + '_>>;
}

/// A capture the round decodes: its kind, and its content hash.
pub(crate) type Capture = (Kind, [u8; 32]);

/// A capture the round decodes, as its open found it.
#[derive(Clone)]
pub(crate) enum Decoded {
    /// A photo, and the size it decodes at.
    Photo(Size),
    /// A video, the size of its frames, and its frames as the container lists
    /// them.
    Video(Size, Arc<[FrameInfo]>),
    /// Not of its kind, past the bounds, or its process gone before it
    /// answered: no pictures.
    Nothing,
}

/// A capture the round opened.
struct Decoding {
    /// What its open found.
    decoded: Decoded,
    /// The channel to the process decoding it, while that process answers:
    /// none for a capture with no pictures, or one whose process has ended
    /// since.
    channel: Option<Channel>,
}

/// The captures the round decodes, each opened once.
#[derive(Default)]
pub(crate) struct Decodes(HashMap<Capture, Decoding>);

impl Decodes {
    /// What the open of `capture` found, where the round opened it.
    pub(crate) fn get(&self, capture: &Capture) -> Option<Decoded> {
        self.0.get(capture).map(|opened| opened.decoded.clone())
    }

    /// The channel to the process decoding `capture`, while it answers.
    fn channel(&mut self, capture: &Capture) -> Option<&mut Channel> {
        self.0.get_mut(capture)?.channel.as_mut()
    }

    /// The process decoding `capture` gone: nothing is asked of it again.
    fn ended(&mut self, capture: &Capture) {
        if let Some(opened) = self.0.get_mut(capture) {
            opened.channel = None;
        }
    }
}

/// The round's failure where the process decoding a capture answered what no
/// such process answers — bytes that are no response, a response to another
/// request — or could not be spoken to: the platform's, never the policy's.
/// It unwinds the guest as the `wasmtime::Error` every host failure is, and
/// the round's end tells it apart by its type.
#[derive(Debug)]
pub struct DecoderFailed {
    /// What it answered, or why it could not be spoken to.
    pub why: String,
}

impl std::fmt::Display for DecoderFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the process decoding a capture failed: {}", self.why)
    }
}

impl std::error::Error for DecoderFailed {}

/// Backing rep for an `image` handle: a picture of a capture the round
/// decodes.
pub struct ImageRep {
    /// The capture it is a picture of.
    capture: Capture,
    /// Which: a video's frame, by its index; 0 for a photo.
    frame: u32,
    size: Size,
}

impl ImageRep {
    /// The picture of the photo `capture`.
    pub(crate) fn photo(capture: Capture, size: Size) -> Self {
        Self {
            capture,
            frame: 0,
            size,
        }
    }

    /// The frame `frame` of the video `capture`.
    pub(crate) fn frame(capture: Capture, frame: u32, size: Size) -> Self {
        Self {
            capture,
            frame,
            size,
        }
    }
}

/// Open `capture`, its `bytes`, in a process of its own, and keep what the
/// open found for the round. Traps past the round's [`MAX_MEDIA_DECODES`].
pub(crate) async fn open(
    state: &mut HostState,
    capture: Capture,
    bytes: Arc<Vec<u8>>,
) -> wasmtime::Result<Decoded> {
    let decode = state.decodes.0.len();
    if decode >= MAX_MEDIA_DECODES {
        return Err(wasmtime::Error::msg(format!(
            "a capture past the round's {MAX_MEDIA_DECODES} to decode"
        )));
    }
    let (kind, _) = capture;
    let bounds = state.picture_bounds;
    // More than an open carries is more than an upload can be.
    let (decoded, channel) = if bytes.len() > MAX_OPEN_BYTES {
        (Decoded::Nothing, None)
    } else {
        let socket = state.media.start(u32::try_from(decode)?).await?;
        let mut channel = Channel::new(socket).map_err(failed)?;
        let open = Request::Open {
            kind,
            bytes: Bytes::new(&bytes),
            bounds,
        };
        match answered(channel.ask(&open, max_response_bytes(bounds)).await)? {
            Some(Response::Opened(opened)) if opened.fits(kind, bounds) => match opened {
                Opened::Photo(size) => (Decoded::Photo(size), Some(channel)),
                Opened::Video { size, frames } => {
                    (Decoded::Video(size, frames.into()), Some(channel))
                }
            },
            Some(Response::Failed(Failure::NotMedia | Failure::PastBounds | Failure::Corrupt))
            | None => (Decoded::Nothing, None),
            Some(Response::Failed(failure)) => return Err(failed(format!("{failure:?}"))),
            Some(_) => return Err(failed("a response no open of the capture has")),
        }
    };
    let opened = Decoding {
        decoded: decoded.clone(),
        channel,
    };
    state.decodes.0.insert(capture, opened);
    Ok(decoded)
}

impl HostState {
    /// `region` of `image` as RGB8, from the process its capture is decoded
    /// in; `None` where it does not decode, or that process has ended — then
    /// or before. Traps for a region larger, either way, than a picture can
    /// be.
    async fn read(
        &mut self,
        image: &Resource<ImageRep>,
        region: Region,
    ) -> wasmtime::Result<Option<Vec<u8>>> {
        let bounds = self.picture_bounds;
        let Some(length) = region.rgb_len(bounds) else {
            return Err(wasmtime::Error::msg(
                "a region larger than a picture can be",
            ));
        };
        let image = self.table.get(image)?;
        let (capture, frame) = (image.capture, image.frame);
        let Some(channel) = self.decodes.channel(&capture) else {
            return Ok(None);
        };
        let request: Request = Request::Region { frame, region };
        match answered(channel.ask(&request, max_response_bytes(bounds)).await)? {
            Some(Response::Pixels(rgb)) if rgb.len() == length => Ok(Some(rgb)),
            Some(Response::Failed(Failure::Corrupt)) => Ok(None),
            Some(Response::Failed(failure)) => Err(failed(format!("{failure:?}"))),
            Some(_) => Err(failed("a response no region of the picture has")),
            None => {
                self.decodes.ended(&capture);
                Ok(None)
            }
        }
    }
}

/// What an ask of the process decoding a capture came to: its response, or
/// `None` where the process ended before it answered. Anything else the
/// channel reads is no answer of a decoder's.
fn answered(asked: Result<Response, ChannelError>) -> wasmtime::Result<Option<Response>> {
    match asked {
        Ok(response) => Ok(Some(response)),
        Err(ChannelError::Io(_)) => Ok(None),
        Err(e) => Err(failed(e)),
    }
}

/// The round's [`DecoderFailed`], for `why`.
fn failed(why: impl std::fmt::Display) -> wasmtime::Error {
    wasmtime::Error::new(DecoderFailed {
        why: why.to_string(),
    })
}

/// The region `options` pick of a picture of `size`: the pixels the crop
/// spans, the whole picture where there is none, brought to the size the
/// resize asks — or kept at their own, pixel for pixel, where there is none.
/// `None` where the crop spans fewer pixels than it must; an error for a crop
/// whose numbers are not finite.
fn picked(size: Size, options: &media::PixelsOptions) -> wasmtime::Result<Option<Region>> {
    let (x, y, w, h) = match &options.crop {
        Some(crop) => {
            let rect = &crop.rect;
            if ![rect.x, rect.y, rect.width, rect.height]
                .iter()
                .all(|n| n.is_finite())
            {
                return Err(wasmtime::Error::msg("a crop whose numbers are not finite"));
            }
            let (x, w) = spanned(rect.x, rect.width, size.width);
            let (y, h) = spanned(rect.y, rect.height, size.height);
            if w < crop.min_width.unwrap_or(1) || h < crop.min_height.unwrap_or(1) {
                return Ok(None);
            }
            (x, y, w, h)
        }
        None => (0, 0, size.width, size.height),
    };
    let (out_w, out_h, mode) = match &options.resize {
        Some(resize) => (
            resize.size.width,
            resize.size.height,
            match resize.mode {
                media::ResizeMode::Nearest => ResizeMode::Nearest,
                media::ResizeMode::Average => ResizeMode::Average,
            },
        ),
        None => (w, h, ResizeMode::Nearest),
    };
    Ok(Some(Region {
        x,
        y,
        w,
        h,
        out_w,
        out_h,
        mode,
    }))
}

/// The pixels a span of `side` pixels covers from `start` for `length`, both
/// fractions of it: its first, on the pixel `start` falls in, and how many, to
/// the pixel past its end — held to the side, a pixel at least.
fn spanned(start: f32, length: f32, side: u32) -> (u32, u32) {
    let pixels = f64::from(side);
    let from = f64::from(start).clamp(0.0, 1.0);
    let to = (f64::from(start) + f64::from(length)).clamp(from, 1.0);
    let first = ((from * pixels).floor() as u32).min(side.saturating_sub(1));
    let past = ((to * pixels).ceil() as u32).clamp(first + 1, side.max(first + 1));
    (first, past - first)
}

impl HostImage for HostState {
    async fn size(&mut self, self_: Resource<ImageRep>) -> wasmtime::Result<media::Size> {
        let size = self.table.get(&self_)?.size;
        Ok(media::Size {
            width: size.width,
            height: size.height,
        })
    }

    async fn all_pixels(&mut self, self_: Resource<ImageRep>) -> wasmtime::Result<Option<Vec<u8>>> {
        let options = media::PixelsOptions {
            crop: None,
            resize: None,
        };
        Ok(self.pixels(self_, options).await?.ok())
    }

    async fn pixels(
        &mut self,
        self_: Resource<ImageRep>,
        options: media::PixelsOptions,
    ) -> wasmtime::Result<Result<Vec<u8>, media::PixelsError>> {
        let size = self.table.get(&self_)?.size;
        let Some(region) = picked(size, &options)? else {
            return Ok(Err(media::PixelsError::TooSmall));
        };
        Ok(self
            .read(&self_, region)
            .await?
            .ok_or(media::PixelsError::Undecoded))
    }

    async fn drop(&mut self, rep: Resource<ImageRep>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIZE: Size = Size {
        width: 4,
        height: 2,
    };

    /// The crop `x`, `y`, `width`, `height` of the picture, at least
    /// `min` pixels each way where given, kept at its own size.
    fn crop(
        x: f32,
        y: f32,
        width: f32,
        height: f32,
        min: Option<(u32, u32)>,
    ) -> media::PixelsOptions {
        media::PixelsOptions {
            crop: Some(media::Crop {
                rect: media::Rect {
                    x,
                    y,
                    width,
                    height,
                },
                min_width: min.map(|(w, _)| w),
                min_height: min.map(|(_, h)| h),
            }),
            resize: None,
        }
    }

    /// A span starts on the pixel its start falls in and ends on the pixel
    /// past its end, held to the side, a pixel at least.
    #[test]
    fn a_span_covers_the_pixels_it_touches() {
        assert_eq!(spanned(0.0, 1.0, 4), (0, 4));
        assert_eq!(spanned(0.25, 0.5, 4), (1, 2));
        assert_eq!(spanned(0.3, 0.4, 4), (1, 2));
        assert_eq!(spanned(-1.0, 3.0, 4), (0, 4));
        assert_eq!(spanned(1.0, 0.5, 4), (3, 1));
        assert_eq!(spanned(0.5, 0.0, 4), (2, 1));
        assert_eq!(spanned(0.5, -0.25, 4), (2, 1));
    }

    /// A crop picks the pixels it spans, at their own size where nothing
    /// resizes them; one spanning fewer than it must picks nothing, and one
    /// whose numbers are not finite is refused.
    #[test]
    fn a_crop_picks_the_pixels_it_spans() {
        let right = Region {
            x: 2,
            y: 0,
            w: 2,
            h: 2,
            out_w: 2,
            out_h: 2,
            mode: ResizeMode::Nearest,
        };
        let half = |min| picked(SIZE, &crop(0.5, 0.0, 0.5, 1.0, min));
        assert_eq!(half(None).unwrap(), Some(right));
        assert_eq!(half(Some((2, 2))).unwrap(), Some(right));
        assert_eq!(half(Some((3, 1))).unwrap(), None);
        assert_eq!(half(Some((1, 3))).unwrap(), None);
        assert!(picked(SIZE, &crop(f32::NAN, 0.0, 0.5, 1.0, None)).is_err());
        assert!(picked(SIZE, &crop(0.0, 0.0, f32::INFINITY, 1.0, None)).is_err());
    }

    /// Without a crop the whole picture is picked, brought to the size a
    /// resize asks.
    #[test]
    fn no_crop_picks_the_whole_picture() {
        let options = media::PixelsOptions {
            crop: None,
            resize: Some(media::Resize {
                size: media::Size {
                    width: 1,
                    height: 1,
                },
                mode: media::ResizeMode::Average,
            }),
        };
        let whole = Region {
            x: 0,
            y: 0,
            w: 4,
            h: 2,
            out_w: 1,
            out_h: 1,
            mode: ResizeMode::Average,
        };
        assert_eq!(picked(SIZE, &options).unwrap(), Some(whole));
    }
}
