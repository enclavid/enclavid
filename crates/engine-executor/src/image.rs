//! The pictures of the applicant's captures, served: `photo.image` and
//! `video.frames` have the capture decoded in a process of its own beside the
//! round's — the media coprocess — started the first time the round asks for
//! the capture's pictures, once a capture; an `image`'s `pixels` ask that
//! process for them, and it decodes the picture then.
//!
//! The coprocess is where the applicant's media is parsed and decoded, so what
//! it answers is taken as the applicant's bytes are: bounded as it is read,
//! and what it says of them — not a photo, not a video, a picture that does
//! not decode — is what the component sees: no image, no frames, `none`. The
//! coprocess dying, or answering out of turn, traps the round instead: a
//! memory kill takes the round's whole group with it, so in a living round
//! that is a crash of the platform's own sandboxed process — its bug, or an
//! attempt on it — which nothing should take for a bad capture.

use std::collections::HashMap;
use std::future::Future;
use std::os::unix::net::UnixStream;
use std::pin::Pin;
use std::sync::Arc;

use coprocess_channel::Channel;
use enclavid_media::protocol::{
    Bytes, Failure, FrameInfo, Kind, MAX_OPEN_BYTES, MAX_RESPONSE_BYTES, Opened, Region, Request,
    ResizeMode, Response, Size,
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
    /// Not of its kind, or past the bounds: no pictures.
    Nothing,
}

/// A capture the round opened.
struct Decoding {
    /// What its open found.
    decoded: Decoded,
    /// The channel to the process decoding it; none for a capture with no
    /// pictures, whose process has ended.
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

    /// The channel to the process decoding `capture`, where it has pictures.
    fn channel(&mut self, capture: &Capture) -> Option<&mut Channel> {
        self.0.get_mut(capture)?.channel.as_mut()
    }
}

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
    // More than an open carries is more than an upload can be.
    let (decoded, channel) = if bytes.len() > MAX_OPEN_BYTES {
        (Decoded::Nothing, None)
    } else {
        let mut channel = Channel::new(state.media.start(u32::try_from(decode)?).await?)?;
        let open = Request::Open {
            kind,
            bytes: Bytes::new(&bytes),
        };
        match channel
            .ask(&open, MAX_RESPONSE_BYTES)
            .await
            .map_err(stopped)?
        {
            Response::Opened(opened) if opened.fits(kind) => match opened {
                Opened::Photo(size) => (Decoded::Photo(size), Some(channel)),
                Opened::Video { size, frames } => {
                    (Decoded::Video(size, frames.into()), Some(channel))
                }
            },
            Response::Failed(Failure::NotMedia | Failure::PastBounds | Failure::Corrupt) => {
                (Decoded::Nothing, None)
            }
            Response::Failed(failure) => return Err(stopped(format!("{failure:?}"))),
            _ => return Err(stopped("a response no open of the capture has")),
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
    /// in; `None` where it does not decode. Traps for a region larger than a
    /// picture can be.
    async fn read(
        &mut self,
        image: &Resource<ImageRep>,
        region: Region,
    ) -> wasmtime::Result<Option<Vec<u8>>> {
        let Some(length) = region.rgb_len() else {
            return Err(wasmtime::Error::msg(
                "a region larger than a picture can be",
            ));
        };
        let image = self.table.get(image)?;
        let (capture, frame) = (image.capture, image.frame);
        let channel = self
            .decodes
            .channel(&capture)
            .ok_or_else(|| wasmtime::Error::msg("an image of a capture with no pictures"))?;
        let request: Request = Request::Region { frame, region };
        match channel
            .ask(&request, MAX_RESPONSE_BYTES)
            .await
            .map_err(stopped)?
        {
            Response::Pixels(rgb) if rgb.len() == length => Ok(Some(rgb)),
            Response::Failed(Failure::Corrupt) => Ok(None),
            Response::Failed(failure) => Err(stopped(format!("{failure:?}"))),
            _ => Err(stopped("a response no region of the picture has")),
        }
    }
}

/// The region `options` pick of a picture of `size`: the crop held inside it,
/// the whole picture where there is none, brought to the size the resize
/// asks — or kept at its own, pixel for pixel, where there is none.
fn picked(size: Size, options: media::PixelsOptions) -> Region {
    let (x, y, w, h) = match options.crop {
        Some(crop) => (crop.x, crop.y, crop.width, crop.height),
        None => (0, 0, size.width, size.height),
    };
    let crop = Region {
        x,
        y,
        w,
        h,
        out_w: w,
        out_h: h,
        mode: ResizeMode::Nearest,
    }
    .held(size.width, size.height);
    match options.resize {
        Some(resize) => Region {
            out_w: resize.size.width,
            out_h: resize.size.height,
            mode: match resize.mode {
                media::ResizeMode::Nearest => ResizeMode::Nearest,
                media::ResizeMode::Average => ResizeMode::Average,
            },
            ..crop
        },
        None => Region {
            out_w: crop.w,
            out_h: crop.h,
            ..crop
        },
    }
}

/// The round's trap where the process decoding a capture stopped answering,
/// or answered out of turn.
fn stopped(why: impl std::fmt::Display) -> wasmtime::Error {
    wasmtime::Error::msg(format!(
        "the process decoding a capture stopped answering: {why}"
    ))
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
        self.pixels(self_, options).await
    }

    async fn pixels(
        &mut self,
        self_: Resource<ImageRep>,
        options: media::PixelsOptions,
    ) -> wasmtime::Result<Option<Vec<u8>>> {
        let size = self.table.get(&self_)?.size;
        let region = picked(size, options);
        self.read(&self_, region).await
    }

    async fn drop(&mut self, rep: Resource<ImageRep>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}
