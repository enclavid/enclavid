//! A photo: the applicant's JPEG, its size read when it opens and its pixels
//! decoded when a region first asks for them — at its own size, or at half of
//! it where its own is past the bounds a decoded picture is held to.

use enclavid_media::protocol::{Failure, PictureBounds, Region, ResizeMode, Size};
use zune_jpeg::JpegDecoder;
use zune_jpeg::zune_core::colorspace::ColorSpace;
use zune_jpeg::zune_core::options::DecoderOptions;

use crate::picture::{self, Rgb};

/// A photo, opened.
pub struct Photo {
    jpeg: Vec<u8>,
    /// Its own size, as its header says.
    own: Size,
    /// The size it decodes at: its own, or half of it.
    pub size: Size,
    /// What its picture and the regions of it are held to.
    bounds: PictureBounds,
    /// Its pixels at `size`, once decoded; why it does not decode, once that
    /// was found.
    pixels: Option<Result<Vec<u8>, Failure>>,
}

impl Photo {
    /// Read `jpeg`'s header for its size: within `bounds`, or within them at
    /// half of it.
    pub fn open(jpeg: Vec<u8>, bounds: PictureBounds) -> Result<Self, Failure> {
        let mut decoder = JpegDecoder::new_with_options(jpeg.as_slice(), options());
        decoder.decode_headers().map_err(|_| Failure::NotMedia)?;
        let (width, height) = decoder.dimensions().ok_or(Failure::NotMedia)?;
        let own = Size {
            width: u32::try_from(width).map_err(|_| Failure::PastBounds)?,
            height: u32::try_from(height).map_err(|_| Failure::PastBounds)?,
        };
        let half = Size {
            width: own.width.div_ceil(2),
            height: own.height.div_ceil(2),
        };
        let size = if own.within(bounds) {
            own
        } else if half.within(bounds) {
            half
        } else {
            return Err(Failure::PastBounds);
        };
        Ok(Self {
            jpeg,
            own,
            size,
            bounds,
            pixels: None,
        })
    }

    /// `region` of the photo as RGB8, decoding it first where no region did.
    /// A photo has one picture: `frame` 0.
    pub fn region(&mut self, frame: u32, region: &Region) -> Result<Vec<u8>, Failure> {
        if frame != 0 {
            return Err(Failure::OutOfTurn);
        }
        if region.rgb_len(self.bounds).is_none() {
            return Err(Failure::PastBounds);
        }
        let Photo {
            jpeg,
            own,
            size,
            pixels,
            ..
        } = self;
        let pixels = pixels
            .get_or_insert_with(|| decode(jpeg, *own, *size))
            .as_ref()
            .map_err(|failure| *failure)?;
        let picture = Rgb {
            width: size.width,
            height: size.height,
            pixels,
        };
        picture::rgb_region(&picture, region).ok_or(Failure::Corrupt)
    }
}

/// What a decoder of the applicant's JPEG is told: RGB out, any size a JPEG
/// can say — [`Photo::open`] holds it to the bounds before anything is
/// decoded — and strict about the format where it can tell. A JPEG cut short
/// it may still fill in, as a browser shows one.
fn options() -> DecoderOptions {
    let most = usize::from(u16::MAX);
    DecoderOptions::default()
        .jpeg_set_out_colorspace(ColorSpace::RGB)
        .set_max_width(most)
        .set_max_height(most)
        .set_strict_mode(true)
}

/// `jpeg`, of its `own` size, decoded as RGB8 at `size`: its own, or half.
fn decode(jpeg: &[u8], own: Size, size: Size) -> Result<Vec<u8>, Failure> {
    let mut decoder = JpegDecoder::new_with_options(jpeg, options());
    let decoded = decoder.decode().map_err(|_| Failure::Corrupt)?;
    let pixels = own.width as usize * own.height as usize;
    let rgb = match decoder.get_output_colorspace() {
        Some(ColorSpace::RGB) if decoded.len() == pixels * 3 => decoded,
        Some(ColorSpace::Luma) if decoded.len() == pixels => {
            decoded.iter().flat_map(|&g| [g, g, g]).collect()
        }
        _ => return Err(Failure::Corrupt),
    };
    if size == own {
        return Ok(rgb);
    }
    let whole = Rgb {
        width: own.width,
        height: own.height,
        pixels: &rgb,
    };
    let half = Region {
        x: 0,
        y: 0,
        w: own.width,
        h: own.height,
        out_w: size.width,
        out_h: size.height,
        mode: ResizeMode::Average,
    };
    picture::rgb_region(&whole, &half).ok_or(Failure::Corrupt)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A photo past the bounds decodes at half its size, each pixel the mean
    /// of the two by two it covers.
    #[test]
    fn a_photo_is_halved_by_the_mean() {
        // 4 × 2, red only: 0 10 20 30 / 40 50 60 70.
        let rgb: Vec<u8> = [0u8, 10, 20, 30, 40, 50, 60, 70]
            .into_iter()
            .flat_map(|r| [r, 0, 0])
            .collect();
        let mut jpeg = Vec::new();
        jpeg_encoder::Encoder::new(&mut jpeg, 100)
            .encode(&rgb, 4, 2, jpeg_encoder::ColorType::Rgb)
            .expect("encode");
        let own = Size {
            width: 4,
            height: 2,
        };
        let half = Size {
            width: 2,
            height: 1,
        };
        let decoded = decode(&jpeg, own, own).unwrap();
        let halved = decode(&jpeg, own, half).unwrap();
        // Each half pixel is the mean of the decoded two by two it covers.
        for (i, pixel) in halved.as_chunks::<3>().0.iter().enumerate() {
            let covered = [2 * i, 2 * i + 1, 4 + 2 * i, 4 + 2 * i + 1];
            for channel in 0..3 {
                let sum: u32 = covered
                    .iter()
                    .map(|&at| u32::from(decoded[at * 3 + channel]))
                    .sum();
                let mean = (sum + 2) / 4;
                assert!(
                    u32::from(pixel[channel]).abs_diff(mean) <= 1,
                    "{halved:?} from {decoded:?}"
                );
            }
        }
    }
}
