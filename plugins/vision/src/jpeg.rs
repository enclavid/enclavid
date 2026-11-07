//! The capture's JPEG, decoded to RGB pixels at the size asked for.

use jpeg_decoder::{Decoder, PixelFormat};

/// Decode a JPEG down by `denom` (1 / 2 / 4 / 8 — snapped to the nearest DCT
/// scale) via DCT-scaled IDCT — a 5-12 MP capture collapses toward the size
/// asked for without ever materialising the full-resolution image. Returns
/// RGB8 + dims; grayscale (L8) is replicated to three channels. `None` on
/// undecodable / unexpected formats (L16 / CMYK32 aren't produced by a
/// browser camera capture).
pub fn decode(bytes: &[u8], denom: u16) -> Option<(Vec<u8>, usize, usize)> {
    let denom = denom.max(1);
    let mut decoder = Decoder::new(bytes);
    decoder.read_info().ok()?;
    let info = decoder.info()?;
    let (ow, oh) = decoder
        .scale((info.width / denom).max(1), (info.height / denom).max(1))
        .ok()?;
    let pixels = decoder.decode().ok()?;
    let rgb = match decoder.info()?.pixel_format {
        PixelFormat::RGB24 => pixels,
        PixelFormat::L8 => pixels.iter().flat_map(|&g| [g, g, g]).collect(),
        _ => return None,
    };
    Some((rgb, ow as usize, oh as usize))
}
