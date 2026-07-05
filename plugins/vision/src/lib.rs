//! Generic in-sandbox image preprocessing — reusable by any vision ML
//! plugin. Produces RGB pixels and crops, NOT tensors: channel order,
//! normalization, and NCHW/NHWC layout are the plugin's model-specific
//! concern (they belong in the plugin's per-model profile, not here).

use jpeg_decoder::{Decoder, PixelFormat};

/// Decode a JPEG straight down to ~1/8 via DCT-scaled IDCT — a 5-12 MP
/// selfie collapses to a few-hundred-px buffer without ever materialising
/// the full-resolution image. Returns RGB8 + dims; grayscale (L8) is
/// replicated to three channels. `None` on undecodable / unexpected
/// formats (L16 / CMYK32 aren't produced by a browser camera capture).
pub fn decode_jpeg_eighth(bytes: &[u8]) -> Option<(Vec<u8>, usize, usize)> {
    let mut decoder = Decoder::new(bytes);
    decoder.read_info().ok()?;
    let info = decoder.info()?;
    let (ow, oh) = decoder
        .scale((info.width / 8).max(1), (info.height / 8).max(1))
        .ok()?;
    let pixels = decoder.decode().ok()?;
    let rgb = match decoder.info()?.pixel_format {
        PixelFormat::RGB24 => pixels,
        PixelFormat::L8 => pixels.iter().flat_map(|&g| [g, g, g]).collect(),
        _ => return None,
    };
    Some((rgb, ow as usize, oh as usize))
}

/// Center-crop the largest square (the capture oval is centered) and
/// nearest-neighbour resample to `side×side`, invoking `place(dst_x,
/// dst_y, r, g, b)` per output pixel. Only crop + resize — the caller lays
/// out / normalizes the pixels. A real model would prefer bilinear/area.
pub fn crop_resize(
    rgb: &[u8],
    w: usize,
    h: usize,
    side: usize,
    mut place: impl FnMut(usize, usize, u8, u8, u8),
) {
    let sq = w.min(h).max(1);
    let x0 = (w - sq) / 2;
    let y0 = (h - sq) / 2;
    for oy in 0..side {
        let sy = y0 + oy * sq / side;
        for ox in 0..side {
            let sx = x0 + ox * sq / side;
            let src = (sy * w + sx) * 3;
            place(ox, oy, rgb[src], rgb[src + 1], rgb[src + 2]);
        }
    }
}
