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

/// A region of interest in NORMALIZED coordinates (`[0,1]` over the source
/// image, origin top-left). Produced by a detector, consumed by
/// [`crop_bbox_resize`]. Normalized so it survives a resolution change
/// (detect on a 1/8 buffer, crop from a 1/4 one) unchanged.
#[derive(Clone, Copy, Debug)]
pub struct Bbox {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}

impl Bbox {
    /// The whole frame — the fallback region when no detector runs.
    /// Squared by [`crop_bbox_resize`], it reproduces a centered crop.
    pub const FULL: Bbox = Bbox {
        x: 0.0,
        y: 0.0,
        w: 1.0,
        h: 1.0,
    };

    /// Grow the box by `factor` about its center (e.g. `1.4` = +40% context,
    /// what face models trained on loosely-cropped faces expect), staying in
    /// normalized space. Clamping to the image happens at crop time.
    pub fn expand(self, factor: f32) -> Bbox {
        let cx = self.x + self.w / 2.0;
        let cy = self.y + self.h / 2.0;
        let w = self.w * factor;
        let h = self.h * factor;
        Bbox {
            x: cx - w / 2.0,
            y: cy - h / 2.0,
            w,
            h,
        }
    }
}

/// Resize the WHOLE frame to `side×side` (nearest-neighbour, aspect
/// IGNORED — a stretch), invoking `place(dst_x, dst_y, r, g, b)` per output
/// pixel. For a detector that takes a fixed square input and returns boxes
/// in normalized `[0,1]`: a stretch preserves normalized coordinates, so
/// the boxes map 1:1 back onto the original frame with no un-letterbox math
/// (the accepted mild distortion is what this model's own reference
/// preprocessing does). The caller lays out / normalizes the pixels.
pub fn resize_stretch(
    rgb: &[u8],
    w: usize,
    h: usize,
    side: usize,
    mut place: impl FnMut(usize, usize, u8, u8, u8),
) {
    for oy in 0..side {
        let sy = oy * h / side;
        for ox in 0..side {
            let sx = ox * w / side;
            let src = (sy * w + sx) * 3;
            place(ox, oy, rgb[src], rgb[src + 1], rgb[src + 2]);
        }
    }
}

/// Crop `b` from the image as the largest SQUARE centered on the box (face
/// models want square input), clamped fully inside the frame, then
/// nearest-neighbour resample to `side×side`, invoking `place(dst_x, dst_y,
/// r, g, b)` per output pixel. Only crop + resize — the caller lays out /
/// normalizes the pixels. `Bbox::FULL` reproduces a centered square crop. A
/// real model would prefer bilinear/area.
pub fn crop_bbox_resize(
    rgb: &[u8],
    w: usize,
    h: usize,
    b: Bbox,
    side: usize,
    mut place: impl FnMut(usize, usize, u8, u8, u8),
) {
    let (wi, hi) = (w as i64, h as i64);
    // Box → pixel space, then the square we actually take: the larger box
    // side, capped by the frame.
    let px = (b.x * w as f32) as i64;
    let py = (b.y * h as f32) as i64;
    let pw = (b.w * w as f32) as i64;
    let ph = (b.h * h as f32) as i64;
    let sq = pw.max(ph).min(wi).min(hi).max(1);
    // Center the square on the box center, shift it wholly inside the frame.
    let cx = px + pw / 2;
    let cy = py + ph / 2;
    let x0 = (cx - sq / 2).clamp(0, wi - sq);
    let y0 = (cy - sq / 2).clamp(0, hi - sq);
    for oy in 0..side {
        let sy = (y0 + oy as i64 * sq / side as i64) as usize;
        for ox in 0..side {
            let sx = (x0 + ox as i64 * sq / side as i64) as usize;
            let src = (sy * w + sx) * 3;
            place(ox, oy, rgb[src], rgb[src + 1], rgb[src + 2]);
        }
    }
}
