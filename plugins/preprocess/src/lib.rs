//! `enclavid:preprocess` — in-sandbox JPEG decode → a PLUGIN-owned
//! `decoded-frame`. The decode of the untrusted capture runs here (never in
//! the host/TCB) and the pixels stay in this plugin's linear memory;
//! downstream face checks pull their own crop/scale via
//! `decoded-frame.region`, so ONE decode serves all of them.

wit_bindgen::generate!({
    path: "wit",
    world: "enclavid:preprocess/preprocess@0.1.0",
    generate_all,
});

// The host `blob` resource — one stored byte-blob (here, a captured JPEG
// frame). Distinct name from this plugin's own `Frame` (the decoded RGB
// buffer below).
use enclavid::host::types::Blob;
use exports::enclavid::preprocess::decode::{Guest as DecodeGuest, Scale};
use exports::enclavid::vision::types::{DecodedFrame, Guest as VisionGuest, GuestDecodedFrame, Size};

struct Preprocess;

/// The decoded RGB8 buffer + dims, held in this plugin's memory. The backing
/// type for the exported `decoded-frame` resource.
struct Frame {
    rgb: Vec<u8>,
    width: u32,
    height: u32,
}

impl GuestDecodedFrame for Frame {
    fn size(&self) -> Size {
        Size {
            width: self.width,
            height: self.height,
        }
    }

    /// Crop `[x,y,w,h]` (source px, clamped inside the frame) and
    /// nearest-neighbour resample to `out_w × out_h` RGB8, row-major.
    fn region(&self, x: u32, y: u32, w: u32, h: u32, out_w: u32, out_h: u32) -> Vec<u8> {
        let (fw, fh) = (self.width, self.height);
        if fw == 0 || fh == 0 {
            return Vec::new();
        }
        let x = x.min(fw - 1);
        let y = y.min(fh - 1);
        let w = w.clamp(1, fw - x);
        let h = h.clamp(1, fh - y);
        let (out_w, out_h) = (out_w.max(1), out_h.max(1));
        let mut out = vec![0u8; (out_w * out_h * 3) as usize];
        for oy in 0..out_h {
            let sy = y + oy * h / out_h;
            for ox in 0..out_w {
                let sx = x + ox * w / out_w;
                let src = ((sy * fw + sx) * 3) as usize;
                let dst = ((oy * out_w + ox) * 3) as usize;
                out[dst] = self.rgb[src];
                out[dst + 1] = self.rgb[src + 1];
                out[dst + 2] = self.rgb[src + 2];
            }
        }
        out
    }
}

impl VisionGuest for Preprocess {
    type DecodedFrame = Frame;
}

impl DecodeGuest for Preprocess {
    fn decode(frame: &Blob, scale: Scale) -> Option<DecodedFrame> {
        let bytes = frame.bytes();
        let denom: u16 = match scale {
            Scale::Eighth => 8,
            Scale::Quarter => 4,
            Scale::Half => 2,
            Scale::Full => 1,
        };
        let (rgb, w, h) = vision::decode_jpeg(&bytes, denom)?;
        Some(DecodedFrame::new(Frame {
            rgb,
            width: w as u32,
            height: h as u32,
        }))
    }
}

export!(Preprocess);
