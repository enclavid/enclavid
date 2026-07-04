//! In-sandbox preprocessing + ONNX inference via tract.
//!
//! The full image→estimate pipeline runs entirely inside the wasm
//! sandbox: DCT-scaled JPEG decode → center crop → resize → normalize →
//! an NCHW `f32` tensor → a tract model. The MODEL is a placeholder for
//! now (a shape-correct `input * 2` so the real `[1,3,H,W]` tensor flows
//! through tract's eval, with the "age" derived from the pixels); the
//! real age net — embedded ONNX weights loaded once via
//! `onnx().model_for_read` — replaces the graph and its output head. The
//! decode / crop / resize / normalize stages are already the real ones.

use jpeg_decoder::{Decoder, PixelFormat};
use tract_onnx::prelude::*;
use tract_onnx::tract_core::ops::math;

/// Model input side (square). The real age net fixes this to its own
/// trained resolution.
const INPUT: usize = 64;

/// Estimate age from the capture frames: DCT-scaled decode → preprocess →
/// run the model. Returns `None` when no frame decodes (an unusable
/// capture), which the caller maps to a zero-confidence estimate. v1 uses
/// the first decodable frame; a real model would aggregate across frames.
pub fn estimate_age(frames: &[Vec<u8>]) -> Option<f32> {
    let (rgb, w, h) = frames.iter().find_map(|f| decode_jpeg_eighth(f))?;
    let chw = preprocess(&rgb, w, h);
    run_model(chw).ok()
}

/// Decode a JPEG straight down to ~1/8 via DCT-scaled IDCT — a 5-12 MP
/// selfie collapses to a few-hundred-px buffer without ever
/// materialising the full-resolution image (the preprocessing bottleneck
/// for the cheap checks). Returns RGB8 + dims; grayscale is replicated to
/// three channels.
fn decode_jpeg_eighth(bytes: &[u8]) -> Option<(Vec<u8>, usize, usize)> {
    let mut decoder = Decoder::new(bytes);
    decoder.read_info().ok()?;
    let info = decoder.info()?;
    // `scale` snaps the request to the nearest DCT scale (1/8, 1/4, …) and
    // returns the actual output dims.
    let (ow, oh) = decoder
        .scale((info.width / 8).max(1), (info.height / 8).max(1))
        .ok()?;
    let pixels = decoder.decode().ok()?;
    let rgb = match decoder.info()?.pixel_format {
        PixelFormat::RGB24 => pixels,
        PixelFormat::L8 => pixels.iter().flat_map(|&g| [g, g, g]).collect(),
        // L16 / CMYK32 aren't produced by a browser camera capture.
        _ => return None,
    };
    Some((rgb, ow as usize, oh as usize))
}

/// Center-crop the largest square (the capture oval is centered), resize
/// to `INPUT×INPUT` (nearest-neighbour — a real model would prefer
/// bilinear/area), and lay out a normalized NCHW `[1,3,INPUT,INPUT]`
/// buffer in `[0,1]`.
fn preprocess(rgb: &[u8], w: usize, h: usize) -> Vec<f32> {
    let side = w.min(h).max(1);
    let x0 = (w - side) / 2;
    let y0 = (h - side) / 2;
    let mut chw = vec![0f32; 3 * INPUT * INPUT];
    let plane = INPUT * INPUT;
    for oy in 0..INPUT {
        let sy = y0 + oy * side / INPUT;
        for ox in 0..INPUT {
            let sx = x0 + ox * side / INPUT;
            let src = (sy * w + sx) * 3;
            for c in 0..3 {
                chw[c * plane + oy * INPUT + ox] = rgb[src + c] as f32 / 255.0;
            }
        }
    }
    chw
}

/// Run the placeholder model on the preprocessed tensor. The graph is a
/// shape-correct no-op (`input * 2`) so the real `[1,3,INPUT,INPUT]`
/// tensor flows through tract's eval on realistic shapes; the "age" is a
/// deterministic function of the pixels (mean of the output). Both the
/// graph and this output decode are replaced by the real model.
fn run_model(chw: Vec<f32>) -> TractResult<f32> {
    let mut model = TypedModel::default();
    let input = model.add_source("input", TypedFact::shape::<f32, _>([1, 3, INPUT, INPUT]))?;
    // tract's typed binary ops require RANK match (dimension-wise
    // broadcast only, no numpy rank-broadcast), so the scalar constant is
    // rank-4 `[1,1,1,1]` to broadcast against `[1,3,INPUT,INPUT]`.
    let two = model.add_const("two", Tensor::from_shape(&[1, 1, 1, 1], &[2.0f32])?)?;
    let scaled = model.wire_node("scale", math::mul(), &[input, two])?;
    model.set_output_outlets(&[scaled[0]])?;
    let runnable = model.into_runnable()?;

    let input_tensor = Tensor::from_shape(&[1, 3, INPUT, INPUT], &chw)?;
    let outputs = runnable.run(tvec![input_tensor.into_tvalue()])?;
    let out = outputs[0].as_slice::<f32>()?;
    let mean = out.iter().sum::<f32>() / out.len() as f32;
    // Map mean brightness (~[0,2] after ×2) to a plausible age band.
    Ok(mean * 30.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gray_jpeg() -> Vec<u8> {
        use jpeg_encoder::{ColorType, Encoder};
        let rgb = vec![128u8; 64 * 64 * 3];
        let mut buf = Vec::new();
        Encoder::new(&mut buf, 90)
            .encode(&rgb, 64, 64, ColorType::Rgb)
            .unwrap();
        buf
    }

    #[test]
    fn decode_stage() {
        let jpeg = gray_jpeg();
        let decoded = decode_jpeg_eighth(&jpeg);
        assert!(decoded.is_some(), "decode returned None");
        let (rgb, w, h) = decoded.unwrap();
        eprintln!("decoded {w}x{h} = {} bytes", rgb.len());
        assert_eq!(rgb.len(), w * h * 3);
    }

    #[test]
    fn full_pipeline() {
        let (rgb, w, h) = decode_jpeg_eighth(&gray_jpeg()).unwrap();
        let chw = preprocess(&rgb, w, h);
        let result = run_model(chw);
        eprintln!("run_model = {result:?}");
        result.expect("run_model errored");
    }
}
