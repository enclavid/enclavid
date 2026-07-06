//! Face-age inference: the generic ONNX runtime ([`onnx_core`]) + image
//! prep ([`vision`]) + face detection ([`face_detect`]) + a compile-time
//! model PROFILE — the thin per-model adapter that is the ONLY
//! face-age-specific part: input format (resolution, channel order,
//! normalization, crop margin) + which model + output decode. The generic
//! crates know nothing of this.
//!
//! Profile selection is compile-time:
//!   * default            → [`placeholder`]: a no-op graph, no weights
//!                          (dev/tests, nothing committed to the repo).
//!   * `--features age-googlenet` → [`age_googlenet`]: the real reference
//!                          (ONNX embedded from `FACE_AGE_MODEL`, 224² BGR
//!                          mean-subtracted, 8-bucket Adience → expected age).

use onnx_core::Model;
use vision::{crop_bbox_resize, decode_jpeg_eighth, Bbox};

#[cfg(not(feature = "age-googlenet"))]
use placeholder as profile;
#[cfg(feature = "age-googlenet")]
use age_googlenet as profile;

/// Estimate the age (years) from the capture frames: DCT-scaled decode →
/// detect the face → crop to it (with the profile's context margin) →
/// normalize → build the model (once) → run → decode. `None` when no frame
/// decodes OR no face is found (unusable capture → the policy asks for a
/// retake). Uses one representative frame — one forward pass; the clip's
/// multiple frames are for anti-replay/liveness (a separate check), not the
/// age estimate.
pub fn estimate_age(frames: &[Vec<u8>]) -> Option<f32> {
    let (rgb, w, h) = frames.iter().find_map(|f| decode_jpeg_eighth(f))?;
    let face = face_detect::detect(&rgb, w, h)?;
    let bbox = face.bbox.expand(profile::MARGIN);
    let chw = profile::preprocess(&rgb, w, h, bbox);
    let model = profile::build().ok()?;
    let s = profile::INPUT;
    let out = onnx_core::run(&model, &[1, 3, s, s], chw).ok()?;
    Some(profile::decode(&out))
}

// ---------------------------------------------------------------------
// Profile: placeholder (default) — no weights, shape-correct no-op
// ---------------------------------------------------------------------

#[cfg(not(feature = "age-googlenet"))]
mod placeholder {
    use super::*;

    pub const INPUT: usize = 64;

    /// No margin: the placeholder detector already returns the whole frame,
    /// so cropping is a centered square (today's behaviour, no change).
    pub const MARGIN: f32 = 1.0;

    /// RGB, normalized `[0,1]`, NCHW `[1,3,64,64]`, cropped to `bbox`.
    pub fn preprocess(rgb: &[u8], w: usize, h: usize, bbox: Bbox) -> Vec<f32> {
        let plane = INPUT * INPUT;
        let mut chw = vec![0f32; 3 * plane];
        crop_bbox_resize(rgb, w, h, bbox, INPUT, |ox, oy, r, g, b| {
            let i = oy * INPUT + ox;
            chw[i] = r as f32 / 255.0;
            chw[plane + i] = g as f32 / 255.0;
            chw[2 * plane + i] = b as f32 / 255.0;
        });
        chw
    }

    /// No-op graph so the pipeline runs without weights.
    pub fn build() -> onnx_core::TractResult<Model> {
        onnx_core::noop(&[1, 3, INPUT, INPUT])
    }

    /// Placeholder decode: map mean brightness to a plausible age band.
    pub fn decode(out: &[f32]) -> f32 {
        let mean = out.iter().sum::<f32>() / out.len().max(1) as f32;
        mean * 30.0
    }
}

// ---------------------------------------------------------------------
// Profile: age_googlenet (real reference, `--features age-googlenet`)
// ---------------------------------------------------------------------

#[cfg(feature = "age-googlenet")]
mod age_googlenet {
    use super::*;

    pub const INPUT: usize = 224;

    /// +40% context around the detected box: the Adience faces the model was
    /// trained on are loosely cropped (hair / chin / some background), so a
    /// tight detector box is grown to match. Harmless under the placeholder
    /// detector (the frame-sized box just clamps back).
    pub const MARGIN: f32 = 1.4;

    /// The ONNX age model, embedded from the `FACE_AGE_MODEL` build-time
    /// path (a build-input, never committed).
    const WEIGHTS: &[u8] = include_bytes!(env!("FACE_AGE_MODEL"));

    /// BGR channel order, Caffe mean-subtract `[104,117,123]`, no scale,
    /// NCHW `[1,3,224,224]`, cropped to `bbox` — age_googlenet's documented
    /// preprocessing.
    pub fn preprocess(rgb: &[u8], w: usize, h: usize, bbox: Bbox) -> Vec<f32> {
        const MEAN: [f32; 3] = [104.0, 117.0, 123.0]; // B, G, R
        let plane = INPUT * INPUT;
        let mut chw = vec![0f32; 3 * plane];
        crop_bbox_resize(rgb, w, h, bbox, INPUT, |ox, oy, r, g, b| {
            let i = oy * INPUT + ox;
            chw[i] = b as f32 - MEAN[0];
            chw[plane + i] = g as f32 - MEAN[1];
            chw[2 * plane + i] = r as f32 - MEAN[2];
        });
        chw
    }

    pub fn build() -> onnx_core::TractResult<Model> {
        onnx_core::load(WEIGHTS)
    }

    /// Adience 8-group softmax → expected age (Σ pᵢ·centerᵢ). The buckets
    /// are coarse — the policy treats this as a buffer/pre-filter signal,
    /// not a precise 18 cut, and escalates the buffer zone to the document
    /// DOB. (The softmax peakedness would be a natural per-frame confidence,
    /// but it's a model-specific signal, out of scope for this
    /// model-agnostic contract.)
    pub fn decode(out: &[f32]) -> f32 {
        const CENTERS: [f32; 8] = [1.0, 5.0, 10.0, 17.5, 28.5, 40.5, 50.5, 65.0];
        out.iter().zip(CENTERS).map(|(p, c)| p * c).sum()
    }
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
        let (rgb, w, h) = decode_jpeg_eighth(&gray_jpeg()).expect("decode");
        eprintln!("decoded {w}x{h} = {} bytes", rgb.len());
        assert_eq!(rgb.len(), w * h * 3);
    }

    // Full pipeline through the ACTIVE profile (placeholder by default,
    // age_googlenet under the feature). Age must land in a sane range.
    #[test]
    fn full_pipeline() {
        let age = estimate_age(&[gray_jpeg()]).expect("estimate");
        eprintln!("age={age}");
        assert!((0.0..=100.0).contains(&age), "age out of range: {age}");
    }

    // Manual: end-to-end on a REAL face photo (not committed) through the
    // ACTIVE profiles — build with the real detector + model to validate the
    // full pipeline (decode → BlazeFace detect → crop → age). Reports the
    // detected box (sanity: a face fills a plausible sub-region, not the
    // whole frame) + the age. Run:
    //   FACE_DETECT_MODEL=/tmp/blaze.onnx FACE_AGE_MODEL=/tmp/age_googlenet.onnx \
    //     cargo test -p face-age --target aarch64-apple-darwin \
    //     --features blazeface,age-googlenet detect_and_age_real_face -- --ignored --nocapture
    #[test]
    #[ignore]
    fn detect_and_age_real_face() {
        let path =
            std::env::var("FACE_TEST_IMAGE").unwrap_or_else(|_| "/tmp/face.jpg".to_string());
        let jpeg = std::fs::read(&path).expect("test image present");
        let (rgb, w, h) = decode_jpeg_eighth(&jpeg).expect("decode");
        eprintln!("decoded {w}x{h}");
        match face_detect::detect(&rgb, w, h) {
            Some(f) => {
                eprintln!(
                    "FACE bbox x={:.3} y={:.3} w={:.3} h={:.3} | landmarks={} score={:.2}",
                    f.bbox.x, f.bbox.y, f.bbox.w, f.bbox.h, f.landmarks.len(), f.score
                );
                for (i, (lx, ly)) in f.landmarks.iter().enumerate() {
                    eprintln!("  kp[{i}] = ({lx:.3}, {ly:.3})");
                }
            }
            None => eprintln!("NO FACE DETECTED"),
        }
        match estimate_age(&[jpeg]) {
            Some(age) => eprintln!("AGE={age:.1}"),
            None => eprintln!("AGE: none (no face / no decode)"),
        }
    }

    // Manual: validates the generic load path against a downloaded ONNX
    // (not committed). Run with a model present:
    //   FACE_AGE_TEST_MODEL=/tmp/age_googlenet.onnx \
    //     cargo test --target aarch64-apple-darwin load_real_onnx -- --ignored --nocapture
    #[test]
    #[ignore]
    fn load_real_onnx() {
        let path = std::env::var("FACE_AGE_TEST_MODEL")
            .unwrap_or_else(|_| "/tmp/age_googlenet.onnx".to_string());
        let bytes = std::fs::read(&path).expect("model file present");
        let model = onnx_core::load(&bytes).expect("load failed");
        let out = onnx_core::run(&model, &[1, 3, 224, 224], vec![0.0f32; 3 * 224 * 224])
            .expect("run failed");
        eprintln!("MODEL {path}: first output len={}, values={out:?}", out.len());
    }
}
