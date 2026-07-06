//! Face-age inference on an ALREADY-CROPPED face patch: normalize (per-model
//! profile) → run the model → decode. The JPEG decode and the crop moved OUT
//! to the preprocess / face-detect plugins — this plugin receives an
//! `INPUT×INPUT` RGB8 face crop (pulled via `decoded-frame.region` in
//! [`lib`]) and only holds the model-specific adapter: input format
//! (channel order, normalization), which model, and output decode.
//!
//! Profile selection is compile-time:
//!   * default            → [`placeholder`]: a no-op graph, no weights.
//!   * `--features age-googlenet` → [`age_googlenet`]: the real reference
//!                          (224² BGR mean-subtracted, 8-bucket Adience).

use onnx_core::Model;

#[cfg(not(feature = "age-googlenet"))]
use placeholder as profile;
#[cfg(feature = "age-googlenet")]
use age_googlenet as profile;

/// The model's square input side. `lib` asks `region` for an `INPUT×INPUT`
/// crop.
pub const INPUT: usize = profile::INPUT;

/// Context margin the crop box is grown by (about its center) before the
/// model sees it — Adience-class models want some hair/chin/background.
pub const MARGIN: f32 = profile::MARGIN;

/// Estimate age (years) from an `INPUT×INPUT` row-major RGB8 face crop.
/// `None` if the model fails to build/run.
pub fn estimate_from_rgb(rgb: &[u8]) -> Option<f32> {
    let chw = profile::normalize(rgb);
    let model = profile::build().ok()?;
    let out = onnx_core::run(&model, &[1, 3, INPUT, INPUT], chw).ok()?;
    Some(profile::decode(&out))
}

// ---------------------------------------------------------------------
// Profile: placeholder (default) — no weights, shape-correct no-op
// ---------------------------------------------------------------------

#[cfg(not(feature = "age-googlenet"))]
mod placeholder {
    use super::Model;

    pub const INPUT: usize = 64;
    pub const MARGIN: f32 = 1.0;

    /// RGB, normalized `[0,1]`, NCHW `[1,3,64,64]`.
    pub fn normalize(rgb: &[u8]) -> Vec<f32> {
        let plane = INPUT * INPUT;
        let mut chw = vec![0f32; 3 * plane];
        for i in 0..plane {
            chw[i] = rgb[i * 3] as f32 / 255.0;
            chw[plane + i] = rgb[i * 3 + 1] as f32 / 255.0;
            chw[2 * plane + i] = rgb[i * 3 + 2] as f32 / 255.0;
        }
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
    use super::Model;

    pub const INPUT: usize = 224;
    /// +40% context: the Adience faces the model trained on are loosely
    /// cropped, so the detector's tight box is grown to match.
    pub const MARGIN: f32 = 1.4;

    /// The ONNX age model, embedded from the `FACE_AGE_MODEL` build-time
    /// path (a build-input, never committed).
    const WEIGHTS: &[u8] = include_bytes!(env!("FACE_AGE_MODEL"));

    /// BGR channel order, Caffe mean-subtract `[104,117,123]`, no scale,
    /// NCHW `[1,3,224,224]` — age_googlenet's documented preprocessing.
    pub fn normalize(rgb: &[u8]) -> Vec<f32> {
        const MEAN: [f32; 3] = [104.0, 117.0, 123.0]; // B, G, R
        let plane = INPUT * INPUT;
        let mut chw = vec![0f32; 3 * plane];
        for i in 0..plane {
            chw[i] = rgb[i * 3 + 2] as f32 - MEAN[0]; // B plane
            chw[plane + i] = rgb[i * 3 + 1] as f32 - MEAN[1]; // G plane
            chw[2 * plane + i] = rgb[i * 3] as f32 - MEAN[2]; // R plane
        }
        chw
    }

    pub fn build() -> onnx_core::TractResult<Model> {
        onnx_core::load(WEIGHTS)
    }

    /// Adience 8-group softmax → expected age (Σ pᵢ·centerᵢ). Coarse — the
    /// policy treats this as a buffer/pre-filter signal, not a precise 18
    /// cut, and escalates the buffer zone to the document DOB.
    pub fn decode(out: &[f32]) -> f32 {
        const CENTERS: [f32; 8] = [1.0, 5.0, 10.0, 17.5, 28.5, 40.5, 50.5, 65.0];
        out.iter().zip(CENTERS).map(|(p, c)| p * c).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Full inference tail on a flat gray patch through the ACTIVE profile
    // (placeholder by default, age_googlenet under the feature). Age must
    // land in a sane range. Run native:
    //   cargo test -p face-age --target aarch64-apple-darwin
    #[test]
    fn estimate_gray_patch() {
        let rgb = vec![128u8; INPUT * INPUT * 3];
        let age = estimate_from_rgb(&rgb).expect("estimate");
        eprintln!("age={age}");
        assert!((0.0..=100.0).contains(&age), "age out of range: {age}");
    }
}
