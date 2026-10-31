//! Face-age inference on a face crop pulled from the decoded frame: shape the
//! crop as the model takes it (per-model profile) → run the model → decode.
//! The JPEG decode and the crop moved OUT to the preprocess / face-detect
//! plugins — this plugin asks `decoded-frame.region` (in [`lib`]) for the face
//! patch at the size its profile wants, and holds only the model-specific
//! adapter: input format (size, channel order, normalization), which model,
//! and output decode.
//!
//! Profile selection is compile-time:
//!   * default            → [`placeholder`]: a no-op graph in the sandbox, no
//!                          weights.
//!   * `--features age-googlenet` → [`age_googlenet`]: in the sandbox, the
//!                          real reference (224² BGR mean-subtracted, 8-bucket
//!                          Adience).
//!   * `--features mivolo` → [`mivolo`]: MiVOLO, run by the host from the
//!                          model files beside this component (384²
//!                          letterboxed RGB, ImageNet-normalized, the face
//!                          beside an empty body).

#[cfg(all(feature = "mivolo", feature = "age-googlenet"))]
compile_error!("one age model per artifact: `mivolo` or `age-googlenet`");

#[cfg(feature = "age-googlenet")]
use age_googlenet as profile;
#[cfg(feature = "mivolo")]
use mivolo as profile;
#[cfg(not(any(feature = "age-googlenet", feature = "mivolo")))]
use placeholder as profile;

/// Context margin the crop box is grown by (about its center) before the
/// model sees it — Adience-class models want some hair/chin/background.
pub const MARGIN: f32 = profile::MARGIN;

/// Estimate age (years) from the face crop `region` reads: a source rect of
/// `crop` pixels, resampled to the size it is asked for, row-major RGB8.
/// `None` if the model fails to build/run, or gives no age.
pub fn estimate(crop: (u32, u32), region: impl FnOnce(u32, u32) -> Vec<u8>) -> Option<f32> {
    profile::estimate(crop, region)
}

/// A profile run in the sandbox, on a square crop of its input side.
#[cfg(not(feature = "mivolo"))]
mod in_sandbox {
    use onnx_core::Model;

    /// Estimate age (years) from an `input×input` row-major RGB8 face crop,
    /// through the profile's `normalize`, model and `decode`.
    pub fn estimate(
        input: usize,
        rgb: &[u8],
        normalize: fn(&[u8]) -> Vec<f32>,
        build: fn() -> onnx_core::TractResult<Model>,
        decode: fn(&[f32]) -> f32,
    ) -> Option<f32> {
        let chw = normalize(rgb);
        let model = build().ok()?;
        let out = onnx_core::run(&model, &[1, 3, input, input], chw).ok()?;
        Some(decode(&out))
    }
}

// ---------------------------------------------------------------------
// Profile: placeholder (default) — no weights, shape-correct no-op
// ---------------------------------------------------------------------

#[cfg(not(any(feature = "age-googlenet", feature = "mivolo")))]
mod placeholder {
    use onnx_core::Model;

    pub const INPUT: usize = 64;
    pub const MARGIN: f32 = 1.0;

    pub fn estimate(_crop: (u32, u32), region: impl FnOnce(u32, u32) -> Vec<u8>) -> Option<f32> {
        let side = INPUT as u32;
        super::in_sandbox::estimate(INPUT, &region(side, side), normalize, build, decode)
    }

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
    use onnx_core::Model;

    pub const INPUT: usize = 224;
    /// +40% context: the Adience faces the model trained on are loosely
    /// cropped, so the detector's tight box is grown to match.
    pub const MARGIN: f32 = 1.4;

    /// The ONNX age model, embedded from the `FACE_AGE_MODEL` build-time
    /// path (a build-input, never committed).
    const WEIGHTS: &[u8] = include_bytes!(env!("FACE_AGE_MODEL"));

    pub fn estimate(_crop: (u32, u32), region: impl FnOnce(u32, u32) -> Vec<u8>) -> Option<f32> {
        let side = INPUT as u32;
        super::in_sandbox::estimate(INPUT, &region(side, side), normalize, build, decode)
    }

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

// ---------------------------------------------------------------------
// Profile: MiVOLO, run by the host (`--features mivolo`)
// ---------------------------------------------------------------------

#[cfg(feature = "mivolo")]
mod mivolo {
    use crate::enclavid::host::tensors::TensorF32;
    use crate::enclavid_ext::face_age::models;

    /// The graph's square input side.
    pub const SIDE: usize = 384;
    /// The detector's box as it is: MiVOLO takes the face as a detector
    /// boxes it.
    pub const MARGIN: f32 = 1.0;
    /// ImageNet's per-channel mean and spread, RGB, over values in `[0, 1]`.
    const MEAN: [f32; 3] = [0.485, 0.456, 0.406];
    const STD: [f32; 3] = [0.229, 0.224, 0.225];
    /// The age the graph's third output is scaled from: `raw · SPAN + MIDDLE`.
    const SPAN: f32 = 122.0;
    const MIDDLE: f32 = 61.0;

    pub fn estimate(crop: (u32, u32), region: impl FnOnce(u32, u32) -> Vec<u8>) -> Option<f32> {
        let (w, h) = fit(crop)?;
        let face = letterbox(&region(w, h), w as usize, h as usize)?;
        let input = TensorF32::new(&[1, 6, SIDE as u64, SIDE as u64], &input(&face));
        decode(&models::age().run(&input).data())
    }

    /// The size a crop of `w×h` is resampled to so that it fits the graph's
    /// square whole, its aspect kept.
    pub(super) fn fit((w, h): (u32, u32)) -> Option<(u32, u32)> {
        if w == 0 || h == 0 {
            return None;
        }
        let side = SIDE as f32;
        let r = (side / w as f32).min(side / h as f32);
        let scaled = |n: u32| ((n as f32 * r).round() as u32).clamp(1, SIDE as u32);
        Some((scaled(w), scaled(h)))
    }

    /// `rgb`, `w×h`, centered on a black square of [`SIDE`] — as MiVOLO's
    /// own preprocessing letterboxes a crop. `None` for pixels that are not
    /// `w×h` or not within the square.
    pub(super) fn letterbox(rgb: &[u8], w: usize, h: usize) -> Option<Vec<u8>> {
        if rgb.len() != w * h * 3 || w > SIDE || h > SIDE {
            return None;
        }
        let offset = |n: usize| (((SIDE - n) as f32 / 2.0) - 0.1).round() as usize;
        let (left, top) = (offset(w), offset(h));
        let mut square = vec![0u8; SIDE * SIDE * 3];
        for (y, row) in rgb.chunks_exact(w * 3).enumerate() {
            let at = ((top + y) * SIDE + left) * 3;
            square[at..at + w * 3].copy_from_slice(row);
        }
        Some(square)
    }

    /// The graph's input from a letterboxed face: the face's three planes,
    /// ImageNet-normalized, then three of an empty body — black, normalized
    /// the same way. NCHW `[1, 6, SIDE, SIDE]`.
    pub(super) fn input(face: &[u8]) -> Vec<f32> {
        let plane = SIDE * SIDE;
        let mut chw = vec![0f32; 6 * plane];
        for c in 0..3 {
            let (face_plane, body_plane) = (c * plane, (3 + c) * plane);
            for (i, pixel) in face.chunks_exact(3).enumerate() {
                chw[face_plane + i] = (pixel[c] as f32 / 255.0 - MEAN[c]) / STD[c];
            }
            chw[body_plane..body_plane + plane].fill((0.0 - MEAN[c]) / STD[c]);
        }
        chw
    }

    /// The age, from the graph's three outputs: two gender logits, then the
    /// age, scaled.
    pub(super) fn decode(out: &[f32]) -> Option<f32> {
        out.get(2).map(|raw| raw * SPAN + MIDDLE)
    }
}

#[cfg(test)]
mod tests {
    // Full inference tail on a flat gray patch through the in-sandbox
    // profile (placeholder by default, age_googlenet under the feature). Age
    // must land in a sane range. Run native:
    //   cargo test -p face-age --target aarch64-apple-darwin
    #[cfg(not(feature = "mivolo"))]
    #[test]
    fn estimate_gray_patch() {
        use super::{estimate, profile};
        let side = profile::INPUT;
        let age = estimate((side as u32, side as u32), |w, h| {
            vec![128u8; (w * h * 3) as usize]
        })
        .expect("estimate");
        eprintln!("age={age}");
        assert!((0.0..=100.0).contains(&age), "age out of range: {age}");
    }

    // The MiVOLO profile's shaping, native — the model itself runs on the
    // host:
    //   cargo test -p face-age --features mivolo --target aarch64-apple-darwin
    #[cfg(feature = "mivolo")]
    mod mivolo {
        use super::super::mivolo::{SIDE, decode, fit, input, letterbox};

        /// A crop fits the square whole, its longer side on the square's,
        /// its aspect kept — scaled up or down alike.
        #[test]
        fn a_crop_fits_the_square_with_its_aspect() {
            assert_eq!(fit((768, 384)), Some((384, 192)));
            assert_eq!(fit((100, 200)), Some((192, 384)));
            assert_eq!(fit((50, 50)), Some((384, 384)));
            assert_eq!(fit((1, 4000)), Some((1, 384)));
            assert_eq!(fit((0, 10)), None);
        }

        /// A letterboxed crop sits centered on black, every pixel of it where
        /// it was.
        #[test]
        fn a_crop_is_centered_on_black() {
            let (w, h) = (4, 2);
            let rgb: Vec<u8> = (0..w * h * 3).map(|i| i as u8 + 1).collect();
            let square = letterbox(&rgb, w, h).expect("fits");
            assert_eq!(square.len(), SIDE * SIDE * 3);
            let (left, top) = ((SIDE - w) / 2, (SIDE - h) / 2);
            for y in 0..h {
                for x in 0..w {
                    let at = ((top + y) * SIDE + left + x) * 3;
                    assert_eq!(square[at..at + 3], rgb[(y * w + x) * 3..][..3]);
                }
            }
            let lit = square.iter().filter(|&&v| v != 0).count();
            assert_eq!(lit, rgb.len(), "everything else is black");
            assert!(letterbox(&rgb, w + 1, h).is_none());
            assert!(letterbox(&vec![0; (SIDE + 1) * 3], SIDE + 1, 1).is_none());
        }

        /// The face's planes are ImageNet-normalized, and the body's are black
        /// normalized the same way, plane after plane.
        #[test]
        fn the_face_lies_beside_an_empty_body() {
            let face = [255u8, 0, 128].repeat(SIDE * SIDE);
            let chw = input(&face);
            let plane = SIDE * SIDE;
            assert_eq!(chw.len(), 6 * plane);
            let first = |c: usize| chw[c * plane];
            let close = |a: f32, b: f32| (a - b).abs() < 1e-5;
            assert!(close(first(0), (1.0 - 0.485) / 0.229));
            assert!(close(first(1), (0.0 - 0.456) / 0.224));
            assert!(close(first(2), (128.0 / 255.0 - 0.406) / 0.225));
            assert!(close(first(3), -0.485 / 0.229));
            assert!(close(first(4), -0.456 / 0.224));
            assert!(close(first(5), -0.406 / 0.225));
            assert!(
                chw[3 * plane..]
                    .chunks(plane)
                    .all(|p| p.iter().all(|&v| v == p[0]))
            );
        }

        /// The age is the third output, scaled; a graph that gave fewer gives
        /// none.
        #[test]
        fn the_age_is_the_third_output_scaled() {
            assert_eq!(decode(&[0.3, -0.3, 0.0]), Some(61.0));
            assert_eq!(decode(&[0.3, -0.3, 0.5]), Some(122.0));
            assert_eq!(decode(&[0.3, -0.3]), None);
        }
    }
}
