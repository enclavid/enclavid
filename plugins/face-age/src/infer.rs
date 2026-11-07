//! Face-age inference on a face crop pulled from the decoded frame: shape the
//! crop as the model takes it (per-model profile) → run the model → decode.
//! The JPEG decode and the face's box are other plugins' (vision,
//! face-detect) — this plugin asks `decoded-frame.region` (in [`lib`]) for the
//! face patch at the size its profile wants, and holds only the model-specific
//! adapter: input format (size, channel order, normalization), which model,
//! and output decode.
//!
//! Profile selection is compile-time:
//!   * default → [`placeholder`]: no model, an age from the crop's brightness
//!     (dev/tests).
//!   * `--features mivolo` → [`mivolo`]: MiVOLO, run by the host from the
//!     model files beside this component (384² letterboxed RGB,
//!     ImageNet-normalized, the face beside an empty body).

#[cfg(feature = "mivolo")]
use mivolo as profile;
#[cfg(not(feature = "mivolo"))]
use placeholder as profile;

/// Context margin the crop box is grown by (about its center) before the
/// model sees it.
pub const MARGIN: f32 = profile::MARGIN;

/// Estimate age (years) from the face crop `region` reads: a source rect of
/// `crop` pixels, resampled to the size it is asked for, row-major RGB8.
/// `None` if the face is unusable, or the model gives no age.
pub fn estimate(crop: (u32, u32), region: impl FnOnce(u32, u32) -> Vec<u8>) -> Option<f32> {
    profile::estimate(crop, region)
}

// ---------------------------------------------------------------------
// Profile: placeholder (default) — no model
// ---------------------------------------------------------------------

#[cfg(not(feature = "mivolo"))]
mod placeholder {
    /// The side the crop is read at: enough for a mean.
    pub const SIDE: u32 = 8;
    pub const MARGIN: f32 = 1.0;

    /// An age from the crop's mean brightness, from 0 for black to 60 for
    /// white — so the pipeline runs end to end with no model, and a gray
    /// frame reads 30.
    pub fn estimate(_crop: (u32, u32), region: impl FnOnce(u32, u32) -> Vec<u8>) -> Option<f32> {
        let rgb = region(SIDE, SIDE);
        let mean = rgb.iter().map(|&v| f32::from(v)).sum::<f32>() / rgb.len().max(1) as f32;
        Some(mean / 255.0 * 60.0)
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
    /// The smallest face, in pixels of the frame it is cut from, that MiVOLO
    /// reads an age from. A smaller one is blown up to the graph's side and
    /// read far off: a face of 42 read 17 at 13 pixels and 31 at 23, and 38
    /// to 44 from 48 up — a margin above that for a real camera's blur.
    pub const MIN_SIDE: u32 = 64;
    /// ImageNet's per-channel mean and spread, RGB, over values in `[0, 1]`.
    const MEAN: [f32; 3] = [0.485, 0.456, 0.406];
    const STD: [f32; 3] = [0.229, 0.224, 0.225];
    /// The age the graph's third output is scaled from: `raw · SPAN + MIDDLE`.
    const SPAN: f32 = 122.0;
    const MIDDLE: f32 = 61.0;

    pub fn estimate(crop: (u32, u32), region: impl FnOnce(u32, u32) -> Vec<u8>) -> Option<f32> {
        if crop.0.min(crop.1) < MIN_SIDE {
            return None;
        }
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
    // The placeholder reads a gray crop as 30, at the size it asks for. Run
    // native:
    //   cargo test -p face-age --target aarch64-apple-darwin
    #[cfg(not(feature = "mivolo"))]
    #[test]
    fn the_placeholder_reads_gray_as_thirty() {
        use super::{estimate, profile};
        let age = estimate((300, 300), |w, h| {
            assert_eq!((w, h), (profile::SIDE, profile::SIDE));
            vec![128u8; (w * h * 3) as usize]
        })
        .expect("estimate");
        assert!((age - 30.1).abs() < 0.1, "{age}");
    }

    // The MiVOLO profile's shaping, native — the model itself runs on the
    // host:
    //   cargo test -p face-age --features mivolo --target aarch64-apple-darwin
    #[cfg(feature = "mivolo")]
    mod mivolo {
        use super::super::mivolo::{MIN_SIDE, SIDE, decode, estimate, fit, input, letterbox};

        /// A face smaller than MiVOLO reads gives no age, and its pixels are
        /// never asked for.
        #[test]
        fn a_face_too_small_gives_no_age() {
            let never = |_, _| -> Vec<u8> { unreachable!("no pixels read") };
            assert_eq!(estimate((MIN_SIDE - 1, 300), never), None);
            assert_eq!(estimate((300, MIN_SIDE - 1), never), None);
        }

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
