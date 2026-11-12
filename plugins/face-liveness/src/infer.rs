//! Liveness inference on crops pulled from the image: where the crops lie and
//! how the model takes them (per-model profile) → run the models → their
//! score. The image's decode is the host's and the face's box face-detect's —
//! this plugin asks `image.pixels` (in [`lib`]) for each crop at the side its
//! profile wants, and holds only the model-specific adapter: which crops,
//! input format (size, channel order, range), which models, and output decode.
//!
//! Profile selection is compile-time:
//!   * default → [`placeholder`]: no model, a score from the face's
//!     brightness (dev/tests).
//!   * `--features minifasnet` → [`minifasnet`]: MiniFASNet, run by the host
//!     from the model files beside this component (two models, on crops at 2.7
//!     and 4 times the face's box, 80² BGR from 0 to 255).

#[cfg(feature = "minifasnet")]
use minifasnet as profile;
#[cfg(not(feature = "minifasnet"))]
use placeholder as profile;

/// The profile's models, made once for the faces of one call; each reads
/// whether a face is live with [`Models::estimate`]: how live the face boxed
/// by `face` in a picture of `size` looks, from 0 to 1, from the crops
/// `region` reads — each a part of the picture resampled to a square of the
/// side asked for, row-major RGB8, or nothing, where the image does not
/// decode. `None` if the face is unusable, or a model gives no score.
pub use profile::Models;

/// A face's box in the picture's pixels, as face-detect gives it: its left
/// and top edges, its width and height.
pub type FaceBox = [f32; 4];

/// A part of the picture in its pixels: its left and top edges, its width and
/// height.
pub type Crop = [u32; 4];

// ---------------------------------------------------------------------
// Profile: placeholder (default) — no model
// ---------------------------------------------------------------------

#[cfg(not(feature = "minifasnet"))]
mod placeholder {
    use super::{Crop, FaceBox};

    /// The side the face is read at: enough for a mean.
    pub const SIDE: u32 = 8;

    /// No model.
    pub struct Models;

    impl Models {
        pub fn new() -> Self {
            Models
        }

        /// A score from the face's mean brightness, from 0 for black to 1 for
        /// white — so the pipeline runs end to end with no model, and a gray
        /// frame reads about a half.
        pub fn estimate(
            &self,
            size: (u32, u32),
            face: FaceBox,
            region: impl Fn(Crop, u32) -> Option<Vec<u8>>,
        ) -> Option<f32> {
            let rgb = region(covered(face, size)?, SIDE)?;
            let mean = rgb.iter().map(|&v| f32::from(v)).sum::<f32>() / rgb.len().max(1) as f32;
            Some(mean / 255.0)
        }
    }

    /// The pixels `face` touches in a picture of `size`; `None` where it
    /// touches none.
    fn covered([x, y, w, h]: FaceBox, (width, height): (u32, u32)) -> Option<Crop> {
        let span = |start: f32, length: f32, side: u32| {
            let side = side as f32;
            let from = start.floor().clamp(0.0, side);
            let to = (start + length).ceil().clamp(0.0, side);
            (to > from).then_some((from as u32, (to - from) as u32))
        };
        let (left, w) = span(x, w, width)?;
        let (top, h) = span(y, h, height)?;
        Some([left, top, w, h])
    }
}

// ---------------------------------------------------------------------
// Profile: MiniFASNet, run by the host (`--features minifasnet`)
// ---------------------------------------------------------------------

#[cfg(feature = "minifasnet")]
mod minifasnet {
    use super::{Crop, FaceBox};
    use crate::enclavid::host::tensors::TensorF32;
    use crate::enclavid_ext::face_liveness::models;

    /// The models' square input side.
    pub const SIDE: u32 = 80;
    // How the detector's box is brought to the box the models' crops were cut
    // around in training, the original's detector's (RetinaFace): its width
    // and height scaled, its center moved up by a share of its height. Medians
    // over 53 frames of both detectors on the same faces.
    const WIDTH: f64 = 1.023;
    const HEIGHT: f64 = 1.046;
    const UP: f64 = 0.058;

    /// The two models, each with the scale of the face's box its crop is cut
    /// at.
    pub struct Models([(f64, models::LivenessModel); 2]);

    impl Models {
        pub fn new() -> Self {
            Models([
                (2.7, models::minifasnet_v2()),
                (4.0, models::minifasnet_v1se()),
            ])
        }

        pub fn estimate(
            &self,
            size: (u32, u32),
            face: FaceBox,
            region: impl Fn(Crop, u32) -> Option<Vec<u8>>,
        ) -> Option<f32> {
            let trained = trained(face)?;
            let side = u64::from(SIDE);
            let mut live = 0.0;
            for (scale, model) in &self.0 {
                let rgb = region(enlarged(trained, *scale, size)?, SIDE)?;
                let scores = model
                    .run(&TensorF32::new(&[1, 3, side, side], &input(&rgb)?))
                    .data();
                live += scores.get(1)?;
            }
            // The original adds the models' scores and takes the class with
            // the most; its live class's share of the sum is the mean.
            Some(live / 2.0)
        }
    }

    /// The box the models' crops were cut around in training, from the
    /// detector's: in whole pixels, as the original's detector gives them.
    /// `None` for a box under a pixel either way.
    pub(super) fn trained([x, y, w, h]: FaceBox) -> Option<[f64; 4]> {
        if !(w >= 1.0 && h >= 1.0) {
            return None;
        }
        let (x, y, w, h) = (f64::from(x), f64::from(y), f64::from(w), f64::from(h));
        let (cx, cy) = (x + w / 2.0, y + h / 2.0 - UP * h);
        let (w, h) = (WIDTH * w, HEIGHT * h);
        Some([
            (cx - w / 2.0).trunc(),
            (cy - h / 2.0).trunc(),
            w.trunc(),
            h.trunc(),
        ])
    }

    /// The crop at `scale` times `face` in a picture of `size`, as the
    /// original cuts it (`_get_new_box`): about the box's center, the scale
    /// lowered where the picture is too small for it, and moved inside where
    /// it would cross an edge. `None` for an empty box, or a picture under two
    /// pixels either way.
    pub(super) fn enlarged(
        [x, y, box_w, box_h]: [f64; 4],
        scale: f64,
        (width, height): (u32, u32),
    ) -> Option<Crop> {
        if width < 2 || height < 2 || box_w < 1.0 || box_h < 1.0 {
            return None;
        }
        let (src_w, src_h) = (f64::from(width), f64::from(height));
        let scale = scale.min((src_w - 1.0) / box_w).min((src_h - 1.0) / box_h);
        let (cx, cy) = (x + box_w / 2.0, y + box_h / 2.0);
        let (half_w, half_h) = (box_w * scale / 2.0, box_h * scale / 2.0);
        let (mut left, mut top) = (cx - half_w, cy - half_h);
        let (mut right, mut bottom) = (cx + half_w, cy + half_h);
        if left < 0.0 {
            right -= left;
            left = 0.0;
        }
        if top < 0.0 {
            bottom -= top;
            top = 0.0;
        }
        if right > src_w - 1.0 {
            left -= right - src_w + 1.0;
            right = src_w - 1.0;
        }
        if bottom > src_h - 1.0 {
            top -= bottom - src_h + 1.0;
            bottom = src_h - 1.0;
        }
        // Its edges on whole pixels, the right and bottom ones taken in.
        let pixel = |v: f64| v.trunc().max(0.0) as u32;
        let (left, top) = (pixel(left), pixel(top));
        Some([
            left,
            top,
            pixel(right).saturating_sub(left) + 1,
            pixel(bottom).saturating_sub(top) + 1,
        ])
    }

    /// The models' input from a crop's RGB8: its planes blue, green, red, from
    /// 0 to 255 as they are, NCHW `[1, 3, SIDE, SIDE]`. The order and range are
    /// load-bearing and silent if wrong: the models were trained on OpenCV's
    /// BGR, unscaled, and scaled to `[0, 1]` every face reads as a spoof.
    /// `None` for pixels that are not `SIDE²`.
    pub(super) fn input(rgb: &[u8]) -> Option<Vec<f32>> {
        let plane = (SIDE * SIDE) as usize;
        if rgb.len() != plane * 3 {
            return None;
        }
        let mut chw = vec![0f32; 3 * plane];
        for (i, pixel) in rgb.chunks_exact(3).enumerate() {
            for (c, &value) in pixel.iter().rev().enumerate() {
                chw[c * plane + i] = f32::from(value);
            }
        }
        Some(chw)
    }
}

#[cfg(test)]
mod tests {
    // The placeholder reads a gray face as about a half, at the side it asks
    // for. Run native:
    //   cargo test -p face-liveness --target aarch64-apple-darwin
    #[cfg(not(feature = "minifasnet"))]
    #[test]
    fn the_placeholder_reads_gray_as_a_half() {
        use super::{Models, profile};
        let face = [100.5, 50.25, 200.0, 220.0];
        let live = Models::new()
            .estimate((640, 480), face, |crop, side| {
                assert_eq!(crop, [100, 50, 201, 221]);
                assert_eq!(side, profile::SIDE);
                Some(vec![128u8; (side * side * 3) as usize])
            })
            .expect("estimate");
        assert!((live - 0.502).abs() < 0.001, "{live}");
    }

    // The MiniFASNet profile's shaping, native — the models themselves run on
    // the host:
    //   cargo test -p face-liveness --features minifasnet --target aarch64-apple-darwin
    #[cfg(feature = "minifasnet")]
    mod minifasnet {
        use super::super::minifasnet::{SIDE, enlarged, input, trained};

        /// The detector's box is brought to the original detector's: larger,
        /// its center higher, in whole pixels; one under a pixel is none.
        #[test]
        fn a_box_is_brought_to_the_trained_one() {
            assert_eq!(
                trained([200.5, 150.75, 120.25, 119.75]),
                Some([199.0, 141.0, 123.0, 125.0])
            );
            assert_eq!(
                trained([3.0, 2.0, 50.0, 60.0]),
                Some([2.0, -2.0, 51.0, 62.0])
            );
            assert_eq!(trained([3.0, 2.0, 0.5, 60.0]), None);
            assert_eq!(trained([3.0, 2.0, f32::NAN, 60.0]), None);
        }

        /// A crop is cut where the original's `_get_new_box` cuts it: inside
        /// the picture, about the box; moved in from an edge; and its scale
        /// lowered where the picture is too small.
        #[test]
        fn a_crop_is_the_originals() {
            let cut = |b: [f64; 4], scale, size| enlarged(b, scale, size);
            assert_eq!(
                cut([250.0, 150.0, 120.0, 125.0], 2.7, (640, 480)),
                Some([148, 43, 325, 339])
            );
            assert_eq!(
                cut([10.0, 5.0, 100.0, 110.0], 4.0, (640, 480)),
                Some([0, 0, 401, 441])
            );
            assert_eq!(
                cut([50.0, 50.0, 150.0, 150.0], 2.7, (200, 200)),
                Some([0, 0, 200, 200])
            );
            assert_eq!(
                cut([560.0, 400.0, 70.0, 70.0], 2.7, (640, 480)),
                Some([450, 290, 190, 190])
            );
            assert_eq!(
                cut([500.0, 200.0, 301.0, 299.0], 4.0, (1280, 720)),
                Some([288, 0, 725, 720])
            );
            assert_eq!(cut([500.0, 200.0, 0.0, 299.0], 4.0, (1280, 720)), None);
        }

        /// The planes are blue, green, red, from 0 to 255 as they are.
        #[test]
        fn the_input_is_bgr_unscaled() {
            let plane = (SIDE * SIDE) as usize;
            let rgb = [10u8, 20, 30].repeat(plane);
            let chw = input(&rgb).expect("80²");
            assert!(chw[..plane].iter().all(|&v| v == 30.0));
            assert!(chw[plane..2 * plane].iter().all(|&v| v == 20.0));
            assert!(chw[2 * plane..].iter().all(|&v| v == 10.0));
            assert!(input(&rgb[3..]).is_none());
        }
    }
}
