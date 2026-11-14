//! Face-detection logic — the per-model profile: how the frame is shaped for
//! the detector, which detector, and how its answer maps back onto the frame.
//! The plugin hands a profile the frame's size and a `region` that reads the
//! whole frame, resampled to the size it is asked for — or nothing, where the
//! frame does not decode; the profile returns an internal [`Detection`] for
//! each face, which [`crate`]'s WIT glue maps to the shared `face`.
//! Bindgen-free but for the model the host runs.
//!
//! Profile selection is compile-time:
//!   * default → [`placeholder`]: whole frame as the "face", no model
//!     (dev/tests).
//!   * `--features blazeface` → [`blazeface`]: MediaPipe BlazeFace (short
//!     range, 128², RGB `[-1,1]`), run by the host from the model file beside
//!     this component; its graph does the anchor decoding, sigmoid and NMS.

#[cfg(feature = "blazeface")]
use blazeface as profile;
#[cfg(not(feature = "blazeface"))]
use placeholder as profile;

/// A detected face, in the frame's pixels; past its edges where the face is.
#[derive(Clone, Debug, PartialEq)]
pub struct Detection {
    /// `[x, y, w, h]`.
    pub bbox: [f32; 4],
    /// Detector-native keypoints `(x, y)` (BlazeFace: 6). Empty if none.
    pub landmarks: Vec<(f32, f32)>,
}

/// Every face in a frame of `size` pixels, read through `region`: the whole
/// frame, resampled to the size it is asked for, row-major RGB8, or `None`
/// where it does not decode. The most prominent — the largest — first; none
/// where the frame does not decode.
pub fn detect_all(
    size: (u32, u32),
    region: impl FnOnce(u32, u32) -> Option<Vec<u8>>,
) -> Vec<Detection> {
    profile::detect_all(size, region)
}

// ---------------------------------------------------------------------
// Profile: placeholder (default) — no model, whole frame as the face
// ---------------------------------------------------------------------

#[cfg(not(feature = "blazeface"))]
mod placeholder {
    use super::Detection;

    /// The whole frame as the "face", so the pipeline runs weightless —
    /// cropping the full box reproduces a centered square crop. The pixels
    /// are not read.
    pub fn detect_all(
        (w, h): (u32, u32),
        _region: impl FnOnce(u32, u32) -> Option<Vec<u8>>,
    ) -> Vec<Detection> {
        vec![Detection {
            bbox: [0.0, 0.0, w as f32, h as f32],
            landmarks: Vec::new(),
        }]
    }
}

// ---------------------------------------------------------------------
// Profile: BlazeFace, run by the host (`--features blazeface`)
// ---------------------------------------------------------------------

#[cfg(feature = "blazeface")]
mod blazeface {
    use super::Detection;
    use crate::enclavid::host::tensors::{TensorF32, TensorI64};
    use crate::enclavid_ext::face_detect::models;

    /// The graph's square input side.
    pub const SIDE: u32 = 128;
    // The thresholds the graph decodes with, fed as its inputs: MediaPipe's
    // confidence and overlap for this model, and room for a few faces — the
    // largest is the one taken.
    const CONF: f32 = 0.5;
    const IOU: f32 = 0.3;
    const MAX_DET: i64 = 25;
    /// The values of one face in the graph's answer: its box's corners, `y`
    /// before `x`, then six keypoints `(x, y)`.
    const ROW: usize = 16;

    pub fn detect_all(
        size: (u32, u32),
        region: impl FnOnce(u32, u32) -> Option<Vec<u8>>,
    ) -> Vec<Detection> {
        let Some(fit) = Fit::of(size) else {
            return Vec::new();
        };
        let Some(square) = region(fit.w, fit.h).and_then(|rgb| fit.square(&rgb)) else {
            return Vec::new();
        };
        let side = u64::from(SIDE);
        let data = models::detector()
            .run(
                &TensorF32::new(&[1, 3, side, side], &input(&square)),
                &TensorF32::new(&[1], &[CONF]),
                &TensorI64::new(&[1], &[MAX_DET]),
                &TensorF32::new(&[1], &[IOU]),
            )
            .data();
        // A row for each face the graph keeps, the largest first.
        let mut rows: Vec<&[f32]> = data.chunks_exact(ROW).collect();
        rows.sort_by(|a, b| area(b).total_cmp(&area(a)));
        rows.into_iter().map(|row| fit.detection(row)).collect()
    }

    /// Where a frame lies on the graph's square: resampled to `w×h`, its
    /// aspect kept, centered, the rest black — as MediaPipe letterboxes a
    /// frame for this model. A stretched frame would show the detector a face
    /// of another shape, and have it boxed so.
    pub(super) struct Fit {
        pub w: u32,
        pub h: u32,
        left: u32,
        top: u32,
        /// The frame's own size.
        frame: (u32, u32),
    }

    impl Fit {
        /// How a frame of `w×h` fits the square. `None` for an empty one.
        pub(super) fn of(frame: (u32, u32)) -> Option<Fit> {
            let (w, h) = frame;
            if w == 0 || h == 0 {
                return None;
            }
            let side = SIDE as f32;
            let r = (side / w as f32).min(side / h as f32);
            let scaled = |n: u32| ((n as f32 * r).round() as u32).clamp(1, SIDE);
            let (w, h) = (scaled(w), scaled(h));
            Some(Fit {
                w,
                h,
                left: (SIDE - w) / 2,
                top: (SIDE - h) / 2,
                frame,
            })
        }

        /// `rgb`, `w×h`, in its place on the black square. `None` for pixels
        /// that are not `w×h`.
        pub(super) fn square(&self, rgb: &[u8]) -> Option<Vec<u8>> {
            let (w, side) = (self.w as usize, SIDE as usize);
            if rgb.len() != w * self.h as usize * 3 {
                return None;
            }
            let mut square = vec![0u8; side * side * 3];
            for (y, row) in rgb.chunks_exact(w * 3).enumerate() {
                let at = ((self.top as usize + y) * side + self.left as usize) * 3;
                square[at..at + w * 3].copy_from_slice(row);
            }
            Some(square)
        }

        /// A row of the graph's answer, over the square, as a detection in
        /// the frame's pixels: where the graph places a face cut by the
        /// frame's edge on the black around it, past that edge. The graph
        /// thresholds its confidence itself and gives none.
        pub(super) fn detection(&self, row: &[f32]) -> Detection {
            let side = SIDE as f32;
            let (width, height) = (self.frame.0 as f32, self.frame.1 as f32);
            let x = |v: f32| (v * side - self.left as f32) / self.w as f32 * width;
            let y = |v: f32| (v * side - self.top as f32) / self.h as f32 * height;
            let (x0, y0, x1, y1) = (x(row[1]), y(row[0]), x(row[3]), y(row[2]));
            Detection {
                bbox: [x0, y0, (x1 - x0).max(0.0), (y1 - y0).max(0.0)],
                landmarks: row[4..ROW]
                    .chunks_exact(2)
                    .map(|p| (x(p[0]), y(p[1])))
                    .collect(),
            }
        }
    }

    /// The graph's input from the square: its RGB planes in `[-1, 1]`, NCHW
    /// `[1, 3, SIDE, SIDE]`. The range is load-bearing and silent if wrong:
    /// the graph does no normalization of its own, and its weights were
    /// trained on `[-1, 1]` — `[0, 1]` still runs, and boxes faces a little
    /// off.
    pub(super) fn input(square: &[u8]) -> Vec<f32> {
        let plane = (SIDE * SIDE) as usize;
        let mut chw = vec![0f32; 3 * plane];
        for (i, pixel) in square.chunks_exact(3).enumerate() {
            for (c, &value) in pixel.iter().enumerate() {
                chw[c * plane + i] = value as f32 / 127.5 - 1.0;
            }
        }
        chw
    }

    /// A row's box area, over the square.
    fn area(row: &[f32]) -> f32 {
        (row[3] - row[1]).max(0.0) * (row[2] - row[0]).max(0.0)
    }
}

#[cfg(test)]
mod tests {
    // The placeholder boxes the whole frame and reads no pixels. Run native:
    //   cargo test -p face-detect --target aarch64-apple-darwin
    #[cfg(not(feature = "blazeface"))]
    #[test]
    fn the_placeholder_boxes_the_whole_frame() {
        let found = super::detect_all((64, 48), |_, _| unreachable!("no pixels read"));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].bbox, [0.0, 0.0, 64.0, 48.0]);
    }

    // BlazeFace's shaping, native — the model itself runs on the host:
    //   cargo test -p face-detect --features blazeface --target aarch64-apple-darwin
    #[cfg(feature = "blazeface")]
    mod blazeface {
        use super::super::blazeface::{Fit, SIDE, input};

        /// A frame fits the square whole, its longer side on the square's, its
        /// aspect kept, centered — scaled up or down alike.
        #[test]
        fn a_frame_fits_the_square_with_its_aspect() {
            let at = |size| Fit::of(size).map(|f| (f.w, f.h));
            assert_eq!(at((1920, 1080)), Some((128, 72)));
            assert_eq!(at((1080, 1920)), Some((72, 128)));
            assert_eq!(at((64, 64)), Some((128, 128)));
            assert_eq!(at((1, 4000)), Some((1, 128)));
            assert!(Fit::of((0, 10)).is_none());
        }

        /// A frame sits centered on black, every pixel of it where it was.
        #[test]
        fn a_frame_sits_centered_on_black() {
            let fit = Fit::of((1920, 1080)).unwrap();
            let rgb: Vec<u8> = (0..fit.w * fit.h * 3)
                .map(|i| (i % 250) as u8 + 1)
                .collect();
            let square = fit.square(&rgb).expect("fits");
            let side = SIDE as usize;
            assert_eq!(square.len(), side * side * 3);
            let top = (side - fit.h as usize) / 2;
            assert_eq!(top, 28);
            for y in 0..fit.h as usize {
                let at = (top + y) * side * 3;
                let from = y * fit.w as usize * 3;
                assert_eq!(square[at..at + side * 3], rgb[from..from + side * 3]);
            }
            let lit = square.iter().filter(|&&v| v != 0).count();
            assert_eq!(lit, rgb.len(), "everything else is black");
            assert!(fit.square(&rgb[3..]).is_none());
        }

        /// A box over the square maps back onto the frame's pixels: a square
        /// on the square is a square in the frame, and a face cut by the
        /// frame's edge reaches past it.
        #[test]
        fn a_box_maps_back_onto_the_frame() {
            let fit = Fit::of((1920, 1080)).unwrap();
            let mut row = [0f32; 16];
            // Corners `y` before `x`: 0.25..0.5 across, 0.5..0.75 down.
            row[..4].copy_from_slice(&[0.5, 0.25, 0.75, 0.5]);
            row[4..6].copy_from_slice(&[0.375, 0.625]);
            let d = fit.detection(&row);
            let [x, y, w, h] = d.bbox;
            let close = |a: f32, b: f32| (a - b).abs() < 1e-2;
            assert!(close(x, 480.0) && close(y, 540.0), "{:?}", d.bbox);
            assert!(close(w, 480.0) && close(h, 480.0), "{:?}", d.bbox);
            let (kx, ky) = d.landmarks[0];
            assert!(close(kx, 720.0) && close(ky, 780.0), "{kx} {ky}");
            assert_eq!(d.landmarks.len(), 6);

            // Into the black above the frame: past its top edge.
            row[..4].copy_from_slice(&[0.1, 0.25, 0.4, 0.5]);
            let d = fit.detection(&row);
            assert!(close(d.bbox[1], -228.0), "{:?}", d.bbox);
            assert!(close(d.bbox[3], 576.0), "{:?}", d.bbox);
        }

        /// The square's planes, in `[-1, 1]`, plane after plane.
        #[test]
        fn the_square_is_given_in_minus_one_to_one() {
            let side = SIDE as usize;
            let square = [0u8, 255, 51].repeat(side * side);
            let chw = input(&square);
            let plane = side * side;
            assert_eq!(chw.len(), 3 * plane);
            assert!(chw[..plane].iter().all(|&v| v == -1.0));
            assert!(chw[plane..2 * plane].iter().all(|&v| v == 1.0));
            assert!(
                chw[2 * plane..]
                    .iter()
                    .all(|&v| (v - (51.0 / 127.5 - 1.0)).abs() < 1e-6)
            );
        }
    }
}
