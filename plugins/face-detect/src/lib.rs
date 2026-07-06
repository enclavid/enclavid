//! In-sandbox face detection — the crop stage shared by every face ML
//! plugin (age today; face-match / liveness later). A KYC capture is
//! single-subject, so [`detect`] returns the ONE most prominent face as a
//! normalized [`vision::Bbox`] the caller crops to before its model runs.
//! Replacing a blind center-crop with a detected box is what makes the
//! downstream estimate meaningful when the face isn't centered / doesn't
//! fill the frame, and turns "no face in the capture" into an honest
//! retake signal (`None`).
//!
//! Profile split mirrors face-age's:
//!   * default          → [`placeholder`]: whole frame as the "face"
//!                        (equivalent to a centered crop, no model, no
//!                        weights committed — dev/tests).
//!   * `--features blazeface` → [`blazeface`]: MediaPipe BlazeFace (front,
//!                        128², RGB `[-1,1]`) embedded from `FACE_DETECT_MODEL`.
//!                        The export bakes anchor-decode + sigmoid + NMS
//!                        into the graph, so the Rust side is just resize →
//!                        run → read boxes. The model lives on its own OCI
//!                        artifact, selected per session.

use vision::Bbox;

#[cfg(not(feature = "blazeface"))]
use placeholder as profile;
#[cfg(feature = "blazeface")]
use blazeface as profile;

/// A detected face: its box, detector-native keypoints, and a confidence.
pub struct Face {
    pub bbox: Bbox,
    /// Keypoints `(x, y)` in `[0,1]`; the point set is DETECTOR-specific
    /// (BlazeFace: 6 points — two eyes, nose, mouth, two ears; NOT the
    /// 5-point ArcFace set, and the eye/ear left-vs-right labelling varies
    /// across ports so individual labels are unverified). Empty when the
    /// profile provides none. Reserved for face-match alignment, which will
    /// map these per detector.
    pub landmarks: Vec<(f32, f32)>,
    pub score: f32,
}

/// Detect the single most prominent face. `None` = no usable face (the
/// caller asks for a retake). The pixels are the already-decoded RGB8 of one
/// frame (`w×h`); the returned box is normalized, so it maps cleanly onto a
/// higher-resolution decode of the same frame if the caller crops from one.
pub fn detect(rgb: &[u8], w: usize, h: usize) -> Option<Face> {
    profile::detect(rgb, w, h)
}

// ---------------------------------------------------------------------
// Profile: placeholder (default) — no model, whole frame as the face
// ---------------------------------------------------------------------

#[cfg(not(feature = "blazeface"))]
mod placeholder {
    use super::*;

    /// The whole frame, so the pipeline runs weightless — cropping
    /// `Bbox::FULL` reproduces today's centered square crop.
    pub fn detect(_rgb: &[u8], _w: usize, _h: usize) -> Option<Face> {
        Some(Face {
            bbox: Bbox::FULL,
            landmarks: Vec::new(),
            score: 1.0,
        })
    }
}

// ---------------------------------------------------------------------
// Profile: blazeface (real, `--features blazeface`)
// ---------------------------------------------------------------------

#[cfg(feature = "blazeface")]
mod blazeface {
    use super::*;
    use onnx_core::{Input, Model};
    use vision::resize_stretch;

    const INPUT: usize = 128;
    // Post-process thresholds this export takes as graph inputs. Conservative
    // conf (single frontal selfie); MediaPipe's default IoU; a small det cap
    // (one face expected).
    const CONF: f32 = 0.5;
    const IOU: f32 = 0.3;
    const MAX_DET: i64 = 25;

    /// The BlazeFace ONNX, embedded from the `FACE_DETECT_MODEL` build-time
    /// path (a build-input, never committed).
    const WEIGHTS: &[u8] = include_bytes!(env!("FACE_DETECT_MODEL"));

    /// Resize the whole frame to 128², normalize RGB to `[-1,1]` (NCHW), run
    /// the graph (anchor-decode + sigmoid + NMS are inside it), read back the
    /// boxes. Output is a flat `N×16` row set — each row `top_y, top_x,
    /// bot_y, bot_x` then 6 `(x, y)` keypoints, all normalized `[0,1]`.
    /// `N = 0` (nothing cleared `CONF`) → `None` → retake.
    ///
    /// The `x/127.5 - 1.0` normalization is LOAD-BEARING and silent if wrong:
    /// this export does NO in-graph normalization (verified by graph trace —
    /// the image goes straight into the first conv), and the weights were
    /// trained on `[-1,1]` (MediaPipe/hollance convention). Feeding `[0,1]`
    /// runs fine but yields plausible-but-shifted boxes (as the model's own
    /// README example, which uses `/255`, mistakenly does).
    pub fn detect(rgb: &[u8], w: usize, h: usize) -> Option<Face> {
        let plane = INPUT * INPUT;
        let mut chw = vec![0f32; 3 * plane];
        resize_stretch(rgb, w, h, INPUT, |ox, oy, r, g, b| {
            let i = oy * INPUT + ox;
            chw[i] = r as f32 / 127.5 - 1.0;
            chw[plane + i] = g as f32 / 127.5 - 1.0;
            chw[2 * plane + i] = b as f32 / 127.5 - 1.0;
        });
        let model = build().ok()?;
        let out = onnx_core::run_multi(
            &model,
            vec![
                Input::F32(vec![1, 3, INPUT, INPUT], chw),
                Input::F32(vec![1], vec![CONF]),
                Input::I64(vec![1], vec![MAX_DET]),
                Input::F32(vec![1], vec![IOU]),
            ],
        )
        .ok()?;
        // Most prominent = largest area (a KYC selfie is single-subject).
        let best = out.chunks_exact(16).max_by(|a, b| area(a).total_cmp(&area(b)))?;
        let (top_y, top_x, bot_y, bot_x) = (best[0], best[1], best[2], best[3]);
        let landmarks = best[4..16].chunks_exact(2).map(|p| (p[0], p[1])).collect();
        Some(Face {
            bbox: Bbox {
                x: top_x,
                y: top_y,
                w: (bot_x - top_x).max(0.0),
                h: (bot_y - top_y).max(0.0),
            },
            landmarks,
            // This export folds conf-thresholding into the graph and emits no
            // per-box score, so every returned box already cleared `CONF`.
            score: 1.0,
        })
    }

    fn area(row: &[f32]) -> f32 {
        (row[3] - row[1]).max(0.0) * (row[2] - row[0]).max(0.0)
    }

    fn build() -> onnx_core::TractResult<Model> {
        onnx_core::load(WEIGHTS)
    }
}
