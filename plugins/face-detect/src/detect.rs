//! Face-detection logic — the per-model profile (input size, normalization,
//! output decode). Works on an ALREADY-RESIZED `INPUT×INPUT` RGB8 patch (the
//! plugin pulls the whole frame stretched to the detector input via
//! `decoded-frame.region` — a stretch preserves normalized coords, so the
//! returned box maps 1:1 back onto the frame). Returns an internal
//! [`Detection`]; [`crate`]'s WIT glue maps it to the shared `face`.
//! Bindgen-free.
//!
//! Profile selection is compile-time:
//!   * default            → [`placeholder`]: whole frame as the "face", no
//!                          model, no weights (dev/tests).
//!   * `--features blazeface` → [`blazeface`]: MediaPipe BlazeFace (front,
//!                          128², RGB `[-1,1]`) embedded from
//!                          `FACE_DETECT_MODEL`; the export bakes
//!                          anchor-decode + sigmoid + NMS into the graph.

#[cfg(not(feature = "blazeface"))]
use placeholder as profile;
#[cfg(feature = "blazeface")]
use blazeface as profile;

/// The detector's square input side. The plugin asks `region` for `INPUT²`.
pub const INPUT: usize = profile::INPUT;

/// A detected face in NORMALIZED `[0,1]` coords over the source frame.
pub struct Detection {
    /// `[x, y, w, h]`.
    pub bbox: [f32; 4],
    /// Detector-native keypoints `(x, y)` (BlazeFace: 6). Empty if none.
    pub landmarks: Vec<(f32, f32)>,
    pub score: f32,
}

/// Detect the single most prominent face from an `INPUT×INPUT` RGB8 patch.
/// `None` = no usable face → retake.
pub fn detect(rgb: &[u8]) -> Option<Detection> {
    profile::detect(rgb)
}

// ---------------------------------------------------------------------
// Profile: placeholder (default) — no model, whole frame as the face
// ---------------------------------------------------------------------

#[cfg(not(feature = "blazeface"))]
mod placeholder {
    use super::Detection;

    /// Arbitrary — the placeholder ignores the pixels.
    pub const INPUT: usize = 64;

    /// The whole frame as the "face", so the pipeline runs weightless —
    /// cropping the full box reproduces a centered square crop.
    pub fn detect(_rgb: &[u8]) -> Option<Detection> {
        Some(Detection {
            bbox: [0.0, 0.0, 1.0, 1.0],
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
    use super::Detection;
    use onnx_core::{Input, Model};

    pub const INPUT: usize = 128;
    // Post-process thresholds this export takes as graph inputs. Conservative
    // conf (single frontal selfie); MediaPipe's default IoU; a small det cap.
    const CONF: f32 = 0.5;
    const IOU: f32 = 0.3;
    const MAX_DET: i64 = 25;

    /// The BlazeFace ONNX, embedded from the `FACE_DETECT_MODEL` build-time
    /// path (a build-input, never committed).
    const WEIGHTS: &[u8] = include_bytes!(env!("FACE_DETECT_MODEL"));

    /// `rgb` is the whole frame stretched to `INPUT²`. Normalize to `[-1,1]`
    /// (NCHW) and run — the graph does anchor-decode + sigmoid + NMS, so the
    /// output is a flat `N×16` row set: `top_y, top_x, bot_y, bot_x` then 6
    /// `(x, y)` keypoints, all normalized `[0,1]`. `N = 0` → `None`.
    ///
    /// `x/127.5 - 1.0` is LOAD-BEARING and silent if wrong: this export does
    /// NO in-graph normalization (verified by graph trace) and the weights
    /// were trained on `[-1,1]` (the README's `/255` is wrong; golden-
    /// validated by anatomically-correct landmarks on a real portrait).
    pub fn detect(rgb: &[u8]) -> Option<Detection> {
        let plane = INPUT * INPUT;
        let mut chw = vec![0f32; 3 * plane];
        for i in 0..plane {
            chw[i] = rgb[i * 3] as f32 / 127.5 - 1.0;
            chw[plane + i] = rgb[i * 3 + 1] as f32 / 127.5 - 1.0;
            chw[2 * plane + i] = rgb[i * 3 + 2] as f32 / 127.5 - 1.0;
        }
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
        // Most prominent = largest area.
        let best = out.chunks_exact(16).max_by(|a, b| area(a).total_cmp(&area(b)))?;
        let (top_y, top_x, bot_y, bot_x) = (best[0], best[1], best[2], best[3]);
        let landmarks = best[4..16].chunks_exact(2).map(|p| (p[0], p[1])).collect();
        Some(Detection {
            bbox: [top_x, top_y, (bot_x - top_x).max(0.0), (bot_y - top_y).max(0.0)],
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

#[cfg(test)]
mod tests {
    use super::*;

    // Placeholder detect on a flat patch returns the whole-frame box.
    #[test]
    fn placeholder_full_frame() {
        let rgb = vec![128u8; INPUT * INPUT * 3];
        let d = detect(&rgb).expect("detection");
        assert_eq!(d.bbox, [0.0, 0.0, 1.0, 1.0]);
    }
}
