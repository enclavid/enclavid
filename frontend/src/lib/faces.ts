// The faces in the camera's frames, for the guides the page reads: MediaPipe's
// BlazeFace (short range), the model the enclave's face-detect runs, through
// TF.js on its wasm backend in one thread; and how sharp a face is, by TF.js's
// own operations. Loaded only when a step asks for it.

import type { Tensor4D } from "@tensorflow/tfjs-core";
import type { Box, Face } from "@/lib/guides";

/// The longer side of the picture the detector is handed, in pixels. The model
/// reads 128×128; the frame is shrunk to it here, averaged as the enclave
/// shrinks its own, rather than sampled by the detector.
const SIDE = 128;

/// The width a face is brought to before its sharpness is measured, in pixels:
/// the same for every frame, so frames of one face compare.
const MEASURED_WIDTH = 256;

/// The Laplacian: each pixel against the four beside it. How much it varies
/// over a picture is the usual measure of focus — edges make it vary, blur
/// evens it out.
const LAPLACIAN = [0, 1, 0, 1, -4, 1, 0, 1, 0];

/// How long the detector may take to load.
const LOAD_MS = 30_000;

export type Detector = {
  /// The faces in `source`, a picture of `width` × `height` pixels, each by its
  /// keypoints in those pixels.
  faces(source: CanvasImageSource, width: number, height: number): Promise<Face[]>;
  /// How sharp the face in `box` of `picture` is: the variance of its
  /// Laplacian, which compares frames of one face, larger for the sharper.
  sharpness(picture: HTMLCanvasElement, box: Box): number;
};

let loading: Promise<Detector> | null = null;

/// The detector, loaded once for the page. Rejects, saying why, where this
/// browser cannot run it; asked again after that, it tries again.
export function loadDetector(): Promise<Detector> {
  loading ??= Promise.race([
    load(),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("The face detector took too long to load.")), LOAD_MS),
    ),
  ]).catch((error: unknown) => {
    loading = null;
    throw error;
  });
  return loading;
}

async function load(): Promise<Detector> {
  const [tf, backend, faceDetection, simd, model, weights] = await Promise.all([
    import("@tensorflow/tfjs-core"),
    import("@tensorflow/tfjs-backend-wasm"),
    import("@tensorflow-models/face-detection"),
    import("@tensorflow/tfjs-backend-wasm/dist/tfjs-backend-wasm-simd.wasm?url"),
    import("@/models/face-detection-short/model.json?url"),
    import("@/models/face-detection-short/group1-shard1of1.bin?url"),
  ]);
  // One thread: threads need the page cross-origin isolated, and their build
  // reserves memory an iPhone may refuse. Only the SIMD build is shipped.
  tf.env().set("WASM_HAS_MULTITHREAD_SUPPORT", false);
  if (!(await tf.env().getAsync("WASM_HAS_SIMD_SUPPORT"))) {
    throw new Error("This browser runs no WebAssembly SIMD.");
  }
  // The backend takes a file for every build it knows; the checks above leave
  // the SIMD one the build it loads.
  backend.setWasmPaths({
    "tfjs-backend-wasm.wasm": simd.default,
    "tfjs-backend-wasm-simd.wasm": simd.default,
    "tfjs-backend-wasm-threaded-simd.wasm": simd.default,
  });
  if (!(await tf.setBackend("wasm"))) throw new Error("TF.js's wasm backend did not start.");
  const detector = await faceDetection.createDetector(
    faceDetection.SupportedModels.MediaPipeFaceDetector,
    {
      runtime: "tfjs",
      modelType: "short",
      // Two, so that a second face is seen.
      maxFaces: 2,
      detectorModelUrl: tf.io.http(model.default, {
        weightUrlConverter: async () => weights.default,
      }),
    },
  );
  const canvas = document.createElement("canvas");
  const context = canvas.getContext("2d", { willReadFrequently: true });
  // The face whose sharpness is measured, drawn at the width it is measured at.
  const measured = document.createElement("canvas");
  const measuredContext = measured.getContext("2d", { willReadFrequently: true });
  if (!context || !measuredContext) throw new Error("This browser draws no 2D canvas.");
  const laplacian = tf.tensor4d(LAPLACIAN, [3, 3, 1, 1]);
  return {
    async faces(source, width, height) {
      const scale = SIDE / Math.max(width, height);
      const w = Math.max(1, Math.round(width * scale));
      const h = Math.max(1, Math.round(height * scale));
      if (canvas.width !== w || canvas.height !== h) {
        canvas.width = w;
        canvas.height = h;
      }
      context.imageSmoothingEnabled = true;
      context.imageSmoothingQuality = "high";
      context.drawImage(source, 0, 0, w, h);
      const found = await detector.estimateFaces(context.getImageData(0, 0, w, h));
      return found.map((face) => {
        const at = (name: string) => {
          const point = face.keypoints.find((k) => k.name === name);
          return point ? { x: (point.x * width) / w, y: (point.y * height) / h } : { x: NaN, y: NaN };
        };
        return {
          rightEye: at("rightEye"),
          leftEye: at("leftEye"),
          noseTip: at("noseTip"),
          mouthCenter: at("mouthCenter"),
          rightEarTragion: at("rightEarTragion"),
          leftEarTragion: at("leftEarTragion"),
        };
      });
    },
    sharpness(picture, box) {
      const width = box.right - box.left;
      const height = box.bottom - box.top;
      measured.width = MEASURED_WIDTH;
      measured.height = Math.round((MEASURED_WIDTH * height) / width);
      measuredContext.drawImage(picture, box.left, box.top, width, height, 0, 0, measured.width, measured.height);
      return tf.tidy(() => {
        // Grey as the mean of the colours: the wasm backend has no kernel for
        // `rgbToGrayscale`'s weighted one, and frames of one face compare
        // either way.
        const grey = tf.mean(tf.cast(tf.browser.fromPixels(measured), "float32"), -1, true);
        const edges = tf.conv2d(tf.expandDims<Tensor4D>(grey, 0), laplacian, 1, "valid");
        return tf.moments(edges).variance.dataSync()[0];
      });
    },
  };
}
