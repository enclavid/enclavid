// What `@mediapipe/face_detection` resolves to in the page's build. The
// face-detection package imports MediaPipe's own runtime for a mode the page
// never uses, and that runtime loads its files from a CDN; this stands in for
// it, so none of it is shipped.
export class FaceDetection {
  constructor() {
    throw new Error("MediaPipe's runtime is not part of the page.");
  }
}

export default FaceDetection;
