// What the page reads from the faces in a frame against the guide on screen:
// BlazeFace's six keypoints, in the frame's own unmirrored pixels.

import type { VideoGuide } from "@/types";

export type Point = { x: number; y: number };

/// A face by its keypoints. Right and left are the face's own: an unmirrored
/// frame shows its right on the frame's left.
export type Face = {
  rightEye: Point;
  leftEye: Point;
  noseTip: Point;
  mouthCenter: Point;
  rightEarTragion: Point;
  leftEarTragion: Point;
};

/// What the applicant is told next.
export type Hint =
  | "show-face"
  | "one-face"
  | "closer"
  | "back"
  /// Toward the screen's left, to the oval.
  | "left"
  /// Toward the screen's right.
  | "right"
  | "centre"
  /// Not turned the way the guide asks.
  | "turn"
  /// Turned that way, not as far.
  | "further"
  /// Following the guide.
  | "hold";

/// The overlap of the face's box with the oval's at which the face fills it,
/// AWS's own for the same box.
const OVAL_OVERLAP = 0.6;
/// How far from straight on a head still looks straight, in degrees.
const STRAIGHT_DEGREES = 8;
/// The nose tip's depth before the eyes, in eye distances, on MediaPipe's
/// canonical face: 4.01 cm over 6.30 cm.
const NOSE_DEPTH = 0.64;
/// How many of the latest frames a turn is read from.
const TURN_FRAMES = 5;

type Box = { left: number; top: number; right: number; bottom: number };

const mid = (a: Point, b: Point): Point => ({ x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 });
const dist = (a: Point, b: Point) => Math.hypot(a.x - b.x, a.y - b.y);

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

/// What the applicant is told about `guide` from the faces in a frame of
/// `width` × `height` pixels shown `mirrored` or not — `"hold"` while they
/// follow it — or `null` for a static guide, which the page does not read.
/// The face is taken into `head`.
export function hintFor(
  guide: VideoGuide,
  faces: Face[],
  head: Head,
  width: number,
  height: number,
  mirrored: boolean,
): Hint | null {
  if (guide.kind === "static_guide") return null;
  if (faces.length === 0) return "show-face";
  if (faces.length > 1) return "one-face";
  const [face] = faces;
  head.see(face);
  if (guide.kind === "head_turn") return turnHint(head.turn(), guide.degrees);
  const hint = ovalHint(face, guide, width, height, mirrored);
  // A face in the oval looks straight on.
  if (hint === "hold") head.settle();
  return hint;
}

function ovalHint(
  face: Face,
  oval: { width: number; height: number },
  width: number,
  height: number,
  mirrored: boolean,
): Hint {
  const shorter = Math.min(width, height);
  const w = oval.width * shorter;
  const h = oval.height * shorter;
  const target = { left: (width - w) / 2, top: (height - h) / 2, right: (width + w) / 2, bottom: (height + h) / 2 };
  const box = faceBox(face, oval.height / oval.width);
  if (overlap(box, target) > OVAL_OVERLAP) return "hold";
  const leftOf = box.left < target.left && box.right < target.right;
  const rightOf = box.left > target.left && box.right > target.right;
  if (leftOf || rightOf) {
    // A mirror shows the frame's left on the screen's right.
    return rightOf !== mirrored ? "left" : "right";
  }
  if (Math.abs((box.top + box.bottom) / 2 - height / 2) > h / 4) return "centre";
  return box.right - box.left < w ? "closer" : "back";
}

/// The face's box as AWS's liveness page builds it from the keypoints: as wide
/// as the eyes and the eyes-to-mouth height say, of the oval's shape, and out
/// to the ears.
function faceBox(face: Face, shape: number): Box {
  const eyes = mid(face.leftEye, face.rightEye);
  const width = (2 * dist(face.leftEye, face.rightEye) + 1.8 * dist(eyes, face.mouthCenter)) / 2;
  const height = shape * width;
  const centre = mid(eyes, face.noseTip);
  return {
    left: Math.min(centre.x - width / 2, face.rightEarTragion.x),
    right: Math.max(centre.x + width / 2, face.leftEarTragion.x),
    top: centre.y - height / 2,
    bottom: centre.y + height / 2,
  };
}

function overlap(a: Box, b: Box): number {
  const w = Math.max(0, Math.min(a.right, b.right) - Math.max(a.left, b.left));
  const h = Math.max(0, Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top));
  const both = w * h;
  if (both === 0) return 0;
  const area = (r: Box) => (r.right - r.left) * (r.bottom - r.top);
  return both / (area(a) + area(b) - both);
}

function turnHint(turn: number, degrees: number): Hint {
  if (degrees === 0) return Math.abs(turn) <= STRAIGHT_DEGREES ? "hold" : "turn";
  const toward = Math.sign(turn) === Math.sign(degrees) ? Math.abs(turn) : 0;
  if (toward >= Math.abs(degrees)) return "hold";
  return toward > STRAIGHT_DEGREES ? "further" : "turn";
}

/// The nose tip's offset along the axis from the right eye to the left, in
/// eye distances: about 0 for a face straight on, growing as it turns to its
/// own left.
function noseOffset(face: Face): number {
  const ax = face.leftEye.x - face.rightEye.x;
  const ay = face.leftEye.y - face.rightEye.y;
  const eyes = mid(face.leftEye, face.rightEye);
  return ((face.noseTip.x - eyes.x) * ax + (face.noseTip.y - eyes.y) * ay) / (ax * ax + ay * ay);
}

/// A head followed from frame to frame: where its nose sat in the latest
/// frames, and where it sat when the head last looked straight on.
export class Head {
  private recent: number[] = [];
  private straight = 0;

  /// Take a frame's face in.
  see(face: Face): void {
    this.recent.push(noseOffset(face));
    if (this.recent.length > TURN_FRAMES) this.recent.shift();
  }

  /// Take the head as looking straight on now.
  settle(): void {
    if (this.recent.length) this.straight = median(this.recent);
  }

  /// How far the head is turned, in degrees, negative to its own left.
  turn(): number {
    if (!this.recent.length) return 0;
    return -(Math.atan((median(this.recent) - this.straight) / NOSE_DEPTH) * 180) / Math.PI;
  }
}
