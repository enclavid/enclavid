import { useEffect, useState, type RefObject } from "react";
import type { CameraFacing, Guide } from "@/types";

/// Best-effort haptic ping. iOS Safari silently ignores; Android /
/// Chrome OS hit a short vibration. Wrapped so callers don't repeat
/// the optional-chain dance everywhere.
export function haptic(pattern: number | number[]) {
  if (typeof navigator !== "undefined" && navigator.vibrate) {
    navigator.vibrate(pattern);
  }
}

/// What `getUserMedia` is asked for to show `camera`: its facing, at up to
/// 1920×1080, and no sound.
export function cameraConstraints(camera: CameraFacing): MediaStreamConstraints {
  return {
    video: {
      facingMode: cameraFacingHint(camera),
      width: { ideal: 1920 },
      height: { ideal: 1080 },
    },
    audio: false,
  };
}

/// The longer side of a picture the platform decodes at its own size, at most
/// — engine-types' `MAX_PICTURE_LONG_SIDE`.
const PICTURE_LONG_SIDE = 1920;
/// Its shorter side at most — `MAX_PICTURE_SHORT_SIDE`.
const PICTURE_SHORT_SIDE = 1080;

/// The size a camera frame of `width` × `height` is drawn at for the platform
/// to decode it at that size: its shape kept, its longer side at most 1920
/// pixels and its shorter 1080.
export function pictureSize(width: number, height: number) {
  const scale = Math.min(
    1,
    PICTURE_LONG_SIDE / Math.max(width, height),
    PICTURE_SHORT_SIDE / Math.min(width, height),
  );
  return {
    width: Math.max(1, Math.round(width * scale)),
    height: Math.max(1, Math.round(height * scale)),
  };
}

/// What the applicant is told when the camera does not start.
export function cameraError(e: unknown): string {
  if (e instanceof DOMException && e.name === "NotAllowedError") {
    return "Camera access was denied. Allow camera permission in your browser settings, then retry.";
  }
  if (e instanceof DOMException && e.name === "NotFoundError") {
    return "No camera was found on this device.";
  }
  return "Could not start the camera.";
}

/// Whether `stream`, started for `camera`, faces the applicant — and so is
/// shown as a mirror, as a phone's own camera shows a selfie. A computer's
/// camera may not say which way it faces; one asked for as the front is taken
/// to face the applicant.
export function facesApplicant(stream: MediaStream, camera: CameraFacing): boolean {
  const facing = stream.getVideoTracks()[0]?.getSettings().facingMode;
  return facing ? facing === "user" : camera === "front";
}

/// Where the camera's frame lies on screen, in the video element's own box,
/// as `object-cover` draws it: scaled to cover the box, centred, and cut at
/// its edges.
export type FrameBox = { left: number; top: number; width: number; height: number };

/// The [`FrameBox`] of `video`, kept as the camera's size or the element's
/// changes; `null` until the camera says its size.
export function useFrameBox(
  videoRef: RefObject<HTMLVideoElement | null>,
): FrameBox | null {
  const [box, setBox] = useState<FrameBox | null>(null);
  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;
    const measure = () => {
      const { videoWidth: w, videoHeight: h, clientWidth, clientHeight } = video;
      if (!w || !h || !clientWidth || !clientHeight) {
        setBox(null);
        return;
      }
      const scale = Math.max(clientWidth / w, clientHeight / h);
      setBox({
        left: (clientWidth - w * scale) / 2,
        top: (clientHeight - h * scale) / 2,
        width: w * scale,
        height: h * scale,
      });
    };
    measure();
    // `resize` is the element's own: the camera's size changed.
    video.addEventListener("loadedmetadata", measure);
    video.addEventListener("resize", measure);
    const observer = new ResizeObserver(measure);
    observer.observe(video);
    return () => {
      video.removeEventListener("loadedmetadata", measure);
      video.removeEventListener("resize", measure);
      observer.disconnect();
    };
  }, [videoRef]);
  return box;
}

/// Render the on-screen capture guide overlaid on the camera preview,
/// one flavour for each kind of the WIT `guide` variant.
export function GuideOverlay({ guide, frame }: { guide: Guide; frame: FrameBox | null }) {
  switch (guide.kind) {
    case "rect":
      return <RectGuide aspect={guide.aspect} />;
    case "oval":
      return frame ? <OvalGuide oval={guide} frame={frame} /> : null;
    case "turn":
      return <TurnGuide degrees={guide.degrees} />;
  }
}

/// The document frame at the centre of the camera's area, at the policy's
/// aspect and as large as fits there: 86% of the area's width or of its
/// height, whichever binds, and no wider than 560 px.
function RectGuide({ aspect }: { aspect: number }) {
  return (
    <div
      className="pointer-events-none absolute inset-0 flex items-center justify-center"
      style={{ containerType: "size" }}
    >
      <div
        className="relative"
        style={{
          width: `min(86cqw, 560px, calc(86cqh * ${aspect}))`,
          aspectRatio: aspect,
          boxShadow: "0 0 0 9999px rgba(0, 0, 0, 0.6)",
          borderRadius: "1rem",
        }}
      >
        <span
          aria-hidden
          className="absolute -left-0.5 -top-0.5 size-6 rounded-tl-2xl border-l-[3px] border-t-[3px] border-white"
        />
        <span
          aria-hidden
          className="absolute -right-0.5 -top-0.5 size-6 rounded-tr-2xl border-r-[3px] border-t-[3px] border-white"
        />
        <span
          aria-hidden
          className="absolute -right-0.5 -bottom-0.5 size-6 rounded-br-2xl border-r-[3px] border-b-[3px] border-white"
        />
        <span
          aria-hidden
          className="absolute -left-0.5 -bottom-0.5 size-6 rounded-bl-2xl border-l-[3px] border-b-[3px] border-white"
        />
      </div>
    </div>
  );
}

/// The oval at the centre of the frame, its size at its fractions of the
/// frame's shorter side.
function OvalGuide({ oval, frame }: { oval: Extract<Guide, { kind: "oval" }>; frame: FrameBox }) {
  const shorter = Math.min(frame.width, frame.height);
  const width = oval.width * shorter;
  const height = oval.height * shorter;
  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden">
      <div
        className="absolute border-[3px] border-white/80"
        style={{
          left: frame.left + (frame.width - width) / 2,
          top: frame.top + (frame.height - height) / 2,
          width,
          height,
          borderRadius: "50%",
          boxShadow: "0 0 0 9999px rgba(0, 0, 0, 0.6)",
        }}
      />
    </div>
  );
}

/// Which way to turn the head, said by the page: a turn's degrees are the
/// applicant's own, negative to their left.
export function turnText(degrees: number): string {
  return degrees < 0
    ? "Turn your head to your left"
    : degrees > 0
      ? "Turn your head to your right"
      : "Look straight at the camera";
}

function TurnGuide({ degrees }: { degrees: number }) {
  return (
    <div className="pointer-events-none absolute inset-x-0 bottom-6 flex justify-center">
      <div className="rounded-full bg-black/60 px-4 py-1.5 text-sm font-medium">
        {turnText(degrees)}
      </div>
    </div>
  );
}

/// Pick a sensible `facingMode` ideal for `getUserMedia` from the
/// WIT camera-facing variant. `any` lets the browser default kick in
/// — useful for laptops without a rear lens.
function cameraFacingHint(c: CameraFacing): MediaTrackConstraints["facingMode"] {
  switch (c) {
    case "front":
      return { ideal: "user" };
    case "rear":
      return { ideal: "environment" };
    case "any":
      return undefined;
  }
}
