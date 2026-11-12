import { useEffect, useState, type RefObject } from "react";
import type { Hint } from "@/lib/guides";
import { cn } from "@/lib/utils";
import type { CameraFacing, Shape } from "@/types";

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

/// How far a hold that began at `heldAt`, on the page's clock, is through
/// `holdMs`, from 0 to 1, redrawn every display frame; `undefined` while
/// nothing is held.
export function useHoldFill(heldAt: number | null, holdMs: number): number | undefined {
  const [fill, setFill] = useState<number>();
  useEffect(() => {
    if (heldAt === null) {
      setFill(undefined);
      return;
    }
    let frame = requestAnimationFrame(function tick() {
      const share = holdMs > 0 ? Math.min(1, (performance.now() - heldAt) / holdMs) : 1;
      setFill(share);
      if (share < 1) frame = requestAnimationFrame(tick);
    });
    return () => cancelAnimationFrame(frame);
  }, [heldAt, holdMs]);
  return fill;
}

/// The round shutter: a white disc in a ring. Given `fill`, from 0 to 1, the
/// disc fills that far round instead, while what it took is held.
export function ShutterButton({
  label,
  disabled = false,
  onClick,
  fill,
}: {
  label: string;
  disabled?: boolean;
  onClick: () => void;
  fill?: number;
}) {
  const filling = fill !== undefined;
  return (
    <button
      type="button"
      aria-label={label}
      disabled={disabled || filling}
      onClick={onClick}
      className={cn(
        "flex size-16 items-center justify-center rounded-full border-4 transition-all duration-150",
        filling ? "cursor-default border-white/40" : "border-white/80",
        !disabled && !filling && "active:scale-95",
        disabled && "cursor-not-allowed opacity-40",
      )}
    >
      <span
        className={cn("block size-12 rounded-full", !filling && "bg-white")}
        style={
          filling
            ? {
                background: `conic-gradient(from -90deg, white 0deg ${fill * 360}deg, rgba(255,255,255,0.25) ${fill * 360}deg 360deg)`,
              }
            : undefined
        }
      />
    </button>
  );
}

/// The camera around a guide, dimmed.
const DIM = "rgba(0, 0, 0, 0.6)";

/// Render a shape overlaid on the camera preview, one flavour for each kind
/// of the WIT `shape` variant.
export function GuideOverlay({
  shape,
  frame,
  met = false,
  surround = DIM,
  inside,
  fill,
}: {
  shape: Shape;
  frame: FrameBox | null;
  /// Whether the face the page reads fills it, which an oval shows in green.
  met?: boolean;
  /// What the screen shows around it: the camera dimmed, or a colour.
  surround?: string;
  /// A colour drawn over the camera inside an oval; none where it shows the
  /// camera as it is.
  inside?: string;
  /// How far round from its top an oval's outline is filled, from 0 to 1,
  /// while the face is held in it; none while it is not.
  fill?: number;
}) {
  switch (shape.kind) {
    case "rect":
      return <RectGuide aspect={shape.aspect} surround={surround} />;
    case "oval":
      return frame ? (
        <OvalGuide
          oval={shape}
          frame={frame}
          met={met}
          surround={surround}
          inside={inside}
          fill={fill}
        />
      ) : null;
  }
}

/// The frame at the centre of the camera's area, at the policy's
/// aspect and as large as fits there: 86% of the area's width or of its
/// height, whichever binds, and no wider than 560 px.
function RectGuide({ aspect, surround }: { aspect: number; surround: string }) {
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
          boxShadow: `0 0 0 9999px ${surround}`,
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
function OvalGuide({
  oval,
  frame,
  met,
  surround,
  inside,
  fill,
}: {
  oval: Extract<Shape, { kind: "oval" }>;
  frame: FrameBox;
  met: boolean;
  surround: string;
  inside?: string;
  fill?: number;
}) {
  const shorter = Math.min(frame.width, frame.height);
  const width = oval.width * shorter;
  const height = oval.height * shorter;
  const left = frame.left + (frame.width - width) / 2;
  const top = frame.top + (frame.height - height) / 2;
  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden">
      <div
        className={cn(
          "absolute border-[3px] transition-colors",
          met ? "border-green-500" : "border-white/80",
        )}
        style={{
          left,
          top,
          width,
          height,
          borderRadius: "50%",
          boxShadow: `0 0 0 9999px ${surround}`,
          background: inside,
        }}
      />
      {fill !== undefined && fill > 0 && (
        <svg
          className="absolute overflow-visible"
          style={{ left, top, width, height }}
          viewBox={`0 0 ${width} ${height}`}
        >
          <path
            d={outline(width, height)}
            pathLength={1}
            strokeDasharray={`${fill} 1`}
            fill="none"
            stroke="#22c55e"
            strokeWidth={ARC_INSET * 2}
            strokeLinecap="round"
          />
        </svg>
      )}
    </div>
  );
}

/// How far in from an oval's edge an arc is drawn on it, in pixels: half its
/// stroke, so the stroke stays inside the oval's box.
const ARC_INSET = 3;

/// The outline of an oval `w` × `h` pixels, from its top round clockwise and
/// back.
function outline(w: number, h: number): string {
  const rx = w / 2 - ARC_INSET;
  const ry = h / 2 - ARC_INSET;
  return [
    `M ${w / 2} ${ARC_INSET}`,
    `A ${rx} ${ry} 0 0 1 ${w / 2} ${h - ARC_INSET}`,
    `A ${rx} ${ry} 0 0 1 ${w / 2} ${ARC_INSET}`,
  ].join(" ");
}

/// A turn of the head, drawn: the oval the face was last asked to fill, if
/// any, its side toward the turn filling out from the middle as the head turns,
/// and chevrons pointing that way. A mirror shows the applicant's left on the
/// screen's left.
export function TurnGuide({
  oval,
  frame,
  degrees,
  turn,
  met,
  mirrored,
}: {
  oval: { width: number; height: number } | null;
  frame: FrameBox | null;
  /// The turn asked for, negative to the applicant's left; 0 for none.
  degrees: number;
  /// How far the head is turned now, in the same degrees; `null` where it is
  /// not read.
  turn: number | null;
  /// Whether the turn is held, which the arc shows whole and in green.
  met: boolean;
  mirrored: boolean;
}) {
  const box =
    oval && frame
      ? (() => {
          const shorter = Math.min(frame.width, frame.height);
          const width = oval.width * shorter;
          const height = oval.height * shorter;
          return {
            left: frame.left + (frame.width - width) / 2,
            top: frame.top + (frame.height - height) / 2,
            width,
            height,
          };
        })()
      : null;
  const ring = oval && frame && (
    <OvalGuide oval={{ kind: "oval", ...oval }} frame={frame} met={met} surround={DIM} />
  );
  if (degrees === 0) return ring;
  const left = degrees < 0 === mirrored;
  const toward = turn !== null && Math.sign(turn) === Math.sign(degrees) ? Math.abs(turn) : 0;
  const share = met ? 1 : Math.min(1, toward / Math.abs(degrees));
  const chevrons = (
    <div className={cn("flex", left && "flex-row-reverse")}>
      {[0, 1, 2].map((i) => (
        <svg
          key={i}
          viewBox="0 0 24 24"
          className="size-7 animate-pulse text-white drop-shadow"
          style={{ animationDelay: `${i * 200}ms` }}
        >
          <path
            d={left ? "M15 5l-7 7 7 7" : "M9 5l7 7-7 7"}
            fill="none"
            stroke="currentColor"
            strokeWidth={3}
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      ))}
    </div>
  );
  if (!box) {
    return (
      <div
        className={cn(
          "pointer-events-none absolute top-1/2 -translate-y-1/2",
          left ? "left-4" : "right-4",
        )}
      >
        {chevrons}
      </div>
    );
  }
  const { width: w, height: h } = box;
  const rx = w / 2 - ARC_INSET;
  const ry = h / 2 - ARC_INSET;
  const side = left ? ARC_INSET : w - ARC_INSET;
  // From the side's middle up to the top and down to the bottom: the sweep
  // that goes round that side.
  const arcs = [
    `M ${side} ${h / 2} A ${rx} ${ry} 0 0 ${left ? 1 : 0} ${w / 2} ${ARC_INSET}`,
    `M ${side} ${h / 2} A ${rx} ${ry} 0 0 ${left ? 0 : 1} ${w / 2} ${h - ARC_INSET}`,
  ];
  return (
    <>
      {ring}
      <svg
        className="pointer-events-none absolute overflow-visible"
        style={{ left: box.left, top: box.top, width: w, height: h }}
        viewBox={`0 0 ${w} ${h}`}
      >
        {share > 0 &&
          arcs.map((d) => (
            <path
              key={d}
              d={d}
              pathLength={1}
              strokeDasharray={`${share} 1`}
              fill="none"
              stroke={met ? "#22c55e" : "white"}
              strokeWidth={ARC_INSET * 2}
              strokeLinecap="round"
            />
          ))}
      </svg>
      <div
        className="pointer-events-none absolute -translate-y-1/2"
        style={{
          top: box.top + h / 2,
          ...(left ? { right: `calc(100% - ${box.left - 4}px)` } : { left: box.left + w + 4 }),
        }}
      >
        {chevrons}
      </div>
    </>
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

/// What the applicant is asked to do with `shape`: line up what the policy's
/// `label` names with it.
export function shapeText(shape: Shape, label: string): string {
  const fit = shape.kind === "rect" ? "Line it up with the frame" : "Line it up with the oval";
  return label ? `${label}. ${fit}` : fit;
}

/// What the applicant is told for `hint` about a guide the page reads their
/// face for; `lead`, what the guide asks, where they are yet to do it.
export function hintText(hint: Hint, lead: string): string {
  switch (hint) {
    case "show-face":
      return "Show your face to the camera";
    case "one-face":
      return "Only one face, please";
    case "closer":
      return "Move closer";
    case "back":
      return "Move back";
    case "left":
      return "Move left";
    case "right":
      return "Move right";
    case "centre":
      return "Center your face in the oval";
    case "turn":
      return lead;
    case "further":
      return "A little further";
    case "hold":
      return "Hold still";
  }
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
