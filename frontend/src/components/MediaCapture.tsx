import { useEffect, useRef, useState, type RefObject } from "react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type { Guide, PhotoStep } from "@/types";

type Props = {
  /// Header shown at the top of the capture screen — describes
  /// the artifact as a whole (e.g. "Your passport", "Holder A's ID").
  promptLabel: string;
  /// One photo step of the artifact's capture sequence. Drives camera
  /// facing, the overlay guide and the per-step hint label.
  step: PhotoStep;
  /// One-based step index plus total — surfaced in the hint as
  /// "Step N of M" when M > 1.
  stepNumber: number;
  totalSteps: number;
  /// Fired once the user keeps the photo: the one frame shown on the
  /// review screen, JPEG-encoded — what is shown is what is sent.
  onCapture: (photo: Blob) => void;
  /// True while the parent is submitting the capture. Disables both
  /// Retake and Use-photo buttons so the user can't double-tap or
  /// retake mid-submit. Surfaced as a prop (not local state) so the
  /// parent's submit lifecycle is the single source of truth — on
  /// error the parent flips it back to false and the buttons
  /// re-enable for retry.
  sending?: boolean;
  /// Optional cancel callback for permission-denied flows etc.
  onCancel?: () => void;
};

type Phase = "initializing" | "streaming" | "taking" | "preview" | "error";

const JPEG_QUALITY = 0.85;

/// Best-effort haptic ping. iOS Safari silently ignores; Android /
/// Chrome OS hit a short vibration. Wrapped so callers don't repeat
/// the optional-chain dance everywhere.
function haptic(pattern: number | number[]) {
  if (typeof navigator !== "undefined" && navigator.vibrate) {
    navigator.vibrate(pattern);
  }
}

export function MediaCapture({
  promptLabel,
  step,
  stepNumber,
  totalSteps,
  onCapture,
  sending = false,
  onCancel,
}: Props) {
  const videoRef = useRef<HTMLVideoElement>(null);
  // Set from the "Use photo" tap until the parent's submit ends without a new
  // step — through the moment before the parent's `sending` turns on. The ref
  // turns a second tap away at once; the state shows the first one taken.
  const busyRef = useRef(false);
  const [busy, setBusy] = useState(false);
  const wasSending = useRef(false);
  useEffect(() => {
    // The submit ended and this step is still on screen — it failed, and the
    // same photo may be sent again or retaken.
    if (wasSending.current && !sending) {
      busyRef.current = false;
      setBusy(false);
    }
    wasSending.current = sending;
  }, [sending]);
  // The photo taken, retained until the user keeps or retakes it.
  const photoRef = useRef<Blob | null>(null);
  // The photo as object URL — drives the preview <img>. Object URL
  // lifecycle is managed via revoke on unmount/retake.
  const previewUrlRef = useRef<string | null>(null);

  const streamRef = useRef<MediaStream | null>(null);
  // Bumped on Retake to re-run the camera-bootstrap effect.
  const [attempt, setAttempt] = useState(0);

  const [phase, setPhase] = useState<Phase>("initializing");
  // A camera facing the applicant is shown as a mirror, as a phone's own
  // camera shows a selfie — otherwise every move reads backwards. Only the
  // view turns: the photo is drawn from the stream as the camera sees it,
  // and the photo to review is the one that is sent.
  const [mirrored, setMirrored] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string>("");
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const frame = useFrameBox(videoRef);

  useEffect(() => {
    let cancelled = false;

    void (async () => {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          video: {
            facingMode: cameraFacingHint(step.camera),
            width: { ideal: 1920 },
            height: { ideal: 1080 },
          },
          audio: false,
        });
        if (cancelled) {
          stream.getTracks().forEach((t) => t.stop());
          return;
        }
        streamRef.current = stream;
        // A computer's camera may not say which way it faces; one asked for
        // as the front is taken to face the applicant.
        const facing = stream.getVideoTracks()[0]?.getSettings().facingMode;
        setMirrored(facing ? facing === "user" : step.camera === "front");

        const video = videoRef.current;
        if (!video) return;
        video.srcObject = stream;
        await video.play();

        setPhase("streaming");
      } catch (e) {
        if (cancelled) return;
        setPhase("error");
        if (e instanceof DOMException && e.name === "NotAllowedError") {
          setErrorMsg(
            "Camera access was denied. Allow camera permission in your browser settings, then retry.",
          );
        } else if (e instanceof DOMException && e.name === "NotFoundError") {
          setErrorMsg("No camera was found on this device.");
        } else {
          setErrorMsg("Could not start the camera.");
        }
      }
    })();

    return () => {
      cancelled = true;
      streamRef.current?.getTracks().forEach((t) => t.stop());
      streamRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [attempt, step.camera]);

  useEffect(() => {
    return () => {
      if (previewUrlRef.current) URL.revokeObjectURL(previewUrlRef.current);
    };
  }, []);

  async function takePhoto() {
    if (phase !== "streaming") return;
    const video = videoRef.current;
    if (!video || video.videoWidth === 0) return;

    setPhase("taking");
    haptic(15);

    const canvas = document.createElement("canvas");
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    const ctx = canvas.getContext("2d");
    if (!ctx) {
      setPhase("error");
      setErrorMsg("Could not capture the photo.");
      return;
    }
    ctx.drawImage(video, 0, 0);
    const photo = await new Promise<Blob | null>((resolve) =>
      canvas.toBlob(resolve, "image/jpeg", JPEG_QUALITY),
    );
    if (!photo) {
      setPhase("error");
      setErrorMsg("Capture failed. Please retry.");
      return;
    }
    photoRef.current = photo;

    streamRef.current?.getTracks().forEach((t) => t.stop());
    streamRef.current = null;

    if (previewUrlRef.current) URL.revokeObjectURL(previewUrlRef.current);
    previewUrlRef.current = URL.createObjectURL(photo);
    setPreviewUrl(previewUrlRef.current);

    setPhase("preview");
  }

  function retake() {
    if (previewUrlRef.current) {
      URL.revokeObjectURL(previewUrlRef.current);
      previewUrlRef.current = null;
    }
    setPreviewUrl(null);
    photoRef.current = null;
    setPhase("initializing");
    setAttempt((a) => a + 1);
  }

  function keep() {
    const photo = photoRef.current;
    if (!photo) return;
    // Guard against double-fire: the buttons are disabled from the first
    // tap, but tap-bursts on touch devices can register two onClicks
    // before React commits the disabled state. The ref makes the second a
    // no-op, and holds until the parent's submit is over.
    if (sending || busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    onCapture(photo);
  }

  const showCamera = phase === "streaming" || phase === "taking";
  const stepText = step.label;
  const promptText = promptLabel;
  const stepHint =
    totalSteps > 1
      ? `Step ${stepNumber} of ${totalSteps}. ${stepText}`
      : stepText;
  const lastStep = stepNumber === totalSteps;

  return (
    <main
      className="flex h-dvh flex-col bg-black text-white"
      style={{
        paddingTop: "max(env(safe-area-inset-top), 0px)",
        paddingBottom: "max(env(safe-area-inset-bottom), 0px)",
      }}
    >
      <div className="relative min-h-0 flex-1 overflow-hidden">
        {/* Video element must be in the DOM before getUserMedia
            resolves, otherwise videoRef stays null and the bootstrap
            effect silently bails before transitioning to "streaming".
            Render it unconditionally; visibility is gated by phase. */}
        <video
          ref={videoRef}
          playsInline
          muted
          autoPlay
          className={cn(
            "absolute inset-0 size-full object-cover",
            mirrored && "-scale-x-100",
            !showCamera && "invisible",
          )}
        />
        {showCamera && (
          <>
            {step.guide && (
              <GuideOverlay guide={step.guide} frame={frame} mirrored={mirrored} />
            )}
            <div className="pointer-events-none absolute inset-x-6 top-6 space-y-1 text-center">
              <p className="text-xs uppercase tracking-wide text-white/70">
                {promptText}
              </p>
              <p className="rounded-md bg-black/60 px-3 py-2 text-sm">
                {stepHint}
              </p>
            </div>
          </>
        )}

        {phase === "preview" && previewUrl && (
          <>
            <img
              src={previewUrl}
              alt="Captured preview"
              className="absolute inset-0 size-full object-contain"
            />
            <div
              className="pointer-events-none absolute inset-x-6 top-6 rounded-md bg-black/70 px-3 py-2 text-center text-sm"
              style={{
                paddingTop: "max(env(safe-area-inset-top), 0.5rem)",
              }}
            >
              {step.review_hint}
            </div>
          </>
        )}

        {phase === "error" && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-4 px-6 text-center">
            <p className="text-sm text-white/90">{errorMsg}</p>
            <Button onClick={retake} className="bg-white text-black">
              Try again
            </Button>
          </div>
        )}
      </div>

      <div
        className={cn(
          "flex shrink-0 items-center justify-center gap-3 px-6 py-4",
          phase === "error" && "hidden",
        )}
      >
        {phase === "preview" ? (
          <>
            <Button
              variant="secondary"
              size="lg"
              className="h-12 flex-1 bg-white/10 text-white hover:bg-white/20"
              onClick={retake}
              disabled={sending || busy}
            >
              Retake
            </Button>
            <Button
              size="lg"
              className="h-12 flex-1 bg-white text-black hover:bg-white/90"
              onClick={keep}
              disabled={sending || busy}
            >
              {sending ? (
                <span className="inline-flex items-center gap-2">
                  <span
                    aria-hidden
                    className="size-3.5 animate-spin rounded-full border-2 border-black/30 border-t-black"
                  />
                  Sending…
                </span>
              ) : lastStep ? (
                "Use photo"
              ) : (
                "Next"
              )}
            </Button>
          </>
        ) : (
          <>
            {onCancel && (
              <Button
                variant="ghost"
                size="lg"
                className="h-12 text-white hover:bg-white/10"
                onClick={onCancel}
              >
                Cancel
              </Button>
            )}
            <button
              type="button"
              aria-label="Capture"
              disabled={phase !== "streaming"}
              onClick={() => void takePhoto()}
              className={cn(
                "flex size-16 items-center justify-center rounded-full border-4 border-white/80 transition-all duration-150",
                phase === "streaming" && "active:scale-95",
                phase !== "streaming" && "opacity-40 cursor-not-allowed",
              )}
            >
              <span className="block size-12 rounded-full bg-white" />
            </button>
            {onCancel && <span className="size-12" aria-hidden />}
          </>
        )}
      </div>
    </main>
  );
}

/// Where the camera's frame lies on screen, in the video element's own box,
/// as `object-cover` draws it: scaled to cover the box, centred, and cut at
/// its edges.
type FrameBox = { left: number; top: number; width: number; height: number };

/// The [`FrameBox`] of `video`, kept as the camera's size or the element's
/// changes; `null` until the camera says its size.
function useFrameBox(
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
function GuideOverlay({
  guide,
  frame,
  mirrored,
}: {
  guide: Guide;
  frame: FrameBox | null;
  mirrored: boolean;
}) {
  switch (guide.kind) {
    case "rect":
      return <RectGuide aspect={guide.aspect} />;
    case "oval":
      return frame ? (
        <OvalGuide oval={guide} frame={frame} mirrored={mirrored} />
      ) : null;
    case "turn":
      return <TurnGuide degrees={guide.degrees} />;
  }
}

function RectGuide({ aspect }: { aspect: number }) {
  return (
    <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
      <div
        className="relative"
        style={{
          width: "min(86vw, 560px)",
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

/// The oval where it lies in the frame: its centre at its fractions of the
/// frame's width and height, its size at its fractions of the frame's shorter
/// side. The frame is the camera's, so a mirrored view mirrors the oval too.
function OvalGuide({
  oval,
  frame,
  mirrored,
}: {
  oval: Extract<Guide, { kind: "oval" }>;
  frame: FrameBox;
  mirrored: boolean;
}) {
  const shorter = Math.min(frame.width, frame.height);
  const width = oval.width * shorter;
  const height = oval.height * shorter;
  const centerX = mirrored ? 1 - oval.center_x : oval.center_x;
  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden">
      <div
        className="absolute border-[3px] border-white/80"
        style={{
          left: frame.left + centerX * frame.width - width / 2,
          top: frame.top + oval.center_y * frame.height - height / 2,
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
function TurnGuide({ degrees }: { degrees: number }) {
  const text =
    degrees < 0
      ? "Turn your head to your left"
      : degrees > 0
        ? "Turn your head to your right"
        : "Look straight at the camera";
  return (
    <div className="pointer-events-none absolute inset-x-0 bottom-6 flex justify-center">
      <div className="rounded-full bg-black/60 px-4 py-1.5 text-sm font-medium">
        {text}
      </div>
    </div>
  );
}

/// Pick a sensible `facingMode` ideal for `getUserMedia` from the
/// WIT camera-facing variant. `any` lets the browser default kick in
/// — useful for laptops without a rear lens.
function cameraFacingHint(
  c: PhotoStep["camera"],
): MediaTrackConstraints["facingMode"] {
  switch (c) {
    case "front":
      return { ideal: "user" };
    case "rear":
      return { ideal: "environment" };
    case "any":
      return undefined;
  }
}
