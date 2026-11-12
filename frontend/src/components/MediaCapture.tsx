import { useEffect, useRef, useState } from "react";
import {
  GuideOverlay,
  ShutterButton,
  cameraConstraints,
  cameraError,
  facesApplicant,
  haptic,
  hintText,
  pictureSize,
  shapeText,
  useFrameBox,
  useHoldFill,
} from "@/components/camera";
import { Button } from "@/components/ui/button";
import { type Detector, loadDetector } from "@/lib/faces";
import { type Box, Head, type Hint, faceBox, hintFor, moved } from "@/lib/guides";
import { cn } from "@/lib/utils";
import type { PhotoStep } from "@/types";

type Props = {
  /// Header shown at the top of the capture screen — describes
  /// the artifact as a whole (e.g. "Your passport", "Holder A's ID").
  promptLabel: string;
  /// One photo step of the artifact's capture sequence. Drives camera
  /// facing, the overlay guide, the per-step hint label and whether the photo
  /// is reviewed.
  step: PhotoStep;
  /// One-based step index plus total — surfaced in the hint as
  /// "Step N of M" when M > 1.
  stepNumber: number;
  totalSteps: number;
  /// Fired once the user keeps the photo — at once where the step has no
  /// review screen: the one frame shown, JPEG-encoded — what is shown is what
  /// is sent.
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
/// How long the face holds still in a face guide's oval before the page takes
/// the photo — the sharpest of the frames meanwhile — in milliseconds, while
/// the oval's outline fills round.
const STEADY_MS = 1000;
/// How far the face may move from one look to the next and still be holding
/// still, as a share of its width: past what the detector's own jitter moves
/// it.
const STILL_SHIFT = 0.1;
/// How often the face is looked for, in milliseconds.
const LOOK_MS = 1000 / 15;
/// What a face guide asks.
const FACE_TEXT = "Fit your face in the oval";

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
  const guide = step.guide;
  const face = guide?.kind === "face" ? guide : null;
  const readsFace = face !== null;
  // The face detector, for a face guide: `undefined` while it loads, `null`
  // where this browser runs none — the shutter takes the photo then. The
  // camera waits for it.
  const [detector, setDetector] = useState<Detector | null>();
  // What the applicant is told about the face guide, from the latest frame.
  const [hint, setHint] = useState<Hint | null>(null);
  // Since when the face has held still in the guide's oval, on the page's
  // clock; `null` while it has not.
  const [heldAt, setHeldAt] = useState<number | null>(null);
  const fill = useHoldFill(heldAt, STEADY_MS);
  // The page takes the photo itself where it reads the face.
  const auto = readsFace && !!detector;

  useEffect(() => {
    if (!readsFace) return;
    let cancelled = false;
    loadDetector().then(
      (loaded) => {
        if (!cancelled) setDetector(loaded);
      },
      (error: unknown) => {
        if (cancelled) return;
        console.warn("The face detector did not load:", error);
        setDetector(null);
      },
    );
    return () => {
      cancelled = true;
    };
  }, [readsFace]);

  useEffect(() => {
    if (readsFace && detector === undefined) return;
    let cancelled = false;

    void (async () => {
      try {
        const stream = await navigator.mediaDevices.getUserMedia(
          cameraConstraints(step.camera),
        );
        if (cancelled) {
          stream.getTracks().forEach((t) => t.stop());
          return;
        }
        streamRef.current = stream;
        setMirrored(facesApplicant(stream, step.camera));

        const video = videoRef.current;
        if (!video) return;
        video.srcObject = stream;
        await video.play();

        setPhase("streaming");
      } catch (e) {
        if (cancelled) return;
        setPhase("error");
        setErrorMsg(cameraError(e));
      }
    })();

    return () => {
      cancelled = true;
      streamRef.current?.getTracks().forEach((t) => t.stop());
      streamRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [attempt, step.camera, detector]);

  useEffect(() => {
    return () => {
      if (previewUrlRef.current) URL.revokeObjectURL(previewUrlRef.current);
    };
  }, []);

  // A face guide: the applicant's face read against its oval, and the photo
  // taken once it has held still there for a moment: the sharpest frame of
  // that moment.
  useEffect(() => {
    if (phase !== "streaming" || !face || !detector) return;
    const head = new Head();
    let stopped = false;
    // Since when the face has held still in the oval, its box at the last
    // look, and the sharpest frame since then, at the photo's size.
    let since: number | null = null;
    let last: Box | null = null;
    let best: { frame: HTMLCanvasElement; sharpness: number } | null = null;
    let spare = document.createElement("canvas");
    const look = async () => {
      const video = videoRef.current;
      if (stopped || !video) return;
      const { videoWidth: width, videoHeight: height } = video;
      if (width && height) {
        const faces = await detector.faces(video, width, height);
        if (stopped) return;
        const next = hintFor(face, faces, head, width, height, mirrored);
        setHint(next);
        const box = next === "hold" ? faceBox(faces[0], face.height / face.width) : null;
        const still = box !== null && last !== null && moved(last, box) <= STILL_SHIFT;
        last = box;
        if (!still) {
          since = null;
          best = null;
        } else {
          since ??= performance.now();
          const size = pictureSize(width, height);
          if (spare.width !== size.width || spare.height !== size.height) {
            spare.width = size.width;
            spare.height = size.height;
          }
          spare.getContext("2d")?.drawImage(video, 0, 0, size.width, size.height);
          const k = size.width / width;
          const sharp = detector.sharpness(spare, {
            left: box.left * k,
            top: box.top * k,
            right: box.right * k,
            bottom: box.bottom * k,
          });
          if (!best || sharp > best.sharpness) {
            const previous = best?.frame;
            best = { frame: spare, sharpness: sharp };
            spare = previous ?? document.createElement("canvas");
          }
          if (performance.now() - since >= STEADY_MS) {
            void takePhoto(best.frame);
            return;
          }
        }
        setHeldAt(since);
      }
      setTimeout(() => void look(), LOOK_MS);
    };
    void look();
    return () => {
      stopped = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase, detector, mirrored]);

  /// Take the photo: `frame`, a frame the page picked, drawn at the photo's
  /// size; none: the camera's frame now.
  async function takePhoto(frame?: HTMLCanvasElement) {
    if (phase !== "streaming") return;
    const video = videoRef.current;
    if (!video || video.videoWidth === 0) return;

    setPhase("taking");
    haptic(15);

    let canvas = frame;
    if (!canvas) {
      // At the size the platform decodes the photo at, not one it would halve.
      const { width, height } = pictureSize(video.videoWidth, video.videoHeight);
      canvas = document.createElement("canvas");
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext("2d");
      if (!ctx) {
        setPhase("error");
        setErrorMsg("Could not capture the photo.");
        return;
      }
      ctx.drawImage(video, 0, 0, width, height);
    }
    const picture = canvas;
    const photo = await new Promise<Blob | null>((resolve) =>
      picture.toBlob(resolve, "image/jpeg", JPEG_QUALITY),
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
    // With no review screen the photo is sent as taken; the preview stays
    // while it is sent, and its buttons come back if the send fails.
    if (step.review_hint === null) keep();
  }

  function retake() {
    if (previewUrlRef.current) {
      URL.revokeObjectURL(previewUrlRef.current);
      previewUrlRef.current = null;
    }
    setPreviewUrl(null);
    photoRef.current = null;
    setHint(null);
    setHeldAt(null);
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
  const instruction =
    guide?.kind === "shape"
      ? shapeText(guide.shape, guide.label)
      : face
        ? hint === null
          ? FACE_TEXT
          : hintText(hint, FACE_TEXT)
        : null;

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
            {guide?.kind === "shape" && (
              <GuideOverlay shape={guide.shape} frame={frame} />
            )}
            {face && (
              <GuideOverlay
                shape={{ kind: "oval", width: face.width, height: face.height }}
                frame={frame}
                met={hint === "hold"}
                fill={fill}
              />
            )}
            <div className="pointer-events-none absolute inset-x-6 top-6 space-y-1 text-center">
              <p className="text-xs uppercase tracking-wide text-white/70">
                {promptText}
              </p>
              <p className="rounded-md bg-black/60 px-3 py-2 text-sm">
                {stepHint}
              </p>
            </div>
            {instruction && (
              <div className="pointer-events-none absolute inset-x-0 bottom-6 flex justify-center px-6">
                <div
                  className={cn(
                    "rounded-full px-4 py-1.5 text-center text-sm font-medium",
                    hint === "hold" ? "bg-white text-black" : "bg-black/60",
                  )}
                >
                  {instruction}
                </div>
              </div>
            )}
          </>
        )}

        {phase === "initializing" && (
          <div className="absolute inset-0 flex items-center justify-center">
            <p className="inline-flex items-center gap-2 text-sm text-white/80">
              <span
                aria-hidden
                className="size-3.5 animate-spin rounded-full border-2 border-white/30 border-t-white"
              />
              Getting ready…
            </p>
          </div>
        )}

        {phase === "preview" && previewUrl && (
          <>
            <img
              src={previewUrl}
              alt="Captured preview"
              className="absolute inset-0 size-full object-contain"
            />
            {step.review_hint !== null && (
              <div
                className="pointer-events-none absolute inset-x-6 top-6 rounded-md bg-black/70 px-3 py-2 text-center text-sm"
                style={{
                  paddingTop: "max(env(safe-area-inset-top), 0.5rem)",
                }}
              >
                {step.review_hint}
              </div>
            )}
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
            {auto ? (
              <p className="inline-flex h-12 items-center text-sm text-white/80">
                The photo is taken when your face fills the oval
              </p>
            ) : (
              <ShutterButton
                label="Capture"
                disabled={phase !== "streaming"}
                onClick={() => void takePhoto()}
              />
            )}
            {onCancel && <span className="size-12" aria-hidden />}
          </>
        )}
      </div>
    </main>
  );
}
