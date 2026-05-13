import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { pickLocalized } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import type { CaptureStep, Translations } from "@/types";

type Props = {
  /// Header shown at the top of the capture screen — describes
  /// the artifact as a whole (e.g. "Your passport", "Holder A's ID").
  promptLabel: Translations;
  /// One step of the artifact's capture sequence. Drives camera
  /// facing, the overlay guide (rect / oval / none) and the
  /// per-step hint label.
  step: CaptureStep;
  /// One-based step index plus total — surfaced in the hint as
  /// "Step N of M" when M > 1.
  stepNumber: number;
  totalSteps: number;
  /// Fired once the user confirms with a `FormData` payload ready
  /// to POST: each captured frame is its own part (`frame`),
  /// JPEG-encoded. The host treats each part as raw bytes and hands
  /// the list to the plugin layer for analysis — no client-side
  /// warp, no video container, just the frames.
  onCapture: (form: FormData) => void;
  /// True while the parent is submitting the form. Disables both
  /// Retake and Use-photo buttons so the user can't double-tap or
  /// retake mid-submit. Surfaced as a prop (not local state) so the
  /// parent's submit lifecycle is the single source of truth — on
  /// error the parent flips it back to false and the buttons
  /// re-enable for retry.
  sending?: boolean;
  /// Optional cancel callback for permission-denied flows etc.
  onCancel?: () => void;
};

type Phase =
  | "initializing"
  | "streaming"
  | "recording"
  | "preview"
  | "error";

// Capture parameters — pulled out so the trade-offs are visible. 12
// frames at 80ms apart covers ~1s and gives the enclave enough
// temporal samples for parallax / glare-drift / hand-jitter checks
// without ballooning the upload (12 × ~80KB ≈ 1MB at 0.85 quality).
const FRAME_COUNT = 12;
const FRAME_INTERVAL_MS = 80;
const JPEG_QUALITY = 0.85;
/// Total time the rAF-driven progress ring takes to fill. Slightly
/// longer than the bare frame-interval product (11 × 80 = 880ms) to
/// soak up `toBlob` overhead per frame — keeps the ring from
/// pegging at 100% before the last frame actually lands.
const EXPECTED_CAPTURE_DURATION_MS = (FRAME_COUNT - 1) * FRAME_INTERVAL_MS + 120;

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
  // Off-DOM canvas reused across frame-grabs to avoid per-frame
  // allocation thrash.
  const grabCanvasRef = useRef<HTMLCanvasElement | null>(null);
  // Captured frames retained until the user confirms or retakes.
  const framesRef = useRef<Blob[]>([]);
  // First frame as object URL — drives the preview <img>. Object URL
  // lifecycle is managed via revoke on unmount/retake.
  const previewUrlRef = useRef<string | null>(null);

  const streamRef = useRef<MediaStream | null>(null);
  // Bumped on Retake to re-run the camera-bootstrap effect.
  const [attempt, setAttempt] = useState(0);

  const [phase, setPhase] = useState<Phase>("initializing");
  const [errorMsg, setErrorMsg] = useState<string>("");
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  // 0..1 — completed-frame ratio while phase === "recording".
  // Drives the conic-gradient pie that fills the capture button so
  // the UX reads as "still photo with a brief hold-still moment",
  // not as video recording.
  const [captureProgress, setCaptureProgress] = useState(0);

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

  async function startCapture() {
    if (phase !== "streaming") return;
    const video = videoRef.current;
    if (!video || video.videoWidth === 0) return;

    setPhase("recording");
    setCaptureProgress(0);
    framesRef.current = [];
    haptic(15);

    // rAF-driven progress fill: decoupled from the frame-capture
    // cadence so the ring renders at display refresh rate (60–120 Hz)
    // instead of in 12 discrete 80ms jumps. The capture loop below
    // runs in parallel; if it overruns the expected duration, the
    // ring pegs at 100% until the last frame lands.
    const captureStart = performance.now();
    let rafId = requestAnimationFrame(function tick() {
      const elapsed = performance.now() - captureStart;
      const p = Math.min(1, elapsed / EXPECTED_CAPTURE_DURATION_MS);
      setCaptureProgress(p);
      if (p < 1) {
        rafId = requestAnimationFrame(tick);
      }
    });

    const canvas = grabCanvasRef.current ?? document.createElement("canvas");
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    grabCanvasRef.current = canvas;
    const ctx = canvas.getContext("2d");
    if (!ctx) {
      cancelAnimationFrame(rafId);
      setPhase("error");
      setErrorMsg("Could not capture the photo.");
      return;
    }

    try {
      for (let i = 0; i < FRAME_COUNT; i++) {
        ctx.drawImage(video, 0, 0);
        const blob = await new Promise<Blob | null>((resolve) =>
          canvas.toBlob(resolve, "image/jpeg", JPEG_QUALITY),
        );
        if (!blob) {
          throw new Error("toBlob returned null");
        }
        framesRef.current.push(blob);
        if (i < FRAME_COUNT - 1) {
          await new Promise<void>((r) =>
            window.setTimeout(r, FRAME_INTERVAL_MS),
          );
        }
      }
    } catch {
      cancelAnimationFrame(rafId);
      setPhase("error");
      setErrorMsg("Capture failed. Please retry.");
      return;
    }

    cancelAnimationFrame(rafId);
    setCaptureProgress(1);
    haptic(30);

    streamRef.current?.getTracks().forEach((t) => t.stop());
    streamRef.current = null;

    if (previewUrlRef.current) URL.revokeObjectURL(previewUrlRef.current);
    const previewBlob = framesRef.current[0];
    previewUrlRef.current = URL.createObjectURL(previewBlob);
    setPreviewUrl(previewUrlRef.current);

    setPhase("preview");
  }

  function retake() {
    if (previewUrlRef.current) {
      URL.revokeObjectURL(previewUrlRef.current);
      previewUrlRef.current = null;
    }
    setPreviewUrl(null);
    framesRef.current = [];
    setPhase("initializing");
    setAttempt((a) => a + 1);
  }

  function confirm() {
    if (framesRef.current.length === 0) return;
    // Guard against double-fire: the buttons themselves get
    // disabled while `sending`, but tap-bursts on touch devices can
    // sometimes register two onClicks before React commits the
    // disabled state. This local check makes the second one a
    // no-op.
    if (sending) return;
    const form = new FormData();
    framesRef.current.forEach((blob, i) => {
      // RFC 7578 allows repeated names — axum's Multipart preserves
      // part order, so we just append under one name per part.
      form.append("frame", blob, `${i}.jpg`);
    });
    onCapture(form);
  }

  const showCamera = phase === "streaming" || phase === "recording";
  const stepText = pickLocalized(step.label);
  const promptText = pickLocalized(promptLabel);
  const stepHint =
    totalSteps > 1
      ? `Step ${stepNumber} of ${totalSteps}. ${stepText}`
      : stepText;

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
            !showCamera && "invisible",
          )}
        />
        {showCamera && (
          <>
            <GuideOverlay guide={step.guide} />
            <div className="pointer-events-none absolute inset-x-6 top-6 space-y-1 text-center">
              <p className="text-xs uppercase tracking-wide text-white/70">
                {promptText}
              </p>
              <p className="rounded-md bg-black/60 px-3 py-2 text-sm">
                {stepHint}
              </p>
            </div>
            {phase === "recording" && (
              <div className="pointer-events-none absolute inset-x-0 top-24 flex justify-center">
                <div className="rounded-full bg-black/60 px-4 py-1.5 text-sm font-medium">
                  Hold still
                </div>
              </div>
            )}
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
              {pickLocalized(step.review_hint)}
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
              disabled={sending}
            >
              Retake
            </Button>
            <Button
              size="lg"
              className="h-12 flex-1 bg-white text-black hover:bg-white/90"
              onClick={confirm}
              disabled={sending}
            >
              {sending ? (
                <span className="inline-flex items-center gap-2">
                  <span
                    aria-hidden
                    className="size-3.5 animate-spin rounded-full border-2 border-black/30 border-t-black"
                  />
                  Sending…
                </span>
              ) : (
                "Use photo"
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
              aria-label={
                phase === "recording" ? "Capturing — hold still" : "Capture"
              }
              disabled={phase !== "streaming"}
              onClick={() => void startCapture()}
              className={cn(
                "flex size-16 items-center justify-center rounded-full border-4 transition-all duration-150",
                phase === "recording"
                  ? "border-white/40 cursor-default"
                  : "border-white/80",
                phase === "streaming" && "active:scale-95",
                (phase === "initializing" || phase === "error") &&
                  "opacity-40 cursor-not-allowed",
              )}
            >
              <span
                className={cn(
                  "block size-12 rounded-full",
                  phase !== "recording" && "bg-white",
                )}
                style={
                  phase === "recording"
                    ? {
                        background: `conic-gradient(from -90deg, white 0deg ${
                          captureProgress * 360
                        }deg, rgba(255,255,255,0.25) ${
                          captureProgress * 360
                        }deg 360deg)`,
                      }
                    : undefined
                }
              />
            </button>
            {onCancel && <span className="size-12" aria-hidden />}
          </>
        )}
      </div>
    </main>
  );
}

/// Render the on-screen capture guide overlaid on the camera preview.
/// Three flavours match the WIT `capture-guide` variant: nothing,
/// rectangle (document framing), oval (face/liveness).
function GuideOverlay({ guide }: { guide: CaptureStep["guide"] }) {
  if (guide.kind === "none") return null;
  if (guide.kind === "rect") {
    return <RectGuide aspect={guide.aspect} />;
  }
  return <OvalGuide />;
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

function OvalGuide() {
  return (
    <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
      <div
        className="relative border-[3px] border-white/80"
        style={{
          width: "min(70vw, 400px)",
          aspectRatio: 0.75,
          borderRadius: "50%",
          boxShadow: "0 0 0 9999px rgba(0, 0, 0, 0.6)",
        }}
      />
    </div>
  );
}

/// Pick a sensible `facingMode` ideal for `getUserMedia` from the
/// WIT camera-facing variant. `any` lets the browser default kick in
/// — useful for laptops without a rear lens.
function cameraFacingHint(
  c: CaptureStep["camera"],
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
