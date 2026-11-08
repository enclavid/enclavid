import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  GuideOverlay,
  ShutterButton,
  cameraConstraints,
  cameraError,
  facesApplicant,
  haptic,
  turnText,
  useFrameBox,
} from "@/components/camera";
import { Button } from "@/components/ui/button";
import { type Detector, loadDetector } from "@/lib/faces";
import { Head, type Hint, hintFor } from "@/lib/guides";
import {
  FPS,
  type RecorderKind,
  type Recording,
  readBack,
  recorderFor,
  startRecording,
} from "@/lib/recorder";
import { cn } from "@/lib/utils";
import type { VideoGuide, VideoStep } from "@/types";

type Props = {
  /// Header shown at the top of the capture screen — describes the artifact
  /// as a whole (e.g. "Your selfie").
  promptLabel: string;
  /// One video step of the artifact's capture sequence: the camera it faces,
  /// and the guides shown while it records, in order.
  step: VideoStep;
  /// One-based step index plus total — surfaced in the hint as "Step N of M"
  /// when M > 1.
  stepNumber: number;
  totalSteps: number;
  /// The most bytes the video may be: its share of what the steps not sent
  /// yet may hold together.
  maxBytes: number;
  /// Fired once the recording is over: the video, and for each of the step's
  /// guides, in order, the first and the last frame it was held in.
  onRecorded: (video: Blob, guides: [number, number][]) => void;
  /// True while the parent is sending the video. Surfaced as a prop for the
  /// reason `MediaCapture`'s is: the parent's submit is the one source of
  /// truth, and a send that ends with the step still on screen failed.
  sending: boolean;
  /// What the applicant may do where this browser cannot record the video:
  /// continue on another device.
  instead: ReactNode;
};

/// How long a guide the page reads waits to be followed before the recording
/// stops.
const FOLLOW_MS = 10_000;
/// How long a hold outlasts frames that do not follow its guide.
const GRACE_MS = 300;
/// How long the face may be gone while a guide that reads it is shown.
const LOST_MS = 1500;
/// How long the applicant follows the first guide before the recording starts
/// by itself.
const GATE_MS = 300;
/// The longest recording, in milliseconds: inside the 900 frames of a video
/// the enclave reads, at the page's rate.
const MAX_MS = (900 / FPS) * 1000 - 5000;
/// The longer side of the recorded frames at most, in pixels.
const MAX_SIDE = 1280;
/// The bits a second the recording is held between.
const MIN_BITRATE = 250_000;
const MAX_BITRATE = 1_500_000;

/// Whether the page reads the applicant's face for `guide`: every guide but a
/// static one, which the applicant confirms.
const reads = (guide: VideoGuide) => guide.kind !== "static_guide";

/// What the page waits for before it records a step whose first guide it
/// reads, `first`: that face, or a head turned no way.
function entryOf(first: VideoGuide): VideoGuide {
  return first.kind === "head_turn" ? { kind: "head_turn", degrees: 0, hold_ms: 0 } : first;
}

/// The longest a recording of `guides` may last: as long as a recording may
/// where a static guide waits on the applicant.
function longest(guides: VideoGuide[]): number {
  if (!guides.every(reads)) return MAX_MS;
  return Math.min(
    MAX_MS,
    guides.reduce((ms, g) => ms + FOLLOW_MS + g.hold_ms, 0),
  );
}

/// For each of the guides' holds, in order — milliseconds from the first
/// frame — the first and the last of the video's frames, at `times`, inside
/// it; `null` where one has none.
function rangesOf(holds: [number, number][], times: number[]): [number, number][] | null {
  // Half a frame either way: the recording's own times are not the page's to
  // the millisecond.
  const slack = 500 / FPS;
  const ranges: [number, number][] = [];
  for (const [from, to] of holds) {
    let range: [number, number] | null = null;
    for (const [index, time] of times.entries()) {
      if (time < from - slack || time > to + slack) continue;
      range = range ? [range[0], index] : [index, index];
    }
    if (!range) return null;
    ranges.push(range);
  }
  return ranges;
}

/// The size the camera's `width` × `height` frames are recorded at: the
/// camera's own shape, its longer side at most [`MAX_SIDE`], each side even.
function recordedSize(width: number, height: number) {
  const scale = Math.min(1, MAX_SIDE / Math.max(width, height));
  const even = (n: number) => Math.max(2, 2 * Math.round((n * scale) / 2));
  return { width: even(width), height: even(height) };
}

/// The bits a second a recording of `ms` milliseconds may take to fit in
/// `maxBytes`, with room for an encoder that overshoots.
function bitrateFor(maxBytes: number, ms: number): number {
  const bits = (maxBytes * 8 * 0.6) / Math.max(ms / 1000, 1);
  return Math.round(Math.min(MAX_BITRATE, Math.max(MIN_BITRATE, bits)));
}

/// What the applicant is first asked to do for a guide.
function leadText(guide: VideoGuide): string {
  switch (guide.kind) {
    case "static_guide":
      return guide.guide.kind === "rect"
        ? "Line it up with the frame"
        : "Line it up with the oval";
    case "face":
      return "Fit your face in the oval";
    case "head_turn":
      return turnText(guide.degrees);
  }
}

/// What the applicant is told about `guide`: by `hint`, where the page reads
/// their face, else by whether the guide is held.
function instructionFor(guide: VideoGuide, hint: Hint | null, holding: boolean): string {
  switch (hint) {
    case null:
      return holding ? "Hold still" : leadText(guide);
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
      return leadText(guide);
    case "further":
      return "A little further";
    case "hold":
      return "Hold still";
  }
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/// How far a hold that began at `heldAt`, on the page's clock, is through
/// `holdMs`, from 0 to 1, redrawn every display frame; `undefined` while
/// nothing is held.
function useHoldFill(heldAt: number | null, holdMs: number): number | undefined {
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

type Phase =
  | { kind: "initializing" }
  /// The camera is on and the first guide shown, the recording not started.
  | {
      kind: "ready";
      /// What the applicant is told, where the page reads their face.
      hint: Hint | null;
    }
  | {
      kind: "recording";
      /// The guide on screen.
      index: number;
      /// What the applicant is told about it, where the page reads their
      /// face.
      hint: Hint | null;
      /// When its hold began, on the page's clock; `null` while it is not
      /// held.
      heldAt: number | null;
      /// How far through the guides, from 0 to 1.
      progress: number;
    }
  /// Recorded, and handed to the parent to send.
  | { kind: "recorded" }
  /// This browser records no WebM of VP8 frames, or runs no face detector
  /// for a step that reads faces.
  | {
      kind: "unsupported";
      /// Why, where something said so; shown in a development build.
      reason: string | null;
    }
  | { kind: "error"; message: string };

/// How this browser records, and the canvas it records from at what bitrate.
type Setup = { kind: RecorderKind; canvas: HTMLCanvasElement; bitrate: number };

export function VideoCapture({
  promptLabel,
  step,
  stepNumber,
  totalSteps,
  maxBytes,
  onRecorded,
  sending,
  instead,
}: Props) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const plan = step.guides;
  const readsFaces = useMemo(() => plan.some(reads), [plan]);
  // The face detector, for a step that reads faces; the camera waits for it.
  const [detector, setDetector] = useState<Detector>();
  // The applicant's head, followed through the preview and the recording.
  const headRef = useRef(new Head());
  // Set once the camera says its size.
  const setupRef = useRef<Setup | null>(null);
  // The video recorded and where its guides were held, kept to send again.
  const recordedRef = useRef<{ video: Blob; guides: [number, number][] } | null>(
    null,
  );
  // Set while a recording runs. Cleared, the recording stops at its next
  // frame and is dropped.
  const runningRef = useRef(false);
  // Set when the page was hidden during the recording: a hidden page draws
  // no frames on time, so what was held is not on record.
  const hiddenRef = useRef(false);
  // Set when the applicant presses the shutter on the static guide on screen.
  const shutterRef = useRef(false);
  // Bumped on Try again to start the camera over.
  const [attempt, setAttempt] = useState(0);
  const [phase, setPhase] = useState<Phase>({ kind: "initializing" });
  // A camera facing the applicant is shown as a mirror; the video is recorded
  // as the camera sees it.
  const [mirrored, setMirrored] = useState(false);
  // The send ended with this step still on screen: it failed.
  const [sendFailed, setSendFailed] = useState(false);
  const wasSending = useRef(false);
  const frame = useFrameBox(videoRef);
  // The recording starts by itself where the page reads the first guide, and
  // on the shutter where it is a static one.
  const auto = detector !== undefined && reads(plan[0]);

  useEffect(() => {
    if (wasSending.current && !sending) setSendFailed(true);
    wasSending.current = sending;
  }, [sending]);

  useEffect(() => {
    if (!readsFaces) return;
    let cancelled = false;
    loadDetector().then(
      (loaded) => {
        if (!cancelled) setDetector(loaded);
      },
      (error: unknown) => {
        if (cancelled) return;
        console.warn("The face detector did not load:", error);
        setPhase({
          kind: "unsupported",
          reason: error instanceof Error ? error.message : String(error),
        });
      },
    );
    return () => {
      cancelled = true;
    };
  }, [readsFaces]);

  function stopCamera() {
    streamRef.current?.getTracks().forEach((t) => t.stop());
    streamRef.current = null;
  }

  useEffect(() => {
    // A step the page reads faces for cannot be taken without the detector.
    if (readsFaces && !detector) return;
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

        const { width, height } = recordedSize(video.videoWidth, video.videoHeight);
        const bitrate = bitrateFor(maxBytes, longest(plan));
        const kind = await recorderFor(width, height, bitrate);
        if (cancelled) return;
        if (!kind) {
          stopCamera();
          setPhase({ kind: "unsupported", reason: null });
          return;
        }
        const canvas = document.createElement("canvas");
        canvas.width = width;
        canvas.height = height;
        setupRef.current = { kind, canvas, bitrate };
        setPhase({ kind: "ready", hint: null });
      } catch (e) {
        if (cancelled) return;
        setPhase({ kind: "error", message: cameraError(e) });
      }
    })();

    return () => {
      cancelled = true;
      runningRef.current = false;
      stopCamera();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [attempt, step.camera, detector]);

  useEffect(() => {
    const onVisibility = () => {
      if (document.hidden && runningRef.current) hiddenRef.current = true;
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => document.removeEventListener("visibilitychange", onVisibility);
  }, []);

  // Before the recording: the applicant's face read against the first guide,
  // and the recording started once they have followed it for a moment.
  useEffect(() => {
    if (phase.kind !== "ready" || !auto || !detector) return;
    const entry = entryOf(plan[0]);
    const head = headRef.current;
    let stopped = false;
    let since: number | null = null;
    const look = async () => {
      const video = videoRef.current;
      if (stopped || !video) return;
      const { videoWidth: width, videoHeight: height } = video;
      if (width && height) {
        const faces = await detector.faces(video, width, height);
        if (stopped) return;
        const hint = hintFor(entry, faces, head, width, height, mirrored);
        setPhase({ kind: "ready", hint });
        if (hint !== "hold") {
          since = null;
        } else {
          since ??= performance.now();
          if (performance.now() - since >= GATE_MS) {
            head.settle();
            void record();
            return;
          }
        }
      }
      setTimeout(() => void look(), 1000 / FPS);
    };
    void look();
    return () => {
      stopped = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase.kind, auto, mirrored]);

  /// The applicant presses the shutter on the static guide on screen; the
  /// first one starts the recording.
  function capture() {
    shutterRef.current = true;
    if (phase.kind === "ready") void record();
  }

  /// Record the step: each guide shown in turn until the applicant has held
  /// it — a static one from the shutter — every frame drawn from the camera;
  /// then hand the video to the parent.
  async function record() {
    const setup = setupRef.current;
    const video = videoRef.current;
    const context = setup?.canvas.getContext("2d");
    if (phase.kind !== "ready" || runningRef.current || !setup || !video || !context) return;
    const fail = (message: string) => {
      runningRef.current = false;
      stopCamera();
      setPhase({ kind: "error", message });
    };

    haptic(15);
    runningRef.current = true;
    hiddenRef.current = false;
    let recording: Recording;
    try {
      recording = await startRecording(setup.kind, setup.canvas, setup.bitrate);
    } catch {
      fail("Could not record the video.");
      return;
    }

    const { width, height } = setup.canvas;
    const head = headRef.current;
    // Each guide's hold, from the first frame and to the last it lasted.
    const holds: [number, number][] = [];
    let index = 0;
    // When the guide on screen was shown, its hold began — `null` while it is
    // not held — and it was last followed.
    let shown = 0;
    let held: number | null = null;
    let followed = 0;
    // When a face was last seen, or a guide shown that reads none.
    let seen = 0;
    // When the first frame was drawn: the recording's own times count from it.
    let origin: number | null = null;
    const start = performance.now();
    let next = start;
    try {
      for (;;) {
        if (!runningRef.current) {
          recording.cancel();
          return;
        }
        if (hiddenRef.current) {
          recording.cancel();
          fail("The recording stopped when the page was hidden. Try again.");
          return;
        }
        const elapsed = performance.now() - start;
        origin ??= elapsed;
        const guide = plan[index];
        context.drawImage(video, 0, 0, width, height);
        let hint: Hint | null = null;
        let follows: boolean;
        if (detector && reads(guide)) {
          const faces = await detector.faces(setup.canvas, width, height);
          if (faces.length) seen = elapsed;
          hint = hintFor(guide, faces, head, width, height, mirrored);
          follows = hint === "hold";
        } else {
          seen = elapsed;
          follows = shutterRef.current;
        }
        const begins = follows && held === null;
        if (follows) {
          held ??= elapsed;
          followed = elapsed;
        } else if (held !== null && elapsed - followed > GRACE_MS) {
          held = null;
        }
        // The first frame a guide is held in is written whole, a picture of
        // its own as a photo is, for what reads the face in it.
        await recording.frame(begins);
        if (held !== null && elapsed - held >= guide.hold_ms) {
          holds.push([held - origin, elapsed - origin]);
          if (index === plan.length - 1) break;
          index += 1;
          shown = elapsed;
          held = null;
          seen = elapsed;
          shutterRef.current = false;
        } else if (held === null && reads(guide) && elapsed - shown > FOLLOW_MS) {
          recording.cancel();
          fail("The prompt was not followed in time. Try again.");
          return;
        } else if (elapsed - seen > LOST_MS) {
          recording.cancel();
          fail("Your face left the camera. Try again.");
          return;
        } else if (elapsed > MAX_MS) {
          recording.cancel();
          fail("The recording took too long. Try again.");
          return;
        }
        const current = plan[index];
        const share =
          held === null ? 0 : Math.min(1, (elapsed - held) / Math.max(1, current.hold_ms));
        setPhase({
          kind: "recording",
          index,
          hint,
          heldAt: held === null ? null : start + held,
          progress: (holds.length + share) / plan.length,
        });
        next += 1000 / FPS;
        const wait = next - performance.now();
        if (wait > 0) await sleep(wait);
        else next = performance.now();
      }
      const recorded = await recording.finish();
      runningRef.current = false;
      stopCamera();
      if (recorded.size > maxBytes) {
        fail("This video is too large to send. Try again.");
        return;
      }
      // Read back as the platform will read it: a recording the browser did
      // not write as it should is found here, where it can be made again. The
      // frames a guide was held in are the recording's own, by their times.
      const back = await readBack(recorded);
      const guides =
        back &&
        back.width === setup.canvas.width &&
        back.height === setup.canvas.height &&
        rangesOf(holds, back.times);
      if (!guides) {
        fail("The recording did not come out right. Try again.");
        return;
      }
      haptic(15);
      recordedRef.current = { video: recorded, guides };
      setSendFailed(false);
      setPhase({ kind: "recorded" });
      onRecorded(recorded, guides);
    } catch {
      recording.cancel();
      fail("Could not record the video.");
    }
  }

  function sendAgain() {
    const recorded = recordedRef.current;
    if (!recorded || sending) return;
    setSendFailed(false);
    onRecorded(recorded.video, recorded.guides);
  }

  function tryAgain() {
    runningRef.current = false;
    recordedRef.current = null;
    setupRef.current = null;
    headRef.current = new Head();
    shutterRef.current = false;
    setSendFailed(false);
    setPhase({ kind: "initializing" });
    setAttempt((a) => a + 1);
  }

  const showCamera = phase.kind === "ready" || phase.kind === "recording";
  const guide = phase.kind === "recording" ? plan[phase.index] : plan[0];
  const hint = phase.kind === "ready" || phase.kind === "recording" ? phase.hint : null;
  const heldAt = phase.kind === "recording" ? phase.heldAt : null;
  const holding = heldAt !== null;
  // A static guide is taken with the shutter, which fills while it is held.
  const shutter = showCamera && guide?.kind === "static_guide";
  const fill = useHoldFill(shutter ? heldAt : null, guide?.hold_ms ?? 0);
  const stepHint =
    totalSteps > 1 ? `Step ${stepNumber} of ${totalSteps}. ${step.label}` : step.label;
  const instruction = guide
    ? instructionFor(phase.kind === "ready" && auto ? entryOf(guide) : guide, hint, holding)
    : null;

  if (phase.kind === "unsupported") {
    return (
      <main
        className="flex min-h-dvh flex-col items-center justify-center gap-4 px-6 text-center"
        style={{
          paddingTop: "max(env(safe-area-inset-top), 1rem)",
          paddingBottom: "max(env(safe-area-inset-bottom), 1.5rem)",
        }}
      >
        <h1 className="text-xl font-semibold">This browser can't record the video</h1>
        <p className="text-sm text-muted-foreground">
          This step records a short video, which this browser cannot do. Continue
          on another device, or open this page in an up-to-date browser.
        </p>
        {import.meta.env.DEV && phase.reason && (
          <p className="wrap-break-word font-mono text-xs text-muted-foreground">{phase.reason}</p>
        )}
        {instead}
      </main>
    );
  }

  return (
    <main
      className="flex h-dvh flex-col bg-black text-white"
      style={{
        paddingTop: "max(env(safe-area-inset-top), 0px)",
        paddingBottom: "max(env(safe-area-inset-bottom), 0px)",
      }}
    >
      <div className="relative min-h-0 flex-1 overflow-hidden">
        {/* In the DOM before getUserMedia resolves, as MediaCapture's is. */}
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
        {showCamera && guide && (
          <>
            {/* A head turn is said by the instruction below, not drawn. */}
            {guide.kind === "static_guide" && <GuideOverlay guide={guide.guide} frame={frame} />}
            {guide.kind === "face" && (
              <GuideOverlay
                guide={{ kind: "oval", width: guide.width, height: guide.height }}
                frame={frame}
                met={hint === "hold"}
              />
            )}
            <div className="pointer-events-none absolute inset-x-6 top-6 space-y-2 text-center">
              <p className="text-xs uppercase tracking-wide text-white/70">
                {promptLabel}
              </p>
              <p className="rounded-md bg-black/60 px-3 py-2 text-sm">{stepHint}</p>
              {phase.kind === "recording" && (
                <div className="h-1 overflow-hidden rounded-full bg-white/20">
                  <div
                    className="h-full bg-white"
                    style={{ width: `${Math.min(100, phase.progress * 100)}%` }}
                  />
                </div>
              )}
            </div>
            {instruction && (
              <div className="pointer-events-none absolute inset-x-0 bottom-6 flex justify-center">
                <div
                  className={cn(
                    "rounded-full px-4 py-1.5 text-sm font-medium",
                    holding || hint === "hold" ? "bg-white text-black" : "bg-black/60",
                  )}
                >
                  {instruction}
                </div>
              </div>
            )}
          </>
        )}

        {phase.kind === "initializing" && (
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

        {phase.kind === "recorded" && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-4 px-6 text-center">
            {sendFailed ? (
              <p className="text-sm text-white/90">The video was not sent.</p>
            ) : (
              <p className="inline-flex items-center gap-2 text-sm text-white/90">
                <span
                  aria-hidden
                  className="size-3.5 animate-spin rounded-full border-2 border-white/30 border-t-white"
                />
                Sending the video…
              </p>
            )}
          </div>
        )}

        {phase.kind === "error" && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-4 px-6 text-center">
            <p className="text-sm text-white/90">{phase.message}</p>
            <Button onClick={tryAgain} className="bg-white text-black">
              Try again
            </Button>
          </div>
        )}
      </div>

      <div
        className={cn(
          "flex shrink-0 items-center justify-center gap-3 px-6 py-4",
          (phase.kind === "error" || phase.kind === "initializing") && "invisible",
        )}
      >
        {phase.kind === "recorded" ? (
          <>
            <Button
              variant="secondary"
              size="lg"
              className="h-12 flex-1 bg-white/10 text-white hover:bg-white/20"
              onClick={tryAgain}
              disabled={sending || !sendFailed}
            >
              Record again
            </Button>
            <Button
              size="lg"
              className="h-12 flex-1 bg-white text-black hover:bg-white/90"
              onClick={sendAgain}
              disabled={sending || !sendFailed}
            >
              Send again
            </Button>
          </>
        ) : shutter ? (
          <ShutterButton
            label={fill === undefined ? "Capture" : "Capturing — hold still"}
            onClick={capture}
            fill={fill}
          />
        ) : phase.kind === "recording" ? (
          <p className="inline-flex h-12 items-center gap-2 text-sm">
            <span aria-hidden className="size-2.5 animate-pulse rounded-full bg-red-500" />
            Recording
          </p>
        ) : (
          <p className="inline-flex h-12 items-center text-sm text-white/80">
            The recording starts when you follow the prompt
          </p>
        )}
      </div>
    </main>
  );
}
