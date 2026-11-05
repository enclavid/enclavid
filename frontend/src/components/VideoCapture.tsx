import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  GuideOverlay,
  cameraConstraints,
  cameraError,
  facesApplicant,
  haptic,
  turnText,
  useFrameBox,
} from "@/components/camera";
import { Button } from "@/components/ui/button";
import {
  FPS,
  type RecorderKind,
  type Recording,
  readBack,
  recorderFor,
  startRecording,
} from "@/lib/recorder";
import { cn } from "@/lib/utils";
import type { Guide, VideoStep } from "@/types";

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

/// How long the applicant is given to follow a guide before it counts as held.
const LEAD_MS = 1500;
/// The longer side of the recorded frames at most, in pixels.
const MAX_SIDE = 1280;
/// The bits a second the recording is held between.
const MIN_BITRATE = 250_000;
const MAX_BITRATE = 1_500_000;

/// When one guide is shown, in milliseconds from the recording's start.
type Segment = {
  guide: Guide;
  /// When it is shown.
  start: number;
  /// When it counts as held: the applicant has had the lead to follow it.
  held: number;
  /// When the next guide is shown: its hold after `held`.
  end: number;
};

/// The guides one after another, each with its lead and its own hold.
function segments(guides: Guide[]): Segment[] {
  let at = 0;
  return guides.map((guide) => {
    const segment = {
      guide,
      start: at,
      held: at + LEAD_MS,
      end: at + LEAD_MS + guide.hold_ms,
    };
    at = segment.end;
    return segment;
  });
}

/// Whether a frame `elapsed` milliseconds in is one `segment`'s guide is held
/// in, given whether the guide has a frame held already: every frame during
/// its hold, or — where none was, as for a hold of 0 — the first after it
/// began.
function heldIn(segment: Segment, elapsed: number, hasFrame: boolean): boolean {
  return elapsed >= segment.held && (elapsed < segment.end || !hasFrame);
}

/// For each guide, in order, the first and the last of the video's frames —
/// at `times`, milliseconds from the first — it was held in; `null` where the
/// video ends before one was.
function rangesOf(plan: Segment[], times: number[]): [number, number][] | null {
  const ranges: [number, number][] = [];
  for (const segment of plan) {
    let range: [number, number] | null = null;
    for (const [index, time] of times.entries()) {
      if (!heldIn(segment, time, range !== null)) continue;
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

/// What the applicant is asked to do in a guide's lead.
function leadText(guide: Guide): string {
  switch (guide.kind) {
    case "rect":
      return "Fit the document in the frame";
    case "oval":
      return "Fit your face in the oval";
    case "turn":
      return turnText(guide.degrees);
  }
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

type Phase =
  | { kind: "initializing" }
  /// The camera is on, the first guide shown, the recording not started.
  | { kind: "ready" }
  | {
      kind: "recording";
      /// The guide on screen.
      segment: number;
      /// Whether it counts as held.
      held: boolean;
      /// Milliseconds from the recording's start.
      elapsed: number;
    }
  /// Recorded, and handed to the parent to send.
  | { kind: "recorded" }
  /// This browser records no WebM of VP8 frames.
  | { kind: "unsupported" }
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
  const plan = useMemo(() => segments(step.guides), [step.guides]);
  const total = plan.length ? plan[plan.length - 1].end : 0;
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

  useEffect(() => {
    if (wasSending.current && !sending) setSendFailed(true);
    wasSending.current = sending;
  }, [sending]);

  function stopCamera() {
    streamRef.current?.getTracks().forEach((t) => t.stop());
    streamRef.current = null;
  }

  useEffect(() => {
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
        const bitrate = bitrateFor(maxBytes, total);
        const kind = await recorderFor(width, height, bitrate);
        if (cancelled) return;
        if (!kind) {
          stopCamera();
          setPhase({ kind: "unsupported" });
          return;
        }
        const canvas = document.createElement("canvas");
        canvas.width = width;
        canvas.height = height;
        setupRef.current = { kind, canvas, bitrate };
        setPhase({ kind: "ready" });
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
  }, [attempt, step.camera]);

  useEffect(() => {
    const onVisibility = () => {
      if (document.hidden && runningRef.current) hiddenRef.current = true;
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => document.removeEventListener("visibilitychange", onVisibility);
  }, []);

  /// Record the step: each guide shown in turn, by the clock, every frame
  /// drawn from the camera; then hand the video to the parent.
  async function record() {
    const setup = setupRef.current;
    const video = videoRef.current;
    const context = setup?.canvas.getContext("2d");
    if (phase.kind !== "ready" || !setup || !video || !context) return;
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

    // Which guides a frame was held in already.
    const opened: boolean[] = plan.map(() => false);
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
        // Each guide in this frame or not, by its hold.
        const holding = plan.map((s, i) => heldIn(s, elapsed, opened[i]));
        // Past the last guide's hold, with every guide held in a frame.
        if (elapsed >= total && !holding.includes(true)) break;
        // On screen: the guide whose hold has not ended, or the last.
        const ahead = plan.findIndex((s) => elapsed < s.end);
        const at = ahead === -1 ? plan.length - 1 : ahead;
        context.drawImage(video, 0, 0, setup.canvas.width, setup.canvas.height);
        // The first frame a guide is held in is written whole, a picture of
        // its own as a photo is, for what reads the face in it.
        await recording.frame(holding.some((h, i) => h && !opened[i]));
        holding.forEach((h, i) => {
          if (h) opened[i] = true;
        });
        setPhase({ kind: "recording", segment: at, held: holding[at], elapsed });
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
        rangesOf(plan, back.times);
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
    setSendFailed(false);
    setPhase({ kind: "initializing" });
    setAttempt((a) => a + 1);
  }

  const showCamera = phase.kind === "ready" || phase.kind === "recording";
  const segment = phase.kind === "recording" ? plan[phase.segment] : plan[0];
  const stepHint =
    totalSteps > 1 ? `Step ${stepNumber} of ${totalSteps}. ${step.label}` : step.label;
  const instruction =
    phase.kind === "recording"
      ? phase.held
        ? "Hold still"
        : leadText(segment.guide)
      : segment
        ? leadText(segment.guide)
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
        {showCamera && segment && (
          <>
            {/* A turn is said by the instruction below, not drawn. */}
            {segment.guide.kind !== "turn" && (
              <GuideOverlay guide={segment.guide} frame={frame} />
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
                    style={{ width: `${Math.min(100, (phase.elapsed / total) * 100)}%` }}
                  />
                </div>
              )}
            </div>
            {instruction && (
              <div className="pointer-events-none absolute inset-x-0 bottom-6 flex justify-center">
                <div
                  className={cn(
                    "rounded-full px-4 py-1.5 text-sm font-medium",
                    phase.kind === "recording" && phase.held
                      ? "bg-white text-black"
                      : "bg-black/60",
                  )}
                >
                  {instruction}
                </div>
              </div>
            )}
          </>
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
        ) : phase.kind === "recording" ? (
          <p className="inline-flex h-12 items-center gap-2 text-sm">
            <span aria-hidden className="size-2.5 animate-pulse rounded-full bg-red-500" />
            Recording
          </p>
        ) : (
          <Button
            size="lg"
            className="h-12 flex-1 bg-white text-black hover:bg-white/90"
            onClick={() => void record()}
            disabled={phase.kind !== "ready"}
          >
            Start recording
          </Button>
        )}
      </div>
    </main>
  );
}
