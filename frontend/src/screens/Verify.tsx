import { useState } from "react";
import { ConsentScreen } from "@/components/ConsentScreen";
import { ContinueOnPhone } from "@/components/ContinueOnPhone";
import { MediaCapture } from "@/components/MediaCapture";
import { MediaInstructions } from "@/components/MediaInstructions";
import { Spinner } from "@/components/icons";
import { fitPhotos } from "@/lib/photos";
import { Completed } from "@/screens/Completed";
import type { RequestView, SessionProgress } from "@/types";

type Props = {
  /// The session on screen — what a capture step offers to continue on a
  /// phone.
  sessionId: string;
  progress: SessionProgress | null;
  error: string | null;
  /// Submit the applicant's input for the current Suspended request
  /// to api/v1/sessions/:id/input/:awaiting_seq/:slot_id as
  /// multipart/form-data. App owns the network call + key + state
  /// update; Verify just hands it the wait the screen was rendered for,
  /// the slot identifier and the assembled FormData (one step's capture for
  /// media, as `media-<step>`; an `accepted` text part for consent).
  onSubmit: (awaitingSeq: number, slotId: string, form: FormData) => Promise<void>;
  /// The session was taken over from a code a capture step showed: `refused`,
  /// the key this page asked with, opens it no more.
  onMoved: (refused: Uint8Array) => void;
};

export function Verify({
  sessionId,
  progress,
  error,
  onSubmit,
  onMoved,
}: Props) {
  if (!progress) {
    // /connect either hasn't returned yet OR returned an error. With
    // progress still null we have no request to render — show the
    // error if one came back, otherwise stay on the loading state.
    if (error) return <ConnectError message={error} />;
    return <Loading />;
  }
  if (progress.status === "completed") {
    // Fresh-submit path: we have the decision, hand it to
    // `<Completed>` so the applicant sees the appropriate
    // variant (approved / rejected / rejected_retryable / review).
    // The reload path (App.tsx terminal short-circuit) renders
    // `<Completed />` WITHOUT a decision — see Completed.tsx for
    // the neutral fallback.
    return <Completed decision={progress.decision} />;
  }
  return (
    <RequestRenderer
      sessionId={sessionId}
      awaitingSeq={progress.awaiting_seq}
      request={progress.request}
      error={error}
      onSubmit={onSubmit}
      onMoved={onMoved}
    />
  );
}

function Loading() {
  return (
    <main
      className="flex min-h-dvh flex-col items-center justify-center gap-4 px-6 text-center"
      style={{
        paddingTop: "max(env(safe-area-inset-top), 1rem)",
        paddingBottom: "max(env(safe-area-inset-bottom), 1.5rem)",
      }}
    >
      <Spinner className="size-7 text-muted-foreground" />
      <p className="text-sm text-muted-foreground">
        Loading verification session…
      </p>
    </main>
  );
}

function ConnectError({ message }: { message: string }) {
  return (
    <main
      className="flex min-h-dvh flex-col items-center justify-center gap-3 px-6 text-center"
      style={{
        paddingTop: "max(env(safe-area-inset-top), 1rem)",
        paddingBottom: "max(env(safe-area-inset-bottom), 1.5rem)",
      }}
    >
      <h1 className="text-xl font-semibold">Can't start verification</h1>
      <p className="text-sm text-muted-foreground">{message}</p>
      <p className="text-xs text-muted-foreground">
        Try reloading the page. If the problem persists, request a new
        link from the service that sent you here.
      </p>
    </main>
  );
}

function RequestRenderer({
  sessionId,
  awaitingSeq,
  request,
  error,
  onSubmit,
  onMoved,
}: {
  sessionId: string;
  /// The wait this screen was rendered for: every answer from it names
  /// it, whatever wait the session has moved on to since.
  awaitingSeq: number;
  request: RequestView;
  error: string | null;
  onSubmit: (awaitingSeq: number, slotId: string, form: FormData) => Promise<void>;
  onMoved: (refused: Uint8Array) => void;
}) {
  const [submitting, setSubmitting] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  // The step on screen: the first whose capture the server does not hold yet,
  // so a reload carries on from where the applicant was.
  const index = request.kind === "media" ? request.next_step : 0;
  // The step whose instruction screen the user has tapped "Start" on —
  // the wait and the step together. Compared with the step on screen
  // rather than reset when it changes, so the render that brings a new
  // step already shows its instructions: a reset after the fact would
  // leave one frame of the old step's capture screen, its "Use photo"
  // live, under the new step.
  const stepKey = `${awaitingSeq}/${index}`;
  const [startedFor, setStartedFor] = useState<string | null>(null);
  const startedCapture = startedFor === stepKey;

  if (request.kind === "media") {
    const total = request.captures.length;
    const step = request.captures[index];

    // Each step's photo is sent as it is kept, fitted under its share of what
    // the steps not sent yet may hold together. The last step's runs the
    // round; any other's leaves the session at the next step. A failed send
    // leaves the step on screen, its photo still there to send again or
    // retake.
    const keep = async (photo: Blob) => {
      setLocalError(null);
      setSubmitting(true);
      try {
        const share = Math.floor(request.max_upload_bytes / (total - index));
        const [fitted] = await fitPhotos([photo], share).catch(() => {
          throw new Error("This photo is too large to send.");
        });
        const form = new FormData();
        form.append("photo", fitted, `${index}.jpg`);
        await onSubmit(awaitingSeq, `media-${index}`, form);
      } catch (e) {
        setLocalError(
          e instanceof Error ? e.message : "Could not submit the photo.",
        );
      } finally {
        setSubmitting(false);
      }
    };

    if (!step) {
      // A spec of no steps — the runtime refuses to render one, but
      // better to surface than crash silently.
      return (
        <main className="flex min-h-dvh items-center justify-center px-6 text-sm text-destructive">
          Unexpected capture state. Please refresh.
        </main>
      );
    }

    if (step.kind === "video") {
      return <VideoUnavailable />;
    }

    // Per-step intro: shown before the camera turns on for EVERY
    // step. `startedCapture` holds only for the step it was tapped
    // on — each step gets its own intro screen, then its own camera,
    // then its own preview. Multi-step captures get "now flip to the
    // back" framing between shots instead of jumping directly
    // into a different camera view.
    if (!startedCapture) {
      return (
        <MediaInstructions
          artifactLabel={request.label}
          icon={step.icon}
          instructions={step.instructions}
          stepNumber={index + 1}
          totalSteps={total}
          onStart={() => setStartedFor(stepKey)}
          secondaryAction={
            <ContinueOnPhone sessionId={sessionId} onMoved={onMoved} />
          }
        />
      );
    }

    return (
      <>
        <MediaCapture
          // A step of its own: photo, preview and buttons start over, so
          // nothing taken for one step can be sent for the next.
          key={stepKey}
          promptLabel={request.label}
          step={step}
          stepNumber={index + 1}
          totalSteps={total}
          onCapture={(photo) => void keep(photo)}
          sending={submitting}
        />
        <StatusOverlay
          submitting={submitting}
          message={localError ?? error}
        />
      </>
    );
  }

  if (request.kind === "consent") {
    const submit = async (accepted: boolean) => {
      setLocalError(null);
      setSubmitting(true);
      try {
        const form = new FormData();
        form.append("accepted", accepted ? "true" : "false");
        // Echo the digest of the exact disclosure screen shown, so the TEE
        // seals only what the applicant audited (show == seal). If the flow
        // advanced since this screen rendered, the TEE rejects the accept.
        form.append("disclosure_hash", request.disclosure_digest);
        await onSubmit(awaitingSeq, "consent", form);
      } catch (e) {
        setLocalError(
          e instanceof Error ? e.message : "Could not submit consent.",
        );
      } finally {
        setSubmitting(false);
      }
    };
    return (
      <>
        <ConsentScreen
          fields={request.fields}
          reasonText={request.reason}
          requesterName={request.requester}
          sending={submitting}
          onAllow={() => void submit(true)}
          onDeny={() => void submit(false)}
        />
        <StatusOverlay
          submitting={submitting}
          message={localError ?? error}
        />
      </>
    );
  }

  // verification_set still renders as JSON — own UI in a subsequent
  // iteration once the tree-walk state machine settles.
  return (
    <main
      className="flex min-h-dvh flex-col gap-4 px-6 py-6"
      style={{
        paddingTop: "max(env(safe-area-inset-top), 1rem)",
        paddingBottom: "max(env(safe-area-inset-bottom), 1.5rem)",
      }}
    >
      <h1 className="text-xl font-semibold">Verification</h1>
      {error && (
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {error}
        </div>
      )}
      <p className="text-sm text-muted-foreground">
        UI for this step is under construction. Latest request:
      </p>
      <pre className="overflow-auto rounded-lg border border-border bg-muted p-3 text-xs">
        {JSON.stringify(request, null, 2)}
      </pre>
    </main>
  );
}

/// A step that records a video, which this page does not yet record.
function VideoUnavailable() {
  return (
    <main
      className="flex min-h-dvh flex-col items-center justify-center gap-3 px-6 text-center"
      style={{
        paddingTop: "max(env(safe-area-inset-top), 1rem)",
        paddingBottom: "max(env(safe-area-inset-bottom), 1.5rem)",
      }}
    >
      <h1 className="text-xl font-semibold">Video is not available yet</h1>
      <p className="text-sm text-muted-foreground">
        This step records a video, which this page cannot do yet.
      </p>
    </main>
  );
}

/// Floating panel pinned above the safe area. Two modes:
///   - submitting → spinner + "Sending…" (no progress metering;
///     the network call is short enough that movement-of-the-icon
///     beats a fake percentage)
///   - error → message text
/// Nothing rendered when idle and no error.
function StatusOverlay({
  submitting,
  message,
}: {
  submitting: boolean;
  message: string | null;
}) {
  if (!submitting && !message) return null;
  return (
    <div className="pointer-events-none fixed inset-x-0 bottom-24 z-50 flex justify-center px-6">
      <div className="rounded-md bg-black/80 px-4 py-2 text-sm text-white">
        {submitting ? (
          <span className="inline-flex items-center gap-2">
            <span
              aria-hidden
              className="size-3.5 animate-spin rounded-full border-2 border-white/30 border-t-white"
            />
            Sending…
          </span>
        ) : (
          message
        )}
      </div>
    </div>
  );
}
