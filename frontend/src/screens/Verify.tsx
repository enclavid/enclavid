import { useEffect, useState } from "react";
import { ConsentScreen } from "@/components/ConsentScreen";
import { MediaCapture } from "@/components/MediaCapture";
import { MediaInstructions } from "@/components/MediaInstructions";
import { Spinner } from "@/components/icons";
import { Completed } from "@/screens/Completed";
import { pickLocalized } from "@/lib/i18n";
import type { RequestView, SessionProgress } from "@/types";

type Props = {
  progress: SessionProgress | null;
  error: string | null;
  /// Submit the applicant's input for the current Suspended request
  /// to /session/:id/input/:slot_id as multipart/form-data. App owns
  /// the network call + key + state update; Verify just hands it the
  /// slot identifier and the assembled FormData (frames as parts for
  /// media captures, an `accepted` text part for consent).
  onSubmit: (slotId: string, form: FormData) => Promise<void>;
};

export function Verify({ progress, error, onSubmit }: Props) {
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
      request={progress.request}
      error={error}
      onSubmit={onSubmit}
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
  request,
  error,
  onSubmit,
}: {
  request: RequestView;
  error: string | null;
  onSubmit: (slotId: string, form: FormData) => Promise<void>;
}) {
  const [submitting, setSubmitting] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  // Whether the user has tapped "Start" on the instruction screen
  // for the CURRENT media prompt. Resets when next_slot_id changes
  // (new prompt or new step within the same prompt) so a fresh
  // prompt always shows instructions on entry.
  const slotKey = request.kind === "media" ? request.next_slot_id : null;
  const [startedCapture, setStartedCapture] = useState(false);
  useEffect(() => {
    setStartedCapture(false);
  }, [slotKey]);

  if (request.kind === "media") {
    // `next_slot_id` is the URL the host wants the next clip POSTed
    // to. We derive the step it refers to from `media-<N>` and read
    // that entry from `captures` to drive the on-screen guide.
    const nextIndex = parseStepIndex(request.next_slot_id);
    const total = request.captures.length;
    const step =
      nextIndex !== null && nextIndex < total
        ? request.captures[nextIndex]
        : null;

    const handle = async (form: FormData) => {
      setLocalError(null);
      setSubmitting(true);
      try {
        await onSubmit(request.next_slot_id, form);
      } catch (e) {
        setLocalError(
          e instanceof Error ? e.message : "Could not submit the photo.",
        );
      } finally {
        setSubmitting(false);
      }
    };

    if (!step) {
      // Backend handed us a slot we can't render — shouldn't happen
      // under a well-formed RequestView, but better to surface than
      // crash silently.
      return (
        <main className="flex min-h-dvh items-center justify-center px-6 text-sm text-destructive">
          Unexpected capture state. Please refresh.
        </main>
      );
    }

    // Per-step intro: shown before the camera turns on for EVERY
    // step. `startedCapture` is local-only and resets when
    // `next_slot_id` changes (new step or new prompt) — so each
    // step gets its own intro screen, then its own camera, then
    // its own preview. Multi-step captures get "now flip to the
    // back" framing between shots instead of jumping directly
    // into a different camera view.
    if (!startedCapture) {
      return (
        <MediaInstructions
          artifactLabel={request.label}
          icon={step.icon}
          instructions={step.instructions}
          stepNumber={(nextIndex ?? 0) + 1}
          totalSteps={total}
          onStart={() => setStartedCapture(true)}
        />
      );
    }

    return (
      <>
        <MediaCapture
          promptLabel={request.label}
          step={step}
          stepNumber={(nextIndex ?? 0) + 1}
          totalSteps={total}
          onCapture={handle}
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
        await onSubmit("consent", form);
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
          reasonText={pickLocalized(request.reason)}
          requesterName={pickLocalized(request.requester)}
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

/// Parse `media-<N>` slot ids back to their integer index. Returns
/// `null` for malformed values (caller surfaces "unexpected state").
function parseStepIndex(slotId: string): number | null {
  const m = slotId.match(/^media-(\d+)$/);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  return Number.isFinite(n) ? n : null;
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
