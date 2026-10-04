import { Button } from "@/components/ui/button";

/// The service did not answer — not the session ending. Reached when
/// `/status` fails for any reason other than an unknown session (404):
/// a 5xx, a dropped connection, no network. Nothing about the session
/// is lost: reconnecting resumes it at the step it was on, so the one
/// action offered is to try again.
export function Unavailable() {
  return (
    <main
      className="flex min-h-dvh flex-col items-center justify-center px-6 text-center"
      style={{
        paddingTop: "max(env(safe-area-inset-top), 1rem)",
        paddingBottom: "max(env(safe-area-inset-bottom), 1.5rem)",
      }}
    >
      <div className="flex max-w-sm flex-col items-center gap-4">
        <div className="flex size-14 items-center justify-center rounded-full bg-muted text-muted-foreground">
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
            className="size-7"
            aria-hidden
          >
            <path d="M21 12a9 9 0 1 1-3-6.7" />
            <path d="M21 4v5h-5" />
          </svg>
        </div>
        <h1 className="text-xl font-semibold">Service unavailable</h1>
        <p className="text-sm leading-relaxed text-muted-foreground">
          We couldn't reach the verification service. Your progress is saved —
          try again in a moment.
        </p>
        <Button
          size="lg"
          className="h-12 w-full text-base"
          onClick={() => window.location.reload()}
        >
          Try again
        </Button>
      </div>
    </main>
  );
}
