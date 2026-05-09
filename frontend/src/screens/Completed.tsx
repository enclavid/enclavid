/// Reached when `/status` reports `completed` — the policy ran to a
/// final decision and the platform consumer has been (or will be)
/// notified. Nothing to do from the applicant's side; we just confirm
/// and let them close the page.

export function Completed() {
  return (
    <main
      className="flex min-h-dvh flex-col items-center justify-center px-6 text-center"
      style={{
        paddingTop: "max(env(safe-area-inset-top), 1rem)",
        paddingBottom: "max(env(safe-area-inset-bottom), 1.5rem)",
      }}
    >
      <div className="flex max-w-sm flex-col items-center gap-4">
        <div className="flex size-14 items-center justify-center rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
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
            <path d="m5 12 5 5 9-11" />
          </svg>
        </div>
        <h1 className="text-xl font-semibold">Verification complete</h1>
        <p className="text-sm leading-relaxed text-muted-foreground">
          You can close this page. The requesting service has been notified
          of the outcome.
        </p>
      </div>
    </main>
  );
}
