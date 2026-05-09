type Props = {
  /// Optional human-readable reason. Used both for terminal session
  /// states (`failed`/`expired`) and for transport failures on the
  /// initial `/status` fetch — same screen shape, different copy.
  reason?: string;
};

/// Catch-all "you can't continue from here" screen. Reached when:
///   * `/status` returns `failed` / `expired` / `unspecified`
///   * `/status` itself can't be reached (server down, network issue)
///
/// Both cases share the same UX shape: a clear message that progress
/// can't continue, and a hint at the recovery path (request a new
/// session from the integrating service / reload).
export function Terminated({ reason }: Props) {
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
            <circle cx="12" cy="12" r="9" />
            <path d="M12 8v4" />
            <path d="M12 16h.01" />
          </svg>
        </div>
        <h1 className="text-xl font-semibold">Session ended</h1>
        <p className="text-sm leading-relaxed text-muted-foreground">
          {reason ??
            "This verification session has ended. Request a new one from the service that linked you here."}
        </p>
      </div>
    </main>
  );
}
