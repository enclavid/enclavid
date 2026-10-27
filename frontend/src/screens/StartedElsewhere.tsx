import { MonitorSmartphone, QrCode } from "lucide-react";
import { StartOver } from "@/components/StartOver";

type Props = {
  /// Why this browser cannot go on: its key does not open the session
  /// (`elsewhere`), or the code it was opened from could not be taken (`code`).
  reason: "elsewhere" | "code";
  /// Hands the session back and starts it over in this browser.
  onStartOver: () => Promise<void>;
};

/// "This session is another browser's." Reached when the key this browser
/// holds does not open the session — `/connect` or an answer refused with 403:
/// it was started in another browser or on another device (an app's own
/// browser counts), or this browser's storage was cleared since. Or when this
/// page was opened from a code that could not be taken: it had expired, was
/// used already, or was made before the session changed hands.
///
/// Going back there keeps the progress, so the screen leads with that.
/// Starting over here comes second and behind a confirmation: it erases what
/// was done in the other browser, which can no longer continue.
export function StartedElsewhere({ reason, onStartOver }: Props) {
  const Icon = reason === "code" ? QrCode : MonitorSmartphone;
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
          <Icon className="size-7" aria-hidden />
        </div>
        {reason === "code" ? (
          <>
            <h1 className="text-xl font-semibold">This code can't be used</h1>
            <p className="text-sm leading-relaxed text-muted-foreground">
              It has expired or was used already. Show a new code on your
              computer and scan it again.
            </p>
            <p className="text-xs leading-relaxed text-muted-foreground">
              Didn't use it yourself? Someone else may have. Start over here to
              take the verification back.
            </p>
          </>
        ) : (
          <>
            <h1 className="text-xl font-semibold">Started in another browser</h1>
            <p className="text-sm leading-relaxed text-muted-foreground">
              This verification was started in another browser or on another
              device. Finish it there to keep your progress.
            </p>
            <p className="text-xs leading-relaxed text-muted-foreground">
              Started on a computer? There, “Continue on your phone” moves it to
              your phone.
            </p>
          </>
        )}
        <StartOver label="Start over here" onStartOver={onStartOver} />
      </div>
    </main>
  );
}
