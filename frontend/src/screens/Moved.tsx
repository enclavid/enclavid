import { useEffect } from "react";
import { Smartphone } from "lucide-react";
import { StartOver } from "@/components/StartOver";
import { getStatus } from "@/lib/api";

type Props = {
  sessionId: string;
  /// The session finished on the phone.
  onCompleted: () => void;
  /// Hands the session back and starts it over in this browser — for an
  /// applicant whose phone never took it: then someone else did.
  onStartOver: () => Promise<void>;
};

/// "The session went on on your phone." Reached when this page showed a code
/// that hands the session over, and the key it holds the session by stopped
/// opening it: a phone took the code. The page watches the session's public
/// status and says when it is done. Whoever took the code cannot be told apart
/// from the applicant's own phone here, so an applicant who did not scan it is
/// offered the way back.
export function Moved({ sessionId, onCompleted, onStartOver }: Props) {
  useEffect(() => {
    const timer = window.setInterval(() => {
      void getStatus(sessionId)
        .then(({ status }) => {
          if (status === "completed") onCompleted();
        })
        .catch(() => {
          // A missed look says nothing; the next one asks again.
        });
    }, 4000);
    return () => window.clearInterval(timer);
  }, [sessionId, onCompleted]);

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
          <Smartphone className="size-7" aria-hidden />
        </div>
        <h1 className="text-xl font-semibold">Continuing on your phone</h1>
        <p className="text-sm leading-relaxed text-muted-foreground">
          Your verification moved to your phone. Finish it there — this page
          shows when it's done, or you can close it.
        </p>
        <p className="text-xs leading-relaxed text-muted-foreground">
          Didn't scan the code with your phone? Then someone else did. Start
          over here to take the verification back.
        </p>
        <StartOver label="Start over here" onStartOver={onStartOver} />
      </div>
    </main>
  );
}
