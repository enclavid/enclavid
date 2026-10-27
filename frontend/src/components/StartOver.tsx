import { useState } from "react";
import { RotateCcw } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogMedia,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";

type Props = {
  /// What the button says.
  label: string;
  /// Hands the session back and starts it over in this browser. Rejects when
  /// that could not be done; the button says so and stays.
  onStartOver: () => Promise<void>;
};

/// Starting the session over in this browser, behind a confirmation: it erases
/// what was done so far, wherever it was done, and whoever holds the session
/// now can no longer continue it.
export function StartOver({ label, onStartOver }: Props) {
  const [confirming, setConfirming] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [failed, setFailed] = useState(false);

  async function startOver() {
    setResetting(true);
    setFailed(false);
    try {
      // On success the page moves on and this button goes with it.
      await onStartOver();
    } catch {
      setResetting(false);
      setConfirming(false);
      setFailed(true);
    }
  }

  return (
    <>
      <Button
        variant="outline"
        size="lg"
        className="mt-2 h-12 w-full text-base"
        onClick={() => setConfirming(true)}
      >
        {label}
      </Button>
      {failed && (
        <p className="text-sm text-destructive">
          Couldn't start over. Try again in a moment.
        </p>
      )}

      <AlertDialog
        open={confirming}
        onOpenChange={(open) => {
          // Not dismissed while the reset is out: it may already have landed.
          if (!open && resetting) return;
          setConfirming(open);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogMedia>
              <RotateCcw className="text-amber-600 dark:text-amber-400" />
            </AlertDialogMedia>
            <AlertDialogTitle>Start over here?</AlertDialogTitle>
            <AlertDialogDescription>
              Everything done so far will be erased, and the verification
              restarts in this browser. Wherever it is open now, it can't be
              continued.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel variant="default" disabled={resetting} autoFocus>
              Keep it
            </AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              onClick={() => void startOver()}
              disabled={resetting}
            >
              {resetting ? (
                <span className="inline-flex items-center gap-2">
                  <span
                    aria-hidden
                    className="size-3.5 animate-spin rounded-full border-2 border-current/30 border-t-current"
                  />
                  Starting over…
                </span>
              ) : (
                "Start over"
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
