import { useState } from "react";
import { Dialog } from "@base-ui/react/dialog";
import { QRCodeSVG } from "qrcode.react";
import { Smartphone } from "lucide-react";
import { Button } from "@/components/ui/button";
import { handoffLink } from "@/lib/handoff";
import { cn } from "@/lib/utils";

/// "Continue on your phone": a QR code that carries the session, with its key,
/// to a phone's camera — for an applicant on a computer, who would rather take
/// the photos with the phone. Offered only where the pointer is a mouse; a
/// phone already has the camera.
///
/// The code is made when asked for and dropped when the dialog closes: it is
/// the whole session to whoever sees it (see `lib/handoff.ts`).
export function ContinueOnPhone({ sessionId }: { sessionId: string }) {
  const [link, setLink] = useState<string | null>(null);
  if (!window.matchMedia("(pointer: fine)").matches) return null;

  return (
    <>
      <Button
        variant="ghost"
        size="lg"
        className="w-full text-muted-foreground"
        onClick={() => setLink(handoffLink(sessionId))}
      >
        <Smartphone />
        Continue on your phone
      </Button>
      <Dialog.Root
        open={link !== null}
        onOpenChange={(open) => {
          if (!open) setLink(null);
        }}
      >
        <Dialog.Portal>
          <Dialog.Backdrop className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm transition-opacity duration-200 data-ending-style:opacity-0 data-starting-style:opacity-0" />
          <Dialog.Popup
            className={cn(
              "fixed left-1/2 top-1/2 z-50 flex w-[min(92vw,24rem)] -translate-x-1/2 -translate-y-1/2 flex-col items-center gap-4 rounded-2xl border border-border bg-background p-6 text-center shadow-xl outline-none",
              "transition-all duration-200 data-ending-style:scale-95 data-ending-style:opacity-0 data-starting-style:scale-95 data-starting-style:opacity-0",
            )}
          >
            <Dialog.Title className="text-lg font-semibold">
              Continue on your phone
            </Dialog.Title>
            <Dialog.Description className="text-sm text-muted-foreground">
              Scan this code with your phone's camera to pick up right where
              you are.
            </Dialog.Description>
            {link && (
              <QRCodeSVG
                value={link}
                size={224}
                marginSize={2}
                className="rounded-lg bg-white"
                title="Your session, for your phone"
              />
            )}
            <p className="text-xs leading-relaxed text-muted-foreground">
              The code carries your session's key: show it only to your own
              phone. Once your phone shows the next step, you can close this
              tab.
            </p>
            <Dialog.Close
              render={<Button variant="outline" className="w-full" />}
            >
              Done
            </Dialog.Close>
          </Dialog.Popup>
        </Dialog.Portal>
      </Dialog.Root>
    </>
  );
}
