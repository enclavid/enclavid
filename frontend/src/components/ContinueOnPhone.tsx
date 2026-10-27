import { useEffect, useRef, useState } from "react";
import { Dialog } from "@base-ui/react/dialog";
import { QRCodeSVG } from "qrcode.react";
import { Smartphone } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ApiError, createHandoff, heldBy } from "@/lib/api";
import { handoffLink, takeOverHere } from "@/lib/handoff";
import { loadKey } from "@/lib/key";
import { cn } from "@/lib/utils";

type Props = {
  sessionId: string;
  /// The session was taken over from a code this page showed: `refused`, the
  /// key this page asked with, opens it no more.
  onMoved: (refused: Uint8Array) => void;
};

/// "Continue on your phone": a QR code that hands the session over to a phone's
/// camera — for an applicant on a computer, who would rather take the photos
/// with the phone. Offered only where the pointer is a mouse; a phone already
/// has the camera.
///
/// The code is a hand-over api made for this page's key (see `lib/handoff.ts`):
/// the phone that scans it takes the session over with a key of its own. While
/// the code is up, the page asks every few seconds whether its key still holds
/// the session, without claiming it. When the code is put away untaken, the
/// page takes its own session over with a fresh key, and every code it showed
/// dies with that; until that take lands, no other code is made.
export function ContinueOnPhone({ sessionId, onMoved }: Props) {
  const [handoff, setHandoff] = useState<string | null>(null);
  const [making, setMaking] = useState(false);
  const [puttingAway, setPuttingAway] = useState(false);
  const [failed, setFailed] = useState<"later" | "never" | null>(null);
  // The code on screen, for putting it away when this goes — the dialog
  // closed, or the page moved on with it still up.
  const shownRef = useRef<string | null>(null);
  const movedRef = useRef(false);

  function moved(refused: Uint8Array) {
    movedRef.current = true;
    shownRef.current = null;
    setHandoff(null);
    onMoved(refused);
  }

  // A code put away untaken: a take of its own here ends every code shown
  // against this page's lock. One the take does not settle is asked after with
  // the key this page holds.
  async function putAway(shown: string) {
    shownRef.current = null;
    setPuttingAway(true);
    try {
      const take = await takeOverHere(sessionId, shown);
      if (take.kind === "taken") return;
      const key = loadKey(sessionId);
      if (key && (await heldBy(sessionId, key)) === "lost") moved(key);
    } catch {
      // Not known; the next request this page makes will say.
    } finally {
      setPuttingAway(false);
    }
  }

  // While the code is up: has a phone taken the session? The key is read
  // afresh each time, and an answer that comes after the code was put away
  // is not acted on.
  useEffect(() => {
    if (!handoff) return;
    const timer = window.setInterval(() => {
      const key = loadKey(sessionId);
      if (!key) return;
      void heldBy(sessionId, key)
        .then((held) => {
          if (held === "lost" && shownRef.current === handoff) moved(key);
        })
        .catch(() => {
          // A missed look says nothing; the next one asks again.
        });
    }, 2000);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [handoff, sessionId]);

  // Gone with a code still up — the page moved on some other way.
  useEffect(
    () => () => {
      if (shownRef.current && !movedRef.current) void putAway(shownRef.current);
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );

  if (!window.matchMedia("(pointer: fine)").matches) return null;

  async function show() {
    const key = loadKey(sessionId);
    if (!key) return;
    setMaking(true);
    setFailed(null);
    try {
      const made = await createHandoff(sessionId, key);
      shownRef.current = made;
      setHandoff(made);
    } catch (e) {
      // 410: the session's lock holds all the keys it can, and it is handed
      // over no more.
      setFailed(e instanceof ApiError && e.status === 410 ? "never" : "later");
    } finally {
      setMaking(false);
    }
  }

  return (
    <>
      <Button
        variant="ghost"
        size="lg"
        className="w-full text-muted-foreground"
        onClick={() => void show()}
        disabled={making || puttingAway || failed === "never"}
      >
        <Smartphone />
        Continue on your phone
      </Button>
      {failed && (
        <p className="mt-2 text-center text-xs text-muted-foreground">
          {failed === "never"
            ? "This verification can't move to another device any more."
            : "Couldn't make a code. Try again in a moment."}
        </p>
      )}
      <Dialog.Root
        open={handoff !== null}
        onOpenChange={(open) => {
          if (open || !handoff) return;
          setHandoff(null);
          if (!movedRef.current) void putAway(handoff);
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
            {handoff && (
              <QRCodeSVG
                value={handoffLink(handoff)}
                size={224}
                marginSize={2}
                className="rounded-lg bg-white"
                title="Your session, for your phone"
              />
            )}
            <p className="text-xs leading-relaxed text-muted-foreground">
              Whoever scans this code takes the verification over from this
              page, so show it only to your own phone. The code works once, for
              a few minutes.
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
