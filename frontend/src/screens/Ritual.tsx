import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { AppFooter } from "@/components/AppFooter";
import { DrawingCanvas } from "@/components/DrawingCanvas";
import { EntropyMeter } from "@/components/EntropyMeter";
import { KeyFingerprint } from "@/components/KeyFingerprint";
import { EntropyAccumulator, storeKey } from "@/lib/key";
import { cn } from "@/lib/utils";
import type { AttestationResult } from "@/lib/attestation";

type Props = {
  sessionId: string;
  attestation: AttestationResult | null;
  /// Fired once the entropy ritual finished and the applicant key
  /// has been finalized + stashed in localStorage. App handles the
  /// `/connect` call on the next state transition — no key needs to
  /// flow through this callback.
  onReady: () => void;
};

export function Ritual({ sessionId, attestation, onReady }: Props) {
  const accumulatorRef = useRef(new EntropyAccumulator());
  const [progress, setProgress] = useState(0);
  const [finalKey, setFinalKey] = useState<Uint8Array | null>(null);
  const [revealed, setRevealed] = useState(false);

  const onPoint = useCallback((x: number, y: number, t: number) => {
    if (finalKey) return;
    accumulatorRef.current.push(x, y, t);
    setProgress(accumulatorRef.current.progress());
  }, [finalKey]);

  // Finalize as soon as the entropy threshold is reached so the
  // fingerprint can play its reveal animation. We deliberately don't
  // call storeKey here — that's deferred to onContinue. Otherwise a
  // reload mid-animation would put a key in localStorage that the
  // user never explicitly committed, and App would auto-/connect.
  useEffect(() => {
    if (finalKey || progress < 1) return;
    let cancelled = false;
    void (async () => {
      const key = await accumulatorRef.current.finalize();
      if (cancelled) return;
      setFinalKey(key);
    })();
    return () => {
      cancelled = true;
    };
  }, [progress, finalKey]);

  const onRevealed = useCallback(() => setRevealed(true), []);

  // Continue waits for the full reveal animation to play. Without
  // this gate, the button would unlock at 100% draw progress and
  // the user might tap through before seeing the fingerprint.
  const continueDisabled = !revealed || !finalKey || !attestation?.ok;
  const ritualComplete = progress >= 1;

  const onContinue = () => {
    if (continueDisabled || !finalKey) return;
    storeKey(sessionId, finalKey);
    onReady();
  };

  return (
    <main
      className="flex h-dvh flex-col gap-4 overflow-hidden px-6"
      style={{
        paddingTop: "max(env(safe-area-inset-top), 1rem)",
        paddingBottom: "max(env(safe-area-inset-bottom), 1rem)",
      }}
    >
      <header className="flex flex-col gap-3 pt-2">
        <div className="flex flex-col gap-1.5">
          <h1 className="text-lg font-semibold leading-tight">
            Generating your private key
          </h1>
          <p className="text-sm leading-relaxed text-muted-foreground">
            Draw on the canvas below. Your strokes seed a key stored
            on this device; inside the enclave it lives only in
            hardware-encrypted memory we cannot read.
          </p>
        </div>
        <EntropyMeter progress={progress} />
      </header>

      <div className="relative min-h-0 flex-1">
        <DrawingCanvas
          className={cn(
            "absolute inset-0 overflow-hidden rounded-2xl border border-border bg-card transition-[filter,opacity] duration-500",
            ritualComplete && "opacity-70 blur-md",
          )}
          onPoint={onPoint}
          hint="Draw with your finger to seed your key"
        />
        {ritualComplete && (
          <div
            className="absolute inset-0 flex items-center justify-center px-4"
            style={{ touchAction: "none" }}
          >
            <KeyFingerprint
              bytes={finalKey ? finalKey.slice(0, 8) : null}
              onRevealed={onRevealed}
              className="rounded-2xl border border-border/60 bg-background/80 px-6 py-4 shadow-lg backdrop-blur-md animate-in fade-in zoom-in-95 duration-300 fill-mode-both"
            />
          </div>
        )}
      </div>

      <Button
        size="lg"
        className="h-12 text-base"
        disabled={continueDisabled}
        onClick={onContinue}
      >
        Continue
      </Button>

      <AppFooter result={attestation} />
    </main>
  );
}
