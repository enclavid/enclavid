import { useEffect, useRef, useState } from "react";
import { cn } from "@/lib/utils";

type Props = {
  /// First 8 bytes of the finalized applicant_key, rendered as 16
  /// hex chars grouped 4·4·4·4. Null while finalize is still in
  /// flight — characters cycle through random hex digits. Once
  /// provided, the cycling phase holds for a minimum duration so
  /// the animation reads as "generating", then the chars lock to
  /// their final values left-to-right with a small stagger.
  bytes: Uint8Array | null;
  /// Fired once after every char has locked to its final value.
  /// Caller uses this to gate the Continue button so the reveal
  /// animation can play to completion before navigation unlocks.
  onRevealed?: () => void;
  className?: string;
};

const HEX = "0123456789ABCDEF";
const LEN = 16;
const TICK_MS = 55;
const MIN_CYCLE_MS = 500;
const LOCK_INTERVAL_MS = 35;

export function KeyFingerprint({ bytes, onRevealed, className }: Props) {
  const [chars, setChars] = useState<string[]>(() =>
    Array.from({ length: LEN }, () => randomHex()),
  );
  const [lockedCount, setLockedCount] = useState(0);
  const stateRef = useRef<{
    locked: number;
    lastLockMs: number;
    target: string | null;
    mountedAt: number;
    notified: boolean;
  }>({
    locked: 0,
    lastLockMs: 0,
    target: null,
    mountedAt: performance.now(),
    notified: false,
  });

  // Keep target in a ref so the interval below can read it without
  // restarting on every parent re-render.
  stateRef.current.target = bytes ? bytesToHex(bytes) : null;

  useEffect(() => {
    const id = setInterval(() => {
      const s = stateRef.current;
      const now = performance.now();
      const cycleElapsed = now - s.mountedAt;

      if (!s.target) {
        // bytes not provided yet — every char keeps cycling.
      } else if (cycleElapsed < MIN_CYCLE_MS) {
        // bytes arrived early; hold cycling for the min duration so
        // the "generating" animation has time to read.
      } else if (s.locked < LEN && now - s.lastLockMs >= LOCK_INTERVAL_MS) {
        s.locked++;
        s.lastLockMs = now;
        setLockedCount(s.locked);
      }

      setChars((prev) => {
        const next = [...prev];
        if (s.target) {
          for (let i = 0; i < s.locked; i++) next[i] = s.target[i];
        }
        for (let i = s.locked; i < LEN; i++) {
          next[i] = randomHex();
        }
        return next;
      });

      if (s.locked >= LEN && !s.notified) {
        s.notified = true;
        onRevealed?.();
      }
    }, TICK_MS);
    return () => clearInterval(id);
  }, [onRevealed]);

  const allLocked = lockedCount >= LEN;

  return (
    <div
      className={cn(
        "flex flex-col items-center gap-1.5",
        className,
      )}
    >
      <span className="text-[10px] font-medium uppercase tracking-[0.18em] text-muted-foreground">
        {allLocked ? "Key fingerprint" : "Generating fingerprint…"}
      </span>
      <div
        className={cn(
          "flex items-baseline gap-2 font-mono text-base tracking-[0.2em] transition-colors duration-300",
          allLocked && "text-foreground",
        )}
        aria-live="polite"
      >
        {[0, 1, 2, 3].map((g) => (
          <span key={g} className="flex">
            {chars.slice(g * 4, g * 4 + 4).map((c, ci) => {
              const idx = g * 4 + ci;
              const isLocked = idx < lockedCount;
              return (
                <span
                  key={ci}
                  className={cn(
                    "inline-block w-[1ch] tabular-nums transition-colors duration-300",
                    isLocked ? "text-foreground" : "text-muted-foreground/60",
                  )}
                >
                  {c}
                </span>
              );
            })}
            {g < 3 && (
              <span className="px-1.5 text-muted-foreground/40">·</span>
            )}
          </span>
        ))}
      </div>
    </div>
  );
}

function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) {
    s += b[i].toString(16).padStart(2, "0").toUpperCase();
  }
  return s;
}

function randomHex(): string {
  return HEX[Math.floor(Math.random() * 16)];
}
