import { useEffect, useRef, useState } from "react";
import { cn } from "@/lib/utils";

type Props = {
  /// 0..1
  progress: number;
  className?: string;
};

/// rAF lerp toward `progress`. Pointer-move events fire in bursts
/// (60–120Hz), so feeding raw values into a CSS transition makes the
/// bar lurch — each transition restarts from the previous frame's
/// intermediate width. Instead, decouple the rendered value from the
/// input: each frame, ease the displayed value toward the latest
/// target by a constant fraction. The result is a smooth, even motion
/// regardless of how irregularly events arrive.
export function EntropyMeter({ progress, className }: Props) {
  const targetRef = useRef(progress);
  targetRef.current = progress;
  const [displayed, setDisplayed] = useState(progress);

  useEffect(() => {
    let raf = 0;
    const tick = () => {
      setDisplayed((prev) => {
        const diff = targetRef.current - prev;
        if (Math.abs(diff) < 0.0005) return targetRef.current;
        return prev + diff * 0.12;
      });
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);

  const pct = Math.max(0, Math.min(1, displayed)) * 100;
  return (
    <div className={cn("flex items-center gap-3", className)}>
      <div
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(pct)}
        aria-label="Key entropy"
        className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted"
      >
        <div
          className="h-full bg-foreground"
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="w-9 text-right font-mono text-xs tabular-nums text-muted-foreground">
        {Math.round(pct)}%
      </span>
    </div>
  );
}
