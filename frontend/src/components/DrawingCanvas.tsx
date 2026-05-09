import { useEffect, useRef } from "react";
import { cn } from "@/lib/utils";

type Props = {
  /// Called for each pointer-move sample while a stroke is active.
  /// `x` and `y` are in CSS pixels relative to the canvas; `t` is
  /// `performance.now()` in milliseconds.
  onPoint: (x: number, y: number, t: number) => void;
  className?: string;
  /// Optional ghost text rendered until the user starts drawing.
  hint?: string;
};

/// Full-bleed canvas that captures pointer events and renders the
/// strokes locally (visual feedback only — the consumed entropy
/// is what `onPoint` callers care about). Uses pointer events for a
/// single touch+mouse path; `touch-action: none` on the canvas
/// prevents pan/zoom from hijacking strokes mid-draw.
export function DrawingCanvas({ onPoint, className, hint }: Props) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const drawingRef = useRef(false);
  const lastRef = useRef<{ x: number; y: number } | null>(null);
  const hintShownRef = useRef(true);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    // Match canvas pixel size to its CSS size × devicePixelRatio so
    // strokes render crisp on high-DPR displays. Re-fit on resize.
    const fit = () => {
      const dpr = window.devicePixelRatio || 1;
      const rect = canvas.getBoundingClientRect();
      canvas.width = Math.round(rect.width * dpr);
      canvas.height = Math.round(rect.height * dpr);
      const ctx = canvas.getContext("2d");
      if (ctx) {
        ctx.scale(dpr, dpr);
        ctx.lineCap = "round";
        ctx.lineJoin = "round";
        ctx.lineWidth = 2.5;
        ctx.strokeStyle = "currentColor";
      }
    };
    fit();
    const ro = new ResizeObserver(fit);
    ro.observe(canvas);
    return () => ro.disconnect();
  }, []);

  const localXY = (e: React.PointerEvent<HTMLCanvasElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    return { x: e.clientX - rect.left, y: e.clientY - rect.top };
  };

  const start = (e: React.PointerEvent<HTMLCanvasElement>) => {
    e.currentTarget.setPointerCapture(e.pointerId);
    drawingRef.current = true;
    lastRef.current = localXY(e);
    hintShownRef.current = false;
  };

  const move = (e: React.PointerEvent<HTMLCanvasElement>) => {
    if (!drawingRef.current) return;
    const { x, y } = localXY(e);
    const last = lastRef.current;
    if (last) {
      const ctx = canvasRef.current?.getContext("2d");
      if (ctx) {
        ctx.beginPath();
        ctx.moveTo(last.x, last.y);
        ctx.lineTo(x, y);
        ctx.stroke();
      }
    }
    lastRef.current = { x, y };
    onPoint(x, y, performance.now());
  };

  const end = (e: React.PointerEvent<HTMLCanvasElement>) => {
    if (!drawingRef.current) return;
    drawingRef.current = false;
    lastRef.current = null;
    e.currentTarget.releasePointerCapture(e.pointerId);
  };

  return (
    <div className={cn("relative", className)}>
      <canvas
        ref={canvasRef}
        className="size-full text-foreground"
        style={{ touchAction: "none" }}
        onPointerDown={start}
        onPointerMove={move}
        onPointerUp={end}
        onPointerCancel={end}
      />
      {hint && hintShownRef.current && (
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center text-center text-sm text-muted-foreground">
          {hint}
        </div>
      )}
    </div>
  );
}
