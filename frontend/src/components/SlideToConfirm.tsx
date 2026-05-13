// Slide-or-hold-to-confirm primitive. Used on the consent screen to
// gate the Disclose action behind a deliberate gesture — accidental
// taps can't commit.
//
// Two interaction modes, both starting from a single pointer-down on
// the thumb:
//
//   1. **Drag** — user grabs the thumb and pulls it right. Thumb
//      tracks the finger 1:1. Released past the confirm threshold ⇒
//      fire onConfirm. Released earlier ⇒ snap back.
//   2. **Press-and-hold** — user presses the thumb and keeps the
//      finger still. The thumb auto-advances toward the right over
//      `HOLD_DURATION_MS` (2 s by default). Reaches the end ⇒ fire
//      onConfirm. Released before reaching the end ⇒ snap back from
//      wherever the auto-slide had got to.
//
// Either gesture works on its own; the user can also start with hold
// and switch to drag mid-gesture (e.g. they got bored waiting and
// shoved the thumb the rest of the way). We detect the switch by
// pointer-move distance: anything past `DRAG_DETECT_THRESHOLD` px
// cancels the auto-slide and rebases the drag origin to the current
// thumb + pointer positions.
//
// Other design notes carried over from the drag-only version:
//
//   * Pointer events (not touch + mouse separately) — single code
//     path across mobile, mouse, pen. `setPointerCapture` keeps the
//     gesture alive even when the pointer leaves the thumb hitrect.
//   * `sending` prop is the parent's submit-lifecycle signal. While
//     true the thumb stays pinned at the right showing a spinner;
//     when sending flips back to false after a confirm (= submit
//     failed) internal state resets so the user can re-gesture.
//   * `touch-action: none` on the thumb disables the browser's pan-y
//     default so vertical scroll doesn't steal a slow drag.
//   * Snap-back uses a CSS transition; the active gesture disables
//     the transition so dragX renders 1:1 with pointer/rAF updates.

import { useEffect, useRef, useState } from "react";
import { ArrowRight, Check } from "lucide-react";
import { cn } from "@/lib/utils";

type Props = {
  /// Idle-state label centered in the track. Fades out as the
  /// thumb travels right.
  label: string;
  /// Label shown once the gesture is committed and the parent is
  /// submitting. Defaults to "Sending…".
  sendingLabel?: string;
  /// Fires when the gesture completes — either dragged past the
  /// threshold, or the press-and-hold timer hit the end.
  onConfirm: () => void;
  /// Parent's submit-in-flight signal. When true the slider is
  /// locked at the right edge and the thumb shows a spinner.
  sending?: boolean;
  /// Hard-disables the slider regardless of `sending`.
  disabled?: boolean;
};

const THUMB_SIZE = 48;
const TRACK_PADDING = 4;
const CONFIRM_THRESHOLD = 0.92;
/// Total time press-and-hold takes to fill the track. Long enough
/// that an accidental press doesn't auto-confirm, short enough that
/// holding doesn't feel punishing.
const HOLD_DURATION_MS = 2000;
/// Pointer movement (in px) that switches from hold mode into drag
/// mode. Small enough that a deliberate drag wins immediately;
/// large enough that a finger jiggle during a steady hold doesn't
/// drop hold mode.
const DRAG_DETECT_THRESHOLD = 8;

export function SlideToConfirm({
  label,
  sendingLabel = "Sending…",
  onConfirm,
  sending = false,
  disabled = false,
}: Props) {
  const trackRef = useRef<HTMLDivElement>(null);
  const confirmedRef = useRef(false);
  const [dragX, setDragX] = useState(0);
  const [dragging, setDragging] = useState(false);
  const [maxX, setMaxX] = useState(0);

  // --- hold mode bookkeeping ---
  const isHoldMode = useRef(false);
  const holdStartTime = useRef(0);
  const holdInitialX = useRef(0);
  const rafId = useRef<number | null>(null);

  // --- drag mode bookkeeping (set when hold→drag transition fires
  //     OR when a fast drag bypasses hold mode entirely) ---
  const pointerStartX = useRef(0);
  const dragOriginThumbX = useRef(0);
  const dragOriginPointerX = useRef(0);

  // Track measurement.
  useEffect(() => {
    const el = trackRef.current;
    if (!el) return;
    const measure = () =>
      setMaxX(Math.max(0, el.clientWidth - THUMB_SIZE - TRACK_PADDING * 2));
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Submit failed → snap back so the user can retry the gesture.
  useEffect(() => {
    if (!sending && confirmedRef.current) {
      confirmedRef.current = false;
      setDragX(0);
    }
  }, [sending]);

  // Belt-and-braces cleanup: cancel any in-flight hold animation
  // when the component unmounts mid-gesture.
  useEffect(
    () => () => {
      if (rafId.current !== null) cancelAnimationFrame(rafId.current);
    },
    [],
  );

  const isLocked = disabled || sending || confirmedRef.current;

  const cancelHold = () => {
    isHoldMode.current = false;
    if (rafId.current !== null) {
      cancelAnimationFrame(rafId.current);
      rafId.current = null;
    }
  };

  const tickHold = (now: number) => {
    if (!isHoldMode.current) return;
    const elapsed = now - holdStartTime.current;
    const progress = Math.min(1, elapsed / HOLD_DURATION_MS);
    const newX =
      holdInitialX.current + (maxX - holdInitialX.current) * progress;
    setDragX(newX);
    if (progress >= 1) {
      cancelHold();
      confirmedRef.current = true;
      onConfirm();
      return;
    }
    rafId.current = requestAnimationFrame(tickHold);
  };

  const onPointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    if (isLocked) return;
    setDragging(true);
    pointerStartX.current = e.clientX;
    // Start hold mode immediately — drag mode takes over if the
    // pointer travels past DRAG_DETECT_THRESHOLD px.
    isHoldMode.current = true;
    holdStartTime.current = performance.now();
    holdInitialX.current = dragX;
    rafId.current = requestAnimationFrame(tickHold);
    e.currentTarget.setPointerCapture(e.pointerId);
  };

  const onPointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    if (!dragging || isLocked) return;
    const totalMove = Math.abs(e.clientX - pointerStartX.current);
    if (isHoldMode.current && totalMove > DRAG_DETECT_THRESHOLD) {
      // Switch from hold to drag — capture origin so the thumb
      // tracks the finger from wherever it currently is, not from
      // the original press position (otherwise it would jump back).
      cancelHold();
      dragOriginThumbX.current = dragX;
      dragOriginPointerX.current = e.clientX;
    }
    if (!isHoldMode.current) {
      const delta = e.clientX - dragOriginPointerX.current;
      const newX = Math.max(
        0,
        Math.min(maxX, dragOriginThumbX.current + delta),
      );
      setDragX(newX);
    }
  };

  const onPointerUp = (e: React.PointerEvent<HTMLDivElement>) => {
    if (!dragging) return;
    setDragging(false);
    cancelHold();
    e.currentTarget.releasePointerCapture(e.pointerId);
    if (confirmedRef.current) return; // hold already fired onConfirm
    if (maxX > 0 && dragX / maxX >= CONFIRM_THRESHOLD) {
      setDragX(maxX);
      confirmedRef.current = true;
      onConfirm();
    } else {
      setDragX(0);
    }
  };

  const progress = maxX > 0 ? dragX / maxX : 0;
  const labelHidden = sending || confirmedRef.current;

  return (
    // Pointer events live on the WHOLE track, not just the thumb —
    // pressing anywhere on the bar starts the gesture. The press-
    // and-hold path is intended to be discoverable: a user who taps
    // the bar (anywhere) and waits naturally sees the thumb advance.
    // The thumb itself is a pure-visual descendant with
    // `pointer-events-none` so all events route to the track.
    <div
      ref={trackRef}
      role="button"
      aria-label={label}
      aria-disabled={isLocked}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerCancel={onPointerUp}
      className={cn(
        "relative h-14 w-full overflow-hidden rounded-full bg-primary select-none",
        isLocked ? "cursor-not-allowed" : "cursor-grab active:cursor-grabbing",
        disabled && "opacity-60",
      )}
      style={{ touchAction: "none" }}
    >
      {/* Idle label — fades as the thumb moves right. */}
      <span
        className="pointer-events-none absolute inset-0 flex items-center justify-center text-base font-medium text-primary-foreground"
        style={{ opacity: labelHidden ? 0 : 1 - progress }}
        aria-hidden={labelHidden}
      >
        {label}
      </span>
      {/* Sending overlay label — replaces the idle label while the
          parent is submitting. */}
      {sending && (
        <span className="pointer-events-none absolute inset-0 flex items-center justify-center text-base font-medium text-primary-foreground">
          {sendingLabel}
        </span>
      )}
      {/* Thumb — pure visual. Pointer events route to the track
          above; pointer-events-none here keeps the thumb from
          stealing them and avoids hit-target ambiguity. */}
      <div
        aria-hidden
        className={cn(
          "pointer-events-none absolute flex items-center justify-center rounded-full bg-white text-primary shadow",
          dragging ? "transition-none" : "transition-transform duration-200",
        )}
        style={{
          top: TRACK_PADDING,
          left: TRACK_PADDING,
          width: THUMB_SIZE,
          height: THUMB_SIZE,
          transform: `translateX(${dragX}px)`,
        }}
      >
        {sending ? (
          <span
            aria-hidden
            className="size-5 animate-spin rounded-full border-2 border-primary/30 border-t-primary"
          />
        ) : confirmedRef.current ? (
          <Check className="size-5" />
        ) : (
          <ArrowRight className="size-5" />
        )}
      </div>
    </div>
  );
}
