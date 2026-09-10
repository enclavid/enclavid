// Shared icon glyphs used across screens. Inline SVGs (rather than a
// dependency) so the bundle stays small and the `currentColor` /
// `className` patterns line up with how the rest of the UI is styled.

import { cn } from "@/lib/utils";

type Props = {
  className?: string;
};

/// Spinning ring loader. Used in active step indicators while the
/// attestation animation is in flight. The trick is the transparent
/// top border on top of `animate-spin` — the gap rotates around the
/// circle, reading as a tail-and-head spinner without any SVG.
export function Spinner({ className }: Props) {
  return (
    <span
      aria-hidden
      className={cn(
        "inline-block animate-spin rounded-full border-2 border-current border-t-transparent",
        className,
      )}
    />
  );
}

