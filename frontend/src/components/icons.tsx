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

/// Small lock used inside the Verified-Enclave badge, both inline
/// (Welcome's flying pill) and persistent (footer). Stroke is a tad
/// heavier (2.5) so the shape stays crisp at icon-sized 12px.
export function LockGlyph({ className }: Props) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden
    >
      <rect x="5" y="11" width="14" height="9" rx="2" />
      <path d="M8 11V7a4 4 0 0 1 8 0v4" />
    </svg>
  );
}
