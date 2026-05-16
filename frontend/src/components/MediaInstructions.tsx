// Pre-capture instruction screen — one per `capture-step`.
//
// Shown BEFORE the camera turns on for each step, including:
//   - Step 0 of any prompt (gates the camera-permission prompt
//     behind a deliberate "Start" tap so it doesn't fire cold)
//   - Subsequent steps of a multi-step capture (so "now flip to
//     the back" or "now the second page" gets a calm framing
//     screen instead of jumping straight into a different camera
//     view)
//
// Styled in the app's default theme (light background, primary
// CTA) — this is an informational screen, not the camera. The
// camera-mode aesthetic kicks in only when the camera actually
// turns on; pretending otherwise here makes the instructions feel
// urgent and movie-mode-ish for no reason.
//
// Composition:
//   - Top: artifact-level title (media-spec.label) — same on every
//     step of a prompt, acts as orientation
//   - Step badge ("Step 2 of 3") when total > 1
//   - Center: bundled artifact icon above the per-step instructions
//     text
//   - Bottom: "Start capture" CTA + camera-permission priming hint
//
// Labels arrive already resolved to the user's locale (server
// resolves via `Accept-Language` header). Icon is dispatched against
// the frontend-bundled SVG library so no policy-controlled imagery
// ever reaches the DOM.

import { ArtifactIcon } from "@/components/ArtifactIcon";
import { Button } from "@/components/ui/button";

type Props = {
  /// `media-spec.label` — overall artifact title, locale-resolved.
  artifactLabel: string;
  /// `capture-step.icon` dispatch name; null = no icon area.
  /// Unknown values gracefully render as no icon (see
  /// `ArtifactIcon` component).
  icon: string | null;
  /// `capture-step.instructions` — per-step pre-capture body,
  /// locale-resolved.
  instructions: string;
  /// 1-based step index for the badge.
  stepNumber: number;
  /// Total step count; badge is hidden when 1.
  totalSteps: number;
  onStart: () => void;
};

export function MediaInstructions({
  artifactLabel,
  icon,
  instructions,
  stepNumber,
  totalSteps,
  onStart,
}: Props) {
  const hasIcon = icon != null;
  return (
    <main
      className="flex min-h-dvh flex-col bg-background px-6 text-foreground"
      style={{
        paddingTop: "max(env(safe-area-inset-top), 1.5rem)",
        paddingBottom: "max(env(safe-area-inset-bottom), 2rem)",
      }}
    >
      <header className="mt-10 flex flex-col items-center gap-1 text-center">
        <h1 className="text-2xl font-semibold">{artifactLabel}</h1>
        {totalSteps > 1 && (
          <p className="text-sm text-muted-foreground">
            Step {stepNumber} of {totalSteps}
          </p>
        )}
      </header>

      {hasIcon && (
        <div className="my-8 flex justify-center text-foreground/80">
          <ArtifactIcon name={icon} className="size-28" />
        </div>
      )}

      <p
        className={`mx-auto max-w-md whitespace-pre-line text-center text-base leading-relaxed text-muted-foreground ${
          hasIcon ? "" : "mt-10"
        }`}
      >
        {instructions}
      </p>

      <div className="mt-auto pt-8">
        <Button size="lg" className="h-14 w-full text-base" onClick={onStart}>
          Start capture
        </Button>
        <p className="mt-3 text-center text-xs text-muted-foreground">
          Your camera will turn on after you tap Start.
        </p>
      </div>
    </main>
  );
}
