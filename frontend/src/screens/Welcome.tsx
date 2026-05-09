import { useEffect, useRef, useState, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { AppFooter } from "@/components/AppFooter";
import { LockGlyph, Spinner } from "@/components/icons";
import { cn } from "@/lib/utils";
import type { AttestationResult } from "@/lib/attestation";

type Props = {
  attestation: AttestationResult | null;
  /// Invoked when Begin is tapped. Only enabled once the attestation
  /// animation has played to completion AND the verification
  /// resolved successfully — see `verified` below.
  onBegin: () => void;
};

// Step-list cadence — bumped from 600ms to give each checkmark
// landing more weight (one beat per second feels deliberate).
const STEP_DELAY_MS = 800;
// Pause between (a) the third checkmark + pill appearing together
// and (b) the merge-down animation kicking off, so the user has a
// moment to register both pieces.
const PILL_HOLD_MS = 800;
// Length of the merge transition (list fades, pill translates + fades,
// wrapper grid row collapses). All three run on this same timeline so
// they read as a single move.
const MERGE_DURATION_MS = 1200;
// One-shot fade-in for the pill when it first appears alongside the
// third checkmark. Short enough to feel synchronous with the check.
const PILL_FADE_IN_MS = 300;

// Module-level latch: set true the first time Welcome mounts in this
// tab. We use this — not `attestation !== null` — to detect "is this
// a re-mount" because the mocked /well-known/attestation usually
// resolves before Welcome ever mounts on the first visit, which would
// otherwise mis-classify a fresh load as a return visit. Resets on a
// real page reload (module re-evaluated).
let welcomeAnimationSeen = false;

// Hero copy slideshow. First slide is the original headline + body
// the user sees during attestation animation; the rest gently rotate
// through how-it-works angles after attestation completes. Auto-cycle
// only starts once `phase === "gone"`, so the first read-through of
// the hero copy isn't interrupted.
const HERO_SLIDES: ReadonlyArray<{ title: ReactNode; body: ReactNode }> = [
  {
    title: (
      <>
        Verify your identity,
        <br />
        not your privacy.
      </>
    ),
    body: "Your scans are processed inside a hardware-sealed enclave whose code you can audit on GitHub. Even our servers can't read what you upload.",
  },
  {
    title: "Hardware-sealed processing.",
    body: "The CPU encrypts the enclave's memory. Neither the operator, the host OS, nor any process outside the enclave can read what's inside.",
  },
  {
    title: "You decide what's shared.",
    body: "Before any data leaves the enclave, you'll see exactly what's about to be shared and approve it explicitly. Nothing else — raw scans, intermediate values, or processing metadata — ever exits.",
  },
  {
    title: "Open code, proven execution.",
    body: "An attestation quote signed by AMD proves the enclave is running the exact code published on GitHub. Anyone can verify that match independently.",
  },
];

const SLIDE_INTERVAL_MS = 6000;

/// Combines the welcome hero + the attestation verification ritual.
/// Status block sits with the hero content (centered, just below the
/// subtext); the Begin button is gated on `verified`. After
/// verification:
///
///   1. all three step checkmarks remain visible;
///   2. a "Verified Enclave" pill pops in underneath them;
///   3. on a single timeline — checkmarks fade out, pill translates
///      down to the footer badge (real distance via refs) and fades,
///      and the wrapper grid row collapses so the hero content slides
///      down smoothly into the freed space — no layout jump.
export function Welcome({ attestation, onBegin }: Props) {
  // Skip the multi-step animation only on a re-mount within the same
  // tab — the user already watched it play once. The first mount
  // always plays it (even if attestation already resolved), so a
  // returning user navigating back from /keygen lands on the final
  // layout instead of replaying the load sequence.
  const skipAnimationRef = useRef(welcomeAnimationSeen);
  useEffect(() => {
    welcomeAnimationSeen = true;
  }, []);

  const [step, setStep] = useState(skipAnimationRef.current ? 3 : 0);
  useEffect(() => {
    if (skipAnimationRef.current) return;
    const t1 = setTimeout(() => setStep((s) => Math.max(s, 1)), STEP_DELAY_MS);
    const t2 = setTimeout(() => setStep((s) => Math.max(s, 2)), STEP_DELAY_MS * 2);
    const t3 = setTimeout(() => setStep((s) => Math.max(s, 3)), STEP_DELAY_MS * 3);
    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
    };
  }, []);

  const animationDone = step >= 3;
  const verified = animationDone && attestation?.ok === true;
  const failed = animationDone && attestation !== null && !attestation.ok;
  const beginDisabled = !verified;

  // The moment `verified` flips true the third checkmark and the
  // pill render together (showing-pill). After PILL_HOLD_MS the
  // merge animation kicks in — list fades, pill flies to the
  // footer, wrapper collapses — all on a single MERGE_DURATION_MS
  // timeline. Failure stays in `stepping` forever. On a re-mount
  // where attestation was already ok, we initialise directly at
  // "gone" so the pill journey doesn't replay either.
  const [phase, setPhase] = useState<
    "stepping" | "showing-pill" | "fading" | "gone"
  >(
    skipAnimationRef.current && attestation?.ok === true
      ? "gone"
      : "stepping",
  );
  useEffect(() => {
    if (!verified) return;
    if (skipAnimationRef.current) {
      // Revisit case: attestation may have resolved after mount.
      // Snap straight to the final state — no replay.
      setPhase("gone");
      return;
    }
    setPhase("showing-pill");
    const t1 = setTimeout(() => setPhase("fading"), PILL_HOLD_MS);
    const t2 = setTimeout(
      () => setPhase("gone"),
      PILL_HOLD_MS + MERGE_DURATION_MS,
    );
    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
    };
  }, [verified]);

  // Compute the exact translateY that lands the inline pill on top
  // of the footer badge. Run when phase becomes "fading" — the pill
  // is in its final pre-animation position and the footer is mounted.
  const pillRef = useRef<HTMLDivElement>(null);
  const [travelY, setTravelY] = useState(0);
  useEffect(() => {
    if (phase !== "fading" || !pillRef.current) return;
    const footer = document.querySelector<HTMLElement>("[data-footer-badge]");
    if (!footer) return;
    const inlineRect = pillRef.current.getBoundingClientRect();
    const footerRect = footer.getBoundingClientRect();
    // Centre-to-centre delta so the pill physically lands on the
    // footer badge regardless of viewport height.
    const dy =
      footerRect.top + footerRect.height / 2 -
      (inlineRect.top + inlineRect.height / 2);
    setTravelY(dy);
  }, [phase]);

  const collapsed = phase === "fading" || phase === "gone";

  // Hero copy slideshow. Cycles only after attestation animation has
  // finished playing — first slide stays put while the user is
  // reading it during the load sequence.
  const slideshowActive = phase === "gone";
  const [slideIndex, setSlideIndex] = useState(0);
  // Bumped by user navigation (dot click, tap zone). The auto-cycle
  // useEffect depends on it, so any interaction restarts the timer —
  // tapping next doesn't immediately get overtaken 1s later.
  const [interactionEpoch, setInteractionEpoch] = useState(0);

  const goToSlide = (next: number) => {
    if (next === slideIndex) return;
    setSlideIndex(next);
    setInteractionEpoch((e) => e + 1);
  };
  const advanceSlide = (delta: number) => {
    setSlideIndex(
      (i) => (i + delta + HERO_SLIDES.length) % HERO_SLIDES.length,
    );
    setInteractionEpoch((e) => e + 1);
  };

  useEffect(() => {
    if (!slideshowActive) return;
    const id = setInterval(() => {
      setSlideIndex((i) => (i + 1) % HERO_SLIDES.length);
    }, SLIDE_INTERVAL_MS);
    return () => clearInterval(id);
  }, [slideshowActive, interactionEpoch]);

  return (
    <main
      className="flex min-h-dvh flex-col px-6"
      style={{
        paddingTop: "max(env(safe-area-inset-top), 1rem)",
        paddingBottom: "max(env(safe-area-inset-bottom), 1.5rem)",
      }}
    >
      <section
        onClick={(e) => {
          if (!slideshowActive) return;
          // Don't intercept taps on real interactive elements
          // (slide-indicator dots, anything we add later). Anything
          // else — text, lock icon, empty space — counts as a swipe-
          // by-tap on the slideshow.
          const target = e.target as HTMLElement;
          if (target.closest("button, a")) return;
          const rect = e.currentTarget.getBoundingClientRect();
          const x = e.clientX - rect.left;
          advanceSlide(x < rect.width / 2 ? -1 : 1);
        }}
        className={cn(
          "flex flex-1 flex-col items-center justify-center gap-6 py-10 text-center",
          slideshowActive && "select-none",
        )}
      >
        <div className="flex size-16 items-center justify-center rounded-2xl bg-foreground text-background">
          <LockIcon />
        </div>

        {/*
         * Slide stack. All slides are rendered in the same grid cell
         * (col-start-1 row-start-1) so the cell sizes to the tallest
         * slide and stays that height for the lifetime of the screen.
         * That stops the dots row below from jumping when slides of
         * different content lengths swap in. Active slide is opaque +
         * untranslated; the others are inert and faded out, ready to
         * crossfade when the index changes.
         */}
        <div className="grid">
          {HERO_SLIDES.map((s, i) => {
            const active = i === slideIndex;
            return (
              <div
                key={i}
                aria-hidden={!active}
                className={cn(
                  "col-start-1 row-start-1 flex flex-col items-center gap-6 transition-[opacity,transform] duration-500 ease-out",
                  active
                    ? "translate-y-0 opacity-100"
                    : "pointer-events-none translate-y-1 opacity-0",
                )}
              >
                <h1 className="text-balance text-3xl font-semibold leading-tight tracking-tight">
                  {s.title}
                </h1>
                <p className="max-w-md text-pretty text-base leading-relaxed text-muted-foreground">
                  {s.body}
                </p>
              </div>
            );
          })}
        </div>

        {/*
         * Dots are always mounted so they reserve their height even
         * during the attestation animation phase. Without this the
         * row would pop in after the merge animation finished and
         * push the hero copy upward, producing a visible "down then
         * up" jump. Visibility is gated by opacity + tab/keyboard
         * inertness via `tabIndex` and `disabled`.
         */}
        <div
          className={cn(
            "flex transition-opacity duration-300",
            slideshowActive ? "opacity-100" : "opacity-0",
          )}
          role="tablist"
          aria-label="How it works"
          aria-hidden={!slideshowActive}
        >
          {HERO_SLIDES.map((_, i) => (
            <button
              key={i}
              type="button"
              role="tab"
              aria-selected={i === slideIndex}
              aria-label={`Slide ${i + 1}`}
              onClick={() => goToSlide(i)}
              disabled={!slideshowActive}
              tabIndex={slideshowActive ? 0 : -1}
              // px/py expand the tap target around the 6px dot —
              // the visible glyph stays small but the touchable
              // area is large enough not to require precision.
              className="cursor-pointer px-2 py-3 disabled:cursor-default"
            >
              <span
                aria-hidden
                className={cn(
                  "block size-1.5 rounded-full transition-colors duration-300",
                  i === slideIndex
                    ? "bg-foreground"
                    : "bg-muted-foreground/30",
                )}
              />
            </button>
          ))}
        </div>

        {/*
         * Grid-row collapse: outer grid animates rows from 1fr to 0fr;
         * inner element's `min-h-0` allows shrinking below content
         * size. Pill (with overflow visible) escapes the collapsing
         * row downward via translateY — height collapse and pill
         * journey play on the same `MERGE_DURATION_MS` timeline so
         * the user reads them as one move.
         */}
        <div
          className={cn(
            "grid w-full ease-in-out",
            collapsed ? "grid-rows-[0fr]" : "grid-rows-[1fr]",
          )}
          style={{
            transitionProperty: "grid-template-rows",
            transitionDuration: `${MERGE_DURATION_MS}ms`,
          }}
          aria-hidden={phase === "gone"}
        >
          <div className="flex min-h-0 justify-center">
            <AttestationStatus
              ref={pillRef}
              step={step}
              verified={verified}
              failed={failed}
              phase={phase}
              travelY={travelY}
              attestation={attestation}
            />
          </div>
        </div>
      </section>

      <div className="flex flex-col gap-4">
        <Button
          size="lg"
          className="h-12 w-full text-base"
          disabled={beginDisabled}
          onClick={onBegin}
        >
          Begin verification
        </Button>

        {/*
         * Footer badge is always visible (spinner while attestation
         * is in flight, green lock when verified). The hero pill
         * above still flies down toward the footer-badge anchor on
         * verification — landing on top of the already-visible badge
         * reads as the celebration "joining" the persistent state.
         */}
        <AppFooter result={attestation} />
      </div>
    </main>
  );
}

/// 3-step list (always rendered while not failed/gone) + a Verified
/// Enclave pill that appears after `phase === "showing-pill"`. During
/// `fading` the list opacity fades and the pill node — which `pillRef`
/// targets — translates onto the footer-badge coordinates and fades.
function AttestationStatus({
  ref,
  step,
  verified,
  failed,
  phase,
  travelY,
  attestation,
}: {
  ref: React.RefObject<HTMLDivElement | null>;
  step: number;
  verified: boolean;
  failed: boolean;
  phase: "stepping" | "showing-pill" | "fading" | "gone";
  travelY: number;
  attestation: AttestationResult | null;
}) {
  if (failed) {
    return (
      <div className="flex max-w-sm flex-col items-center gap-2 text-sm text-destructive">
        <span aria-hidden className="size-2 rounded-full bg-destructive" />
        <p className="font-medium">Attestation failed</p>
        <p className="text-xs text-destructive/80">{failureCopy(attestation)}</p>
      </div>
    );
  }

  if (phase === "gone") {
    return null;
  }

  const showingPill = phase === "showing-pill";
  const fading = phase === "fading";
  // Pill duration: short fade-in when the third checkmark lands;
  // long, synchronized merge when sliding to the footer. Tracking
  // both as inline style lets us swap durations cleanly between
  // phases (Tailwind transitions don't switch durations mid-flight).
  const pillTransition = {
    transitionProperty: "opacity, transform",
    transitionDuration: fading
      ? `${MERGE_DURATION_MS}ms`
      : `${PILL_FADE_IN_MS}ms`,
    transitionTimingFunction: "cubic-bezier(0.4, 0, 0.2, 1)",
  } as const;
  const listFadeStyle = {
    transitionProperty: "opacity",
    transitionDuration: `${MERGE_DURATION_MS}ms`,
    transitionTimingFunction: "cubic-bezier(0.4, 0, 0.2, 1)",
  } as const;

  return (
    <div className="flex flex-col items-center gap-4" aria-live="polite">
      <ol
        className={cn("flex flex-col gap-2", fading && "opacity-0")}
        style={listFadeStyle}
      >
        <Step
          label="Fetching enclave identity"
          state={step >= 1 ? "done" : "active"}
        />
        <Step
          label="Comparing to published source"
          state={step >= 2 ? "done" : step >= 1 ? "active" : "pending"}
        />
        <Step
          label="Confirming measurement match"
          state={step >= 3 && verified ? "done" : step >= 2 ? "active" : "pending"}
        />
      </ol>

      {/*
       * Pill is rendered from the start (just invisible until the
       * third checkmark lands) so the section's `justify-center`
       * doesn't shift hero content when it appears. Only when phase
       * reaches `fading` do we apply the precomputed translateY +
       * opacity-0 — at that moment transitionDuration switches from
       * the short fade-in to the long merge duration above.
       */}
      <div
        ref={ref}
        aria-hidden={!showingPill}
        className={cn(!showingPill && "opacity-0")}
        style={{
          ...pillTransition,
          transform: fading ? `translateY(${travelY}px)` : undefined,
        }}
      >
        <VerifiedPill />
      </div>
    </div>
  );
}

function failureCopy(result: AttestationResult | null): string {
  if (!result || result.ok) return "Could not complete the verification.";
  switch (result.reason) {
    case "fetch_failed":
      return "Could not reach the attestation endpoint. Check your connection and reload.";
    case "measurement_mismatch":
      return "The running enclave does not match the published source. Do not proceed.";
    case "format_unsupported":
      return "Attestation format is not recognised. Do not proceed.";
  }
}

type StepState = "pending" | "active" | "done";

function Step({ label, state }: { label: string; state: StepState }) {
  return (
    <li className="flex items-center gap-3 text-left text-sm">
      <span
        aria-hidden
        className={cn(
          "inline-flex size-5 shrink-0 items-center justify-center rounded-full border transition-colors",
          state === "pending" && "border-border bg-background text-muted-foreground",
          state === "active" && "border-foreground/40 bg-background text-foreground",
          state === "done" && "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
        )}
      >
        {state === "active" && <Spinner className="size-3" />}
        {state === "done" && (
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" className="size-3" aria-hidden>
            <path d="m5 12 5 5 9-11" />
          </svg>
        )}
      </span>
      <span
        className={cn(
          "transition-colors",
          state === "pending" && "text-muted-foreground",
          state === "active" && "text-foreground",
          state === "done" && "text-foreground",
        )}
      >
        {label}
      </span>
    </li>
  );
}

/// Visually identical to the footer badge — same shape, colors, lock
/// glyph. The match is what sells the "merge into footer" animation.
function VerifiedPill() {
  return (
    <div className="inline-flex items-center gap-1.5 rounded-full border border-border bg-background px-2 py-0.5 text-[11px] font-medium leading-tight">
      <LockGlyph className="size-3 text-emerald-500" />
      <span>Verified Enclave</span>
    </div>
  );
}

function LockIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className="size-7"
      aria-hidden
    >
      <rect x="3" y="11" width="18" height="11" rx="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  );
}
