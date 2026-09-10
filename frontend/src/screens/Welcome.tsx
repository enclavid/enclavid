import { useEffect, useRef, useState, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { AppFooter } from "@/components/AppFooter";
import { cn } from "@/lib/utils";

type Props = {
  /// Invoked when Begin is tapped. Never gated: nothing on this screen
  /// establishes a fact that beginning ought to wait for.
  onBegin: () => void;
};

// How long the pill sits in the hero before it starts moving.
const PILL_DELAY_MS = 800;
// Pause between the pill appearing and the merge-down animation kicking
// off, so the user has a moment to register it.
const PILL_HOLD_MS = 800;
// Length of the merge transition (pill translates + fades, wrapper grid
// row collapses). Both run on this same timeline so they read as a
// single move.
const MERGE_DURATION_MS = 1200;
// One-shot fade-in for the pill when it first appears.
const PILL_FADE_IN_MS = 300;

// Module-level latch: set true the first time Welcome mounts in this
// tab, so a return visit lands on the final layout instead of replaying
// the opening. Resets on a real page reload (module re-evaluated).
let welcomeAnimationSeen = false;

// Hero copy slideshow. First slide is the headline the user reads while
// the pill is on screen; the rest gently rotate through how-it-works
// angles afterwards. Auto-cycle only starts once `phase === "gone"`, so
// the first read-through of the hero copy isn't interrupted.
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
    title: "Open code, measured at launch.",
    body: "The hardware hashes the enclave's code when it starts and will sign that hash on request, so which code handled your scans is a checkable fact rather than a promise.",
  },
];

const SLIDE_INTERVAL_MS = 6000;

/// The welcome hero plus the opening motion: a pill naming the platform
/// appears under the hero copy, then merges down onto the footer badge —
/// it translates the real distance (via refs) and fades while the wrapper
/// grid row collapses, so the hero slides into the freed space with no
/// layout jump.
///
/// The motion narrates nothing and gates nothing. What used to sit here
/// was a three-step checklist — fetching, comparing, confirming — for a
/// verification the page never performed, and an animation is the worst
/// possible place to put a claim like that: it reads as progress, so the
/// third checkmark reads as a result. When there is a real check to
/// narrate, this is where it goes.
export function Welcome({ onBegin }: Props) {
  // Play the opening only on the first mount in this tab — a user
  // navigating back from /keygen lands on the final layout rather than
  // watching it again.
  const skipAnimationRef = useRef(welcomeAnimationSeen);
  useEffect(() => {
    welcomeAnimationSeen = true;
  }, []);

  // One fixed timeline, on its own clock: the pill appears, holds, then
  // merges into the footer over MERGE_DURATION_MS.
  const [phase, setPhase] = useState<
    "before" | "showing-pill" | "fading" | "gone"
  >(skipAnimationRef.current ? "gone" : "before");
  useEffect(() => {
    if (skipAnimationRef.current) return;
    const t1 = setTimeout(() => setPhase("showing-pill"), PILL_DELAY_MS);
    const t2 = setTimeout(
      () => setPhase("fading"),
      PILL_DELAY_MS + PILL_HOLD_MS,
    );
    const t3 = setTimeout(
      () => setPhase("gone"),
      PILL_DELAY_MS + PILL_HOLD_MS + MERGE_DURATION_MS,
    );
    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
    };
  }, []);

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

  // Hero copy slideshow. Cycles only after the opening has finished
  // playing — the first slide stays put while the user is reading it.
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
            <PlatformBadge ref={pillRef} phase={phase} travelY={travelY} />
          </div>
        </div>
      </section>

      <div className="flex flex-col gap-4">
        <Button size="lg" className="h-12 w-full text-base" onClick={onBegin}>
          Begin verification
        </Button>

        {/*
         * The footer badge is always present; the hero pill flies down
         * onto it, so the opening reads as the pill settling into the
         * place it lives for the rest of the session.
         */}
        <AppFooter />
      </div>
    </main>
  );
}

/// The pill that appears in the hero and then merges onto the footer
/// badge. `pillRef` targets the moving node; during `fading` it takes the
/// precomputed translateY and fades over the merge duration.
function PlatformBadge({
  ref,
  phase,
  travelY,
}: {
  ref: React.RefObject<HTMLDivElement | null>;
  phase: "before" | "showing-pill" | "fading" | "gone";
  travelY: number;
}) {
  if (phase === "gone") {
    return null;
  }

  const showingPill = phase === "showing-pill";
  const fading = phase === "fading";
  // Short fade-in when it lands, long synchronized merge when it slides to
  // the footer. Tracking both inline lets the duration swap cleanly between
  // phases — Tailwind transitions cannot switch durations mid-flight.
  const pillTransition = {
    transitionProperty: "opacity, transform",
    transitionDuration: fading
      ? `${MERGE_DURATION_MS}ms`
      : `${PILL_FADE_IN_MS}ms`,
    transitionTimingFunction: "cubic-bezier(0.4, 0, 0.2, 1)",
  } as const;

  return (
    <div className="flex flex-col items-center gap-4">
      {/*
       * Rendered from the start, just invisible, so the section's
       * `justify-center` does not shift the hero content when it appears.
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
        <PlatformPill />
      </div>
    </div>
  );
}

/// Visually identical to the footer badge — same shape, same colors, same
/// words. The match is what sells the merge. It carries no glyph and no
/// colour signal, because it reports no outcome: see `AttestationModal`
/// for what this page can and cannot establish.
function PlatformPill() {
  return (
    <div className="inline-flex items-center gap-1.5 rounded-full border border-border bg-background px-2 py-0.5 text-[11px] font-medium leading-tight">
      <span>Where this runs</span>
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
