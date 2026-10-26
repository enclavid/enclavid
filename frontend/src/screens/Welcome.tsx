import { useEffect, useRef, useState, type ReactNode } from "react";
import Autoplay from "embla-carousel-autoplay";
import { Button } from "@/components/ui/button";
import {
  Carousel,
  CarouselContent,
  CarouselItem,
  type CarouselApi,
} from "@/components/ui/carousel";
import { AppFooter, EnclaveBadgeFace } from "@/components/AppFooter";
import { useEnclave, type EnclaveState } from "@/lib/enclave";
import { cn } from "@/lib/utils";

type Props = {
  /// Invoked when Begin is tapped. Never gated: a check that did not pass is
  /// reported, on the badge, and the applicant decides.
  onBegin: () => void;
};

// The hero badge: the footer badge's shape at a third larger, so it shrinks
// onto it in proportion on the way down.
const HERO_BADGE_CLASS =
  "inline-flex items-center gap-2 rounded-full border border-border bg-background px-3.5 py-1.5 text-base font-medium leading-tight shadow-sm";

// How long the hero shows alone before the badge appears.
const BADGE_DELAY_MS = 600;
// The least the spinner shows, so a check that finishes at once does not
// flash past.
const MIN_CHECKING_MS = 1200;
// How long the result holds before the badge flies down.
const RESULT_HOLD_MS = 1200;
// The longest the badge waits for the check: past it, it flies down with the
// check still under way, and the footer badge goes on reporting it.
const CHECK_WAIT_MS = 8000;
// Length of the merge transition (badge translates + fades, wrapper grid row
// collapses). Both run on this same timeline so they read as a single move.
const MERGE_DURATION_MS = 1200;
// One-shot fade-in for the badge when it first appears.
const BADGE_FADE_IN_MS = 300;

type Phase = "before" | "checking" | "result" | "fading" | "gone";

// Module-level latch: set true the first time Welcome mounts in this
// tab, so a return visit lands on the final layout instead of replaying
// the opening. Resets on a real page reload (module re-evaluated).
let welcomeAnimationSeen = false;

// Hero copy slideshow. First slide is the headline the user reads while
// the badge is on screen; the rest gently rotate through how-it-works
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

/// The welcome hero plus the opening motion: a badge under the hero copy shows
/// the page's check of where the session runs — a spinner while it runs, then
/// the result — and merges down onto the footer badge, which says the same and
/// goes on reporting it. The badge translates the real distance (via refs),
/// shrinking to the footer badge's size, and fades while the wrapper grid row
/// collapses, so the hero slides into the freed space with no layout jump.
///
/// The result it shows is the one the page computed; the motion paces it, and
/// invents none. The checks one by one, and what they cannot establish, are
/// behind the footer badge — see `AttestationModal`.
export function Welcome({ onBegin }: Props) {
  // Play the opening only on the first mount in this tab — a user
  // navigating back from /keygen lands on the final layout rather than
  // watching it again.
  const skipAnimationRef = useRef(welcomeAnimationSeen);
  useEffect(() => {
    welcomeAnimationSeen = true;
  }, []);

  const enclave = useEnclave();

  // The badge appears with its spinner, shows the result once the check is in
  // and the spinner has had its moment, holds, then merges into the footer
  // over MERGE_DURATION_MS.
  const [phase, setPhase] = useState<Phase>(
    skipAnimationRef.current ? "gone" : "before",
  );
  const [spun, setSpun] = useState(false);
  useEffect(() => {
    if (phase !== "before") return;
    const t = setTimeout(() => setPhase("checking"), BADGE_DELAY_MS);
    return () => clearTimeout(t);
  }, [phase]);
  useEffect(() => {
    if (phase !== "checking") return;
    const spin = setTimeout(() => setSpun(true), MIN_CHECKING_MS);
    const wait = setTimeout(() => setPhase("fading"), CHECK_WAIT_MS);
    return () => {
      clearTimeout(spin);
      clearTimeout(wait);
    };
  }, [phase]);
  useEffect(() => {
    if (phase === "checking" && spun && enclave.status === "done") setPhase("result");
  }, [phase, spun, enclave.status]);
  useEffect(() => {
    if (phase !== "result") return;
    const t = setTimeout(() => setPhase("fading"), RESULT_HOLD_MS);
    return () => clearTimeout(t);
  }, [phase]);
  useEffect(() => {
    if (phase !== "fading") return;
    const t = setTimeout(() => setPhase("gone"), MERGE_DURATION_MS);
    return () => clearTimeout(t);
  }, [phase]);

  // Compute the exact translateY that lands the badge on top of the footer
  // badge, and the scale that makes it the footer badge's size. Run when phase
  // becomes "fading" — the badge is in its final pre-animation position and
  // the footer is mounted.
  const badgeRef = useRef<HTMLDivElement>(null);
  const [landing, setLanding] = useState({ y: 0, scale: 1 });
  useEffect(() => {
    if (phase !== "fading" || !badgeRef.current) return;
    const footer = document.querySelector<HTMLElement>("[data-footer-badge]");
    if (!footer) return;
    const badgeRect = badgeRef.current.getBoundingClientRect();
    const footerRect = footer.getBoundingClientRect();
    // Centre-to-centre delta so the badge physically lands on the
    // footer badge regardless of viewport height.
    const y =
      footerRect.top + footerRect.height / 2 -
      (badgeRect.top + badgeRect.height / 2);
    setLanding({ y, scale: footerRect.height / badgeRect.height });
  }, [phase]);

  const collapsed = phase === "fading" || phase === "gone";

  // Hero copy slideshow: a carousel a finger drags, the next slide coming in
  // under it, looping round from the last to the first. It turns on its own
  // only after the opening has finished playing — the first slide stays put
  // while the user is reading it — pauses while a finger is on it, and
  // starts its count over after a tap on a dot or a side.
  const slideshowActive = phase === "gone";
  const [carousel, setCarousel] = useState<CarouselApi>();
  const autoplay = useRef(
    Autoplay({
      delay: SLIDE_INTERVAL_MS,
      playOnInit: false,
      stopOnInteraction: false,
    }),
  );
  // The slide the carousel shows, kept for the dots, however it got there.
  const [slideIndex, setSlideIndex] = useState(0);
  useEffect(() => {
    if (!carousel) return;
    const select = () => setSlideIndex(carousel.selectedScrollSnap());
    select();
    carousel.on("select", select);
    return () => {
      carousel.off("select", select);
    };
  }, [carousel]);
  useEffect(() => {
    if (slideshowActive && carousel) autoplay.current.play();
  }, [slideshowActive, carousel]);

  const goToSlide = (next: number) => {
    carousel?.scrollTo(next);
    autoplay.current.reset();
  };
  const advanceSlide = (delta: number) => {
    if (delta < 0) carousel?.scrollPrev();
    else carousel?.scrollNext();
    autoplay.current.reset();
  };

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
         * The slides, each as wide as the screen: the carousel reaches past
         * the page's own padding to both edges, so a slide comes in from the
         * edge of the screen rather than from inside it, and each slide puts
         * the padding back inside itself. A row is as tall as its tallest
         * slide, so the dots below stay put whichever slide is shown.
         */}
        <Carousel
          setApi={setCarousel}
          opts={{ loop: true }}
          plugins={[autoplay.current]}
          className="-mx-6 self-stretch"
        >
          <CarouselContent className="ml-0">
            {HERO_SLIDES.map((s, i) => (
              <CarouselItem
                key={i}
                className="flex flex-col items-center gap-6 px-6"
              >
                <h1 className="text-balance text-3xl font-semibold leading-tight tracking-tight">
                  {s.title}
                </h1>
                <p className="max-w-md text-pretty text-base leading-relaxed text-muted-foreground">
                  {s.body}
                </p>
              </CarouselItem>
            ))}
          </CarouselContent>
        </Carousel>

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
         * size. The badge (with overflow visible) escapes the collapsing
         * row downward via translateY — height collapse and the badge's
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
            <HeroBadge
              ref={badgeRef}
              phase={phase}
              landing={landing}
              enclave={enclave}
            />
          </div>
        </div>
      </section>

      <div className="flex flex-col gap-4">
        <Button size="lg" className="h-12 w-full text-base" onClick={onBegin}>
          Begin verification
        </Button>

        {/*
         * The footer badge is always present; the hero badge flies down
         * onto it, so the opening reads as the result settling into the
         * place it lives for the rest of the session.
         */}
        <AppFooter />
      </div>
    </main>
  );
}

/// The badge that shows the check in the hero and then merges onto the footer
/// badge: the same face at a larger size, shrinking to the footer badge's on
/// the way, which is what makes the landing read as one badge. `ref` targets
/// the moving node; during `fading` it takes the precomputed translate and
/// scale and fades over the merge duration.
///
/// Rendered from the start, just invisible, so the section's `justify-center`
/// does not shift the hero content when it appears.
function HeroBadge({
  ref,
  phase,
  landing,
  enclave,
}: {
  ref: React.RefObject<HTMLDivElement | null>;
  phase: Phase;
  landing: { y: number; scale: number };
  enclave: EnclaveState;
}) {
  if (phase === "gone") {
    return null;
  }

  const shown = phase === "checking" || phase === "result";
  const fading = phase === "fading";
  // Short fade-in when it appears, long synchronized merge when it slides to
  // the footer. Tracking both inline lets the duration swap cleanly between
  // phases — Tailwind transitions cannot switch durations mid-flight.
  const transition = {
    transitionProperty: "opacity, transform",
    transitionDuration: fading ? `${MERGE_DURATION_MS}ms` : `${BADGE_FADE_IN_MS}ms`,
    transitionTimingFunction: "cubic-bezier(0.4, 0, 0.2, 1)",
  } as const;

  return (
    <div
      ref={ref}
      aria-hidden={!shown}
      className={cn(!shown && "opacity-0")}
      style={{
        ...transition,
        transform: fading
          ? `translateY(${landing.y}px) scale(${landing.scale})`
          : undefined,
      }}
    >
      <div className={HERO_BADGE_CLASS}>
        {/* The spinner holds until the check is in and has had its moment,
            whatever the check's own state meanwhile. */}
        <EnclaveBadgeFace
          state={phase === "checking" ? { status: "checking" } : enclave}
        />
      </div>
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
