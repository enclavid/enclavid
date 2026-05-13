/// Reached when `/status` reports `completed` (no decision available
/// — reload path, App.tsx terminal short-circuit) or when the engine
/// returns SessionProgress::Completed via /input or /connect (decision
/// available — fresh-submit path through `Verify.tsx`).
///
/// Visuals diverge by decision because only some outcomes are
/// actionable for the applicant:
///   * `approved` — success-tinged green check; the platform will
///     follow up but the applicant can relax.
///   * `rejected` — neutral-but-firm red X; the platform decides
///     next steps (appeal, retry, etc.) so we don't promise either.
///   * `rejected_retryable` — amber refresh; the engine couldn't
///     decide (bad scan, low-quality liveness, ...) and the
///     applicant CAN retry by starting a new session from the
///     requesting service.
///   * `review` — blue clock; case escalated to a human reviewer,
///     applicant waits for an external channel to update them.
///
/// Reload path (`decision` undefined) collapses to a neutral
/// "Verification finished" — we don't have the decision because the
/// public /status endpoint deliberately omits it (sensitive info
/// that should not leak via forwarded session URLs).

import { Check, Clock, RotateCcw, X } from "lucide-react";
import type { Decision } from "@/types";

type Props = {
  decision?: Decision;
};

type Variant = {
  iconBg: string;
  iconText: string;
  Icon: typeof Check;
  title: string;
  body: string;
};

const VARIANTS: Record<Decision, Variant> = {
  approved: {
    iconBg: "bg-emerald-500/10",
    iconText: "text-emerald-600 dark:text-emerald-400",
    Icon: Check,
    title: "Verification approved",
    body: "Your verification was successful. The requesting service has been notified.",
  },
  rejected: {
    iconBg: "bg-destructive/10",
    iconText: "text-destructive",
    Icon: X,
    title: "Verification declined",
    body: "The requesting service has been notified. If you think this is a mistake, please reach out to them.",
  },
  rejected_retryable: {
    iconBg: "bg-amber-500/10",
    iconText: "text-amber-600 dark:text-amber-400",
    Icon: RotateCcw,
    title: "Couldn't verify",
    body: "Something didn't work out — usually a document or photo that wasn't readable. Start a new verification from the requesting service to try again.",
  },
  review: {
    iconBg: "bg-sky-500/10",
    iconText: "text-sky-600 dark:text-sky-400",
    Icon: Clock,
    title: "Pending review",
    body: "Your verification is being reviewed manually. The requesting service will notify you when there's an update.",
  },
};

const FALLBACK: Omit<Variant, "Icon"> & { Icon: typeof Check } = {
  iconBg: "bg-muted",
  iconText: "text-muted-foreground",
  Icon: Check,
  title: "Verification finished",
  body: "You can close this page. The outcome is determined by the requesting service, which has been notified.",
};

export function Completed({ decision }: Props) {
  const v = decision ? VARIANTS[decision] : FALLBACK;
  const Icon = v.Icon;
  return (
    <main
      className="flex min-h-dvh flex-col items-center justify-center px-6 text-center"
      style={{
        paddingTop: "max(env(safe-area-inset-top), 1rem)",
        paddingBottom: "max(env(safe-area-inset-bottom), 1.5rem)",
      }}
    >
      <div className="flex max-w-sm flex-col items-center gap-4">
        <div
          className={`flex size-14 items-center justify-center rounded-full ${v.iconBg} ${v.iconText}`}
        >
          <Icon className="size-7" strokeWidth={2.5} aria-hidden />
        </div>
        <h1 className="text-xl font-semibold">{v.title}</h1>
        <p className="text-sm leading-relaxed text-muted-foreground">
          {v.body}
        </p>
      </div>
    </main>
  );
}
