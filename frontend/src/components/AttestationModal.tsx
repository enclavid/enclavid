import { Dialog } from "@base-ui/react/dialog";
import { CircleAlert, CircleCheck } from "lucide-react";
import { Spinner } from "@/components/icons";
import { useEnclave } from "@/lib/enclave";
import type { CheckId, Facts } from "@/lib/attestation";
import { cn } from "@/lib/utils";

/// Where the steps to check the enclave without this page are written.
const SELF_CHECK_URL = "https://github.com/enclavid/enclavid#verifying-the-gateway";

/// Where to read, in plain words, what the hardware this runs on does.
const LEARN_URL = "https://en.wikipedia.org/wiki/Confidential_computing";

/// Each check as the applicant reads it: what it is, and what it found. The
/// verifier's own account of each is under "See more".
const PLAIN: Record<CheckId, { title: string; passed: string; failed: string }> = {
  hardware: {
    title: "Genuine AMD chip",
    passed: "Signed by a real AMD processor.",
    failed: "We couldn't confirm the chip is genuine.",
  },
  connection: {
    title: "Sealed connection",
    passed: "Your connection ends inside the enclave.",
    failed: "We couldn't confirm where your connection ends.",
  },
  build: {
    title: "The expected software",
    passed: "Your session runs exactly the software your link points to.",
    failed: "We couldn't confirm which software runs your session.",
  },
  sealed: {
    title: "Private from the operator",
    passed: "Not even the people who run the servers can look inside.",
    failed: "We couldn't confirm it's closed to the operator.",
  },
  firmware: {
    title: "Security fixes installed",
    passed: "The chip has the required security fixes.",
    failed: "We couldn't confirm the chip's security fixes.",
  },
};

type Props = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
};

/// Detail dialog opened from the footer badge: each check the page made of
/// where the session runs and how it came out, in plain words, with the
/// verifier's own account a tap away; and — beside them, never below the
/// fold — that a page's own checks cannot fully vouch for the page, and where
/// to check without it. The checks are real, and the notice is what keeps them
/// from reading as more.
export function AttestationModal({ open, onOpenChange }: Props) {
  const enclave = useEnclave();
  const checks = enclave.status === "done" ? enclave.enclave.checks : null;

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Backdrop className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm transition-opacity duration-200 data-ending-style:opacity-0 data-starting-style:opacity-0" />
        <Dialog.Popup
          className={cn(
            "fixed z-50 flex flex-col gap-5 border border-border bg-background shadow-xl outline-none",
            // Mobile: bottom sheet. Desktop: centered card.
            "inset-x-0 bottom-0 max-h-[88dvh] overflow-y-auto rounded-t-2xl p-6",
            "sm:inset-auto sm:left-1/2 sm:top-1/2 sm:max-w-md sm:-translate-x-1/2 sm:-translate-y-1/2 sm:rounded-2xl",
            "transition-all duration-200",
            "data-starting-style:translate-y-full data-starting-style:opacity-0",
            "data-ending-style:translate-y-full data-ending-style:opacity-0",
            "sm:data-starting-style:-translate-y-1/2 sm:data-starting-style:scale-95 sm:data-starting-style:opacity-0",
            "sm:data-ending-style:-translate-y-1/2 sm:data-ending-style:scale-95 sm:data-ending-style:opacity-0",
          )}
          style={{
            paddingBottom: "max(env(safe-area-inset-bottom), 1.5rem)",
          }}
        >
          <header className="flex flex-col gap-2">
            <Dialog.Title className="text-lg font-semibold">
              Where this runs
            </Dialog.Title>
            <Dialog.Description className="text-sm text-muted-foreground">
              Your browser checked where your data is processed.
            </Dialog.Description>
          </header>

          {checks === null ? (
            <p className="flex items-center gap-2 text-sm text-muted-foreground">
              <Spinner className="size-4" />
              Checking…
            </p>
          ) : checks.length === 0 ? (
            <p className="flex items-start gap-2.5 text-sm">
              <CircleAlert className="mt-0.5 size-4 shrink-0 text-amber-600 dark:text-amber-400" />
              This page couldn't run the checks.
            </p>
          ) : (
            <div className="flex flex-col gap-3">
              <ul className="flex flex-col gap-3 text-sm">
                {checks.map((check) => (
                  <li key={check.id} className="flex items-start gap-2.5">
                    {check.ok ? (
                      <CircleCheck className="mt-0.5 size-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
                    ) : (
                      <CircleAlert className="mt-0.5 size-4 shrink-0 text-amber-600 dark:text-amber-400" />
                    )}
                    <span className="min-w-0">
                      <span className="block font-medium">{PLAIN[check.id].title}</span>
                      <span className="block text-muted-foreground">
                        {check.ok ? PLAIN[check.id].passed : PLAIN[check.id].failed}
                      </span>
                    </span>
                  </li>
                ))}
              </ul>

              <details className="text-sm">
                <summary className="cursor-pointer text-muted-foreground">
                  See more
                </summary>
                <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5 text-xs">
                  {checks.map((check) => (
                    <div key={check.id} className="contents">
                      <dt className="text-muted-foreground">{PLAIN[check.id].title}</dt>
                      <dd className="wrap-break-word">{check.detail}</dd>
                    </div>
                  ))}
                  {enclave.status === "done" && enclave.enclave.gateway && (
                    <FactRows title="Gateway" facts={enclave.enclave.gateway} />
                  )}
                  {enclave.status === "done" && enclave.enclave.session && (
                    <FactRows title="Your session" facts={enclave.enclave.session} />
                  )}
                </dl>
              </details>
            </div>
          )}

          <section className="space-y-2 rounded-xl bg-muted px-4 py-3 text-sm leading-relaxed">
            <p>
              Your browser ran these checks itself. But this page comes from
              the same service it's checking, so it can't fully vouch for
              itself. For complete certainty, you may always check
              independently.
            </p>
            <a
              href={SELF_CHECK_URL}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 font-medium underline underline-offset-2"
            >
              How to check it yourself →
            </a>
          </section>

          <section className="space-y-3 text-sm leading-relaxed text-muted-foreground">
            <p>
              Your data is processed in an enclave: a sealed-off part of an
              AMD processor (the technology is called AMD SEV-SNP). The chip
              encrypts everything inside it, so not even the people who run
              the servers can see it.
            </p>
            <p>
              Nothing leaves without your approval. Before anything is shared,
              you'll see exactly what it is and decide.
            </p>
            <a
              href={LEARN_URL}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 font-medium text-foreground underline underline-offset-2"
            >
              What is confidential computing? →
            </a>
          </section>

          <a
            href="https://github.com/enclavid/enclavid"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 text-sm font-medium underline underline-offset-2"
          >
            View source on GitHub →
          </a>

          <Dialog.Close
            className="absolute right-3 top-3 inline-flex size-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
            aria-label="Close"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="size-4" aria-hidden>
              <path d="M6 6 18 18" />
              <path d="M18 6 6 18" />
            </svg>
          </Dialog.Close>
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

/// One report's signed fields, under a heading of whose report it is.
function FactRows({ title, facts }: { title: string; facts: Facts }) {
  return (
    <>
      <dt className="col-span-2 mt-2 font-medium text-foreground">{title}</dt>
      <dt className="text-muted-foreground">Build</dt>
      <dd className="break-all font-mono">{facts.measurement}</dd>
      <dt className="text-muted-foreground">Processor</dt>
      <dd>{facts.product || "—"}</dd>
      <dt className="text-muted-foreground">Chip</dt>
      <dd className="break-all font-mono">{facts.chipId}</dd>
      <dt className="text-muted-foreground">Firmware</dt>
      <dd>{facts.reportedTcb}</dd>
      <dt className="text-muted-foreground">At launch</dt>
      <dd>{facts.launchTcb}</dd>
      <dt className="text-muted-foreground">Guest policy</dt>
      <dd className="font-mono">
        {facts.policy}, report version {facts.version}
      </dd>
    </>
  );
}
