import { Dialog } from "@base-ui/react/dialog";
import { cn } from "@/lib/utils";
import { shortCommit, type AttestationResult } from "@/lib/attestation";

type Props = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  result: AttestationResult | null;
};

/// Detail modal opened by tapping the Verified Enclave badge in the
/// footer. Explains what attestation actually proves, lists the live
/// values (commit, measurement) when verified, and links to the
/// public source for independent audit.
export function AttestationModal({ open, onOpenChange, result }: Props) {
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
              Verified Enclave
            </Dialog.Title>
            <Dialog.Description className="text-sm text-muted-foreground">
              What this badge proves, in plain terms.
            </Dialog.Description>
          </header>

          <section className="space-y-4 text-sm leading-relaxed">
            <p>
              Your scans are processed inside an{" "}
              <span className="font-medium text-foreground">AMD SEV-SNP</span>{" "}
              hardware enclave — the CPU itself encrypts the enclave's memory
              and refuses to expose it to the operator, the operating system,
              or even our own server processes outside the enclave.
            </p>
            <p>
              At session start the enclave produced a cryptographic{" "}
              <span className="font-medium text-foreground">attestation quote</span>
              {" "}signed by AMD. The quote contains a measurement (a hash of
              the exact code currently running). We compare that measurement
              to the measurement of our published source code: if they match,
              you know the running code is exactly what you can audit on
              GitHub.
            </p>
            <p>
              Before any data leaves the enclave, you'll see exactly what's
              about to be shared and approve it explicitly. Nothing else —
              raw scans, intermediate values, or processing metadata —
              ever exits.
            </p>
            {result?.ok && (
              <dl className="grid gap-2 rounded-xl border border-border bg-card p-3 text-xs">
                <div className="flex items-baseline justify-between gap-3">
                  <dt className="text-muted-foreground">Format</dt>
                  <dd className="font-mono">{result.manifest.format}</dd>
                </div>
                <div className="flex items-baseline justify-between gap-3">
                  <dt className="text-muted-foreground">Commit</dt>
                  <dd className="font-mono">
                    {shortCommit(result.manifest.reference.commit_sha)}
                  </dd>
                </div>
                <div className="flex items-baseline justify-between gap-3 break-all">
                  <dt className="shrink-0 text-muted-foreground">Measurement</dt>
                  <dd className="text-right font-mono">
                    {shortHex(result.manifest.measurement)}
                  </dd>
                </div>
              </dl>
            )}
            <p className="text-muted-foreground">
              You don't have to take our word for it — anyone can re-run this
              check independently with the source URL below.
            </p>
            {result?.ok && (
              <a
                href={result.manifest.reference.source_url}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 text-sm font-medium underline underline-offset-2"
              >
                View source on GitHub →
              </a>
            )}
          </section>

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

function shortHex(hex: string): string {
  if (hex.length <= 16) return hex;
  return `${hex.slice(0, 8)}…${hex.slice(-8)}`;
}
