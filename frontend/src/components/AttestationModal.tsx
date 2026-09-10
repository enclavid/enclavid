import { Dialog } from "@base-ui/react/dialog";
import { cn } from "@/lib/utils";

type Props = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
};

/// Detail modal opened from the footer. Describes where the session runs
/// and says plainly what this page has and has not checked.
///
/// It states no verification result, because the page performs none: a
/// browser cannot read the certificate of its own TLS connection, so the
/// binding between an attestation quote and this channel is not something
/// in-page JavaScript can confirm. Anything shown here that looked like a
/// verdict would be decoration, and a reader who takes a decoration for a
/// check stops looking for the real one.
export function AttestationModal({ open, onOpenChange }: Props) {
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
              How your scans are protected, and what this page can and
              cannot check.
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
              What runs inside is fixed when the enclave starts, and the
              hardware hashes it into a{" "}
              <span className="font-medium text-foreground">measurement</span>{" "}
              it will sign on request. That is what makes it possible to check
              which code handled your scans, rather than being asked to take
              our word for it.
            </p>
            <p>
              Before any data leaves the enclave, you'll see exactly what's
              about to be shared and approve it explicitly. Nothing else —
              raw scans, intermediate values, or processing metadata —
              ever exits.
            </p>
            <p className="text-muted-foreground">
              This page does not perform that check, and shows no result for
              it. A browser cannot see the certificate of its own connection,
              so it cannot tell whether a measurement it was handed belongs to
              the enclave it is actually talking to. Checking that takes a tool
              running outside the browser.
            </p>
            <a
              href="https://github.com/enclavid/enclavid"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-sm font-medium underline underline-offset-2"
            >
              View source on GitHub →
            </a>
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
