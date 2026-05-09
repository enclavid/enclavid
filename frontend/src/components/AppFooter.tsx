import { useState } from "react";
import { cn } from "@/lib/utils";
import { AttestationModal } from "@/components/AttestationModal";
import { LockGlyph, Spinner } from "@/components/icons";
import type { AttestationResult } from "@/lib/attestation";

type Props = {
  result: AttestationResult | null;
  className?: string;
};

/// Persistent footer for post-attestation screens. Renders a single
/// status line: "Powered by AMD SEV-SNP · [Verified Enclave]". The
/// badge is always present; its glyph reflects the live attestation
/// state — spinner while the request is in flight, green lock once
/// verified, red dot on failure. Tapping opens the explanation modal.
export function AppFooter({ result, className }: Props) {
  const [open, setOpen] = useState(false);
  const state = result === null ? "loading" : result.ok ? "ok" : "fail";

  return (
    <>
      <footer
        className={cn(
          "flex items-center justify-center gap-2 text-center text-xs text-muted-foreground",
          className,
        )}
      >
        <span>Powered by AMD SEV-SNP</span>
        <span aria-hidden>·</span>
        <button
          type="button"
          onClick={() => setOpen(true)}
          // `data-footer-badge` is the anchor Welcome's pill animation
          // homes onto when it slides downward — see the pillRef
          // bounding-rect math in Welcome.tsx. Don't rename without
          // updating the query.
          data-footer-badge=""
          className="inline-flex items-center gap-1.5 rounded-full border border-border bg-background px-2 py-0.5 text-[11px] font-medium leading-tight transition-colors hover:bg-muted"
          aria-haspopup="dialog"
        >
          {state === "ok" && (
            <LockGlyph className="size-3 text-emerald-500" />
          )}
          {state === "loading" && (
            <Spinner className="size-3 text-muted-foreground" />
          )}
          {state === "fail" && (
            <span
              aria-hidden
              className="size-1.5 rounded-full bg-destructive"
            />
          )}
          <span>
            {state === "fail" ? "Attestation failed" : "Verified Enclave"}
          </span>
        </button>
      </footer>
      <AttestationModal open={open} onOpenChange={setOpen} result={result} />
    </>
  );
}
