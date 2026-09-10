import { useState } from "react";
import { cn } from "@/lib/utils";
import { AttestationModal } from "@/components/AttestationModal";

type Props = {
  className?: string;
};

/// Persistent footer. One line naming where the session runs, tapping it
/// opens the explanation.
///
/// It carries no status glyph. A badge has exactly one job — to say whether
/// something was checked — and nothing here checks anything, so a green
/// indicator would be reporting a verification that did not happen. The
/// footer states a fact about the platform and hands the reader somewhere to
/// find out what that does and does not buy them.
export function AppFooter({ className }: Props) {
  const [open, setOpen] = useState(false);

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
          <span>Where this runs</span>
        </button>
      </footer>
      <AttestationModal open={open} onOpenChange={setOpen} />
    </>
  );
}
