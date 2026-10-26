import { useState } from "react";
import { CircleCheck, ShieldAlert } from "lucide-react";
import { Spinner } from "@/components/icons";
import { AttestationModal } from "@/components/AttestationModal";
import { useEnclave, type EnclaveState } from "@/lib/enclave";
import { cn } from "@/lib/utils";

type Props = {
  className?: string;
};

/// Persistent footer. One line naming where the session runs, with a badge
/// that says how the page's check of it came out; tapping the badge opens the
/// checks one by one, and what a page's own checks cannot establish.
export function AppFooter({ className }: Props) {
  const [open, setOpen] = useState(false);
  const enclave = useEnclave();

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
          // `data-footer-badge` is the anchor Welcome's badge homes onto
          // when it slides downward — see the badgeRef bounding-rect math
          // in Welcome.tsx. Don't rename without updating the query.
          data-footer-badge=""
          className={BADGE_CLASS + " transition-colors hover:bg-muted"}
          aria-haspopup="dialog"
        >
          <EnclaveBadgeFace state={enclave} />
        </button>
      </footer>
      <AttestationModal open={open} onOpenChange={setOpen} />
    </>
  );
}

/// The badge's shape. Welcome flies a larger one of the same proportions down
/// onto it, shrinking to this size on the way, which is what makes the landing
/// read as one badge.
export const BADGE_CLASS =
  "inline-flex items-center gap-1.5 rounded-full border border-border bg-background px-2.5 py-1 text-xs font-medium leading-tight";

/// The badge's face: the check under way, passed, or not. Its glyphs are sized
/// in `em`, so the face scales with whichever badge it is in.
export function EnclaveBadgeFace({ state }: { state: EnclaveState }) {
  if (state.status === "checking") {
    return (
      <>
        <Spinner className="size-[1em]" />
        <span>Checking enclave</span>
      </>
    );
  }
  if (state.verified) {
    return (
      <>
        <CircleCheck className="size-[1.2em] text-emerald-600 dark:text-emerald-400" />
        <span>Enclave verified</span>
      </>
    );
  }
  return (
    <>
      <ShieldAlert className="size-[1.2em] text-amber-600 dark:text-amber-400" />
      <span>Enclave not verified</span>
    </>
  );
}
