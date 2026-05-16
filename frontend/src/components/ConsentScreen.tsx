// Consent screen for Extract Mode — the ONLY surface where personal data is
// shown to the user before being released to the requesting service.
//
// Security constraints (see docs/match-mode-and-report.md):
// - value cell forced monospace (homoglyph attacks become visually apparent)
// - `break-all` so long values wrap fully visible — never truncate or
//   ellipsize what the user is agreeing to share; the server-side
//   length cap (`MAX_VALUE_LENGTH = 200` in `sanitize.rs`) keeps any
//   single field manageable on screen
// - direction ltr + unicodeBidi plaintext (neutralize RTL-override tricks)
// - text rendered as JSX children (React auto-escapes; no HTML injection)
//
// Sanitization of invisible/control/bidi/zero-width/Unicode-tag codepoints
// is performed server-side in `crates/engine/src/sanitize.rs` before the
// fields reach this component.
//
// Custom-key visual treatment:
// Each field carries a policy-declared `key` text-ref. For keys not in
// `KNOWN_GOOD_KEYS` (the frontend's "canonical" set), the row is amber-
// tinted, marked with a small "custom" badge, and the raw text-ref is
// displayed inline. This is the visibility check against a policy that
// tries to encode categorical data (country, gender, ...) via key
// cardinality — anything off-canon flags itself before the user taps
// Allow.

import { useState } from "react";
import { Eye, Info, ShieldAlert, ShieldCheck } from "lucide-react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogMedia,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogMedia,
  DialogTitle,
} from "@/components/ui/dialog";
import { SlideToConfirm } from "@/components/SlideToConfirm";
import type { ConsentFieldView } from "@/types";

/// Canonical text-refs the consent UI treats as "ordinary". Adding a
/// key here is a frontend UX call (just suppresses the custom badge);
/// the backend is unaware. Keep kebab-case spellings matching what
/// policies use as text-refs.
/// Visible-region threshold (in code points) for a single field's
/// value before the row collapses behind a "Show full" toggle. Picked
/// to comfortably show the typical short value (passport number,
/// short name, tax-id) at full width while preventing a single
/// 4000-char field from dominating the screen. The user can always
/// expand to see the full value before consenting — this is purely a
/// scanability gate, not a security boundary.
const VALUE_COLLAPSE_THRESHOLD = 200;

const KNOWN_GOOD_KEYS = new Set<string>([
  "passport-number",
  "id-card-number",
  "drivers-license-number",
  "first-name",
  "last-name",
  "middle-name",
  "full-name",
  "date-of-birth",
  "gender",
  "nationality",
  "residence-country",
  "document-expiry",
  "document-issued",
  "document-issuing-country",
  "address",
  "email",
  "phone",
  "tax-id",
]);

export type ConsentScreenProps = {
  fields: ConsentFieldView[];
  reasonText: string;
  /// Policy-supplied display name of the requesting party (resolved
  /// from `prompt-disclosure.requester` via the policy's text
  /// registry, then picked into the user's locale upstream). Empty
  /// string is treated as a fallback case — the screen still
  /// renders but with a generic descriptor.
  requesterName: string;
  /// True while the parent is submitting the consent answer.
  /// Disables Disclose / Don't-disclose so the user can't re-tap
  /// before the response lands. Surfaced as a prop because the parent
  /// owns the submit lifecycle.
  sending?: boolean;
  onAllow: () => void;
  onDeny: () => void;
};

/// CSS used for any cell that renders policy-supplied text. The
/// inline `direction`/`unicodeBidi` are belt-and-suspenders alongside
/// the server-side sanitizer that strips RTL/BIDI overrides — if a
/// stripping rule ever regresses, the layout still renders the bytes
/// in their literal LTR order rather than letting the browser flip
/// them.
const LTR_STYLE: React.CSSProperties = {
  direction: "ltr",
  unicodeBidi: "plaintext",
};

export function ConsentScreen({
  fields,
  reasonText,
  requesterName,
  sending = false,
  onAllow,
  onDeny,
}: ConsentScreenProps) {
  // Inline confirmation gate for Don't-disclose. The button itself
  // never directly fires onDeny — first tap flips this to true,
  // swapping the action area for a "really cancel?" two-button row.
  // Tapping "Keep reviewing" flips it back; tapping "Cancel
  // verification" fires onDeny. Single-tap accidental cancels are
  // turned into a two-step intentional cancel.
  const [confirmingDeny, setConfirmingDeny] = useState(false);
  return (
    <main
      className="flex min-h-dvh flex-col bg-background px-6 text-foreground"
      style={{
        paddingTop: "max(env(safe-area-inset-top), 1.5rem)",
        paddingBottom: "max(env(safe-area-inset-bottom), 1.5rem)",
      }}
    >
      <header className="mt-4 flex flex-col items-center gap-3 text-center">
        <div className="flex size-14 items-center justify-center rounded-full bg-primary/10 text-primary">
          <ShieldCheck className="size-7" />
        </div>
        <h1 className="text-xl font-semibold">Disclosure request</h1>
        <p className="max-w-md text-sm leading-relaxed text-muted-foreground">
          {requesterName ? (
            <>
              <span className="font-semibold text-foreground">
                {requesterName}
              </span>{" "}
              is asking for the details below.
            </>
          ) : (
            "The website that requested your verification is asking for the details below."
          )}{" "}
          Check each one — disclose only if nothing looks suspicious.
        </p>
        {reasonText && (
          <p className="max-w-md rounded-md bg-muted px-3 py-2 text-sm leading-relaxed text-foreground">
            <span className="font-medium">Purpose:</span> {reasonText}
          </p>
        )}
      </header>

      <ul className="mt-6 mb-4 space-y-2">
        {fields.map((f, i) => (
          <FieldRow key={i} field={f} />
        ))}
      </ul>

      <div className="mt-auto space-y-3">
        <Button
          variant="outline"
          size="lg"
          className="h-12 w-full text-base"
          onClick={() => setConfirmingDeny(true)}
          disabled={sending}
        >
          Don't disclose
        </Button>
        <SlideToConfirm
          label="Slide to disclose"
          sendingLabel="Disclosing…"
          onConfirm={onAllow}
          sending={sending}
        />
      </div>

      <AlertDialog
        open={confirmingDeny}
        onOpenChange={(open) => {
          // Block dismiss attempts while a submit is in flight —
          // an accidental backdrop tap shouldn't silently drop the
          // commitment. AlertDialog's primitive close button is
          // also routed through here, so we mirror the `disabled`
          // prop on it for consistency.
          if (!open && sending) return;
          setConfirmingDeny(open);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogMedia>
              <ShieldAlert className="text-amber-600 dark:text-amber-400" />
            </AlertDialogMedia>
            <AlertDialogTitle>Don't disclose?</AlertDialogTitle>
            <AlertDialogDescription>
              These details won't be disclosed to{" "}
              {requesterName ? (
                <span className="font-medium text-foreground">
                  {requesterName}
                </span>
              ) : (
                "the service"
              )}
              . The verification may continue, or end here.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel
              variant="default"
              disabled={sending}
              autoFocus
            >
              Keep reviewing
            </AlertDialogCancel>
            <AlertDialogAction
              variant="outline"
              onClick={onDeny}
              disabled={sending}
            >
              {sending ? (
                <span className="inline-flex items-center gap-2">
                  <span
                    aria-hidden
                    className="size-3.5 animate-spin rounded-full border-2 border-current/30 border-t-current"
                  />
                  Sending…
                </span>
              ) : (
                "Don't disclose"
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </main>
  );
}

function FieldRow({ field }: { field: ConsentFieldView }) {
  const isCustom = !KNOWN_GOOD_KEYS.has(field.key);
  const [showFull, setShowFull] = useState(false);
  const [showCustomInfo, setShowCustomInfo] = useState(false);
  // Code-point slicing (via Array.from / spread) so we don't cut a
  // surrogate pair in half on emoji or non-BMP scripts. Safer than
  // `String.prototype.slice` which works on UTF-16 code units.
  const codePoints = [...field.value];
  const overflows = codePoints.length > VALUE_COLLAPSE_THRESHOLD;
  const preview = overflows
    ? codePoints.slice(0, VALUE_COLLAPSE_THRESHOLD).join("")
    : field.value;
  const hiddenCount = codePoints.length - VALUE_COLLAPSE_THRESHOLD;
  const label = field.label;
  return (
    <li className="rounded-lg border border-border bg-card px-4 py-3">
      <div className="mb-1.5 flex items-start justify-between gap-3">
        <p className="text-xs font-medium text-muted-foreground">{label}</p>
        {(isCustom || overflows) && (
          <div className="flex shrink-0 items-center gap-1.5">
            {overflows && (
              <Badge
                render={<button type="button" />}
                onClick={() => setShowFull(true)}
                variant="secondary"
                aria-haspopup="dialog"
                className="cursor-pointer"
              >
                <Eye />
                {codePoints.length} chars
              </Badge>
            )}
            {isCustom && (
              <Badge
                render={<button type="button" />}
                onClick={() => setShowCustomInfo(true)}
                variant="secondary"
                aria-haspopup="dialog"
                className="cursor-pointer"
              >
                <Info />
                custom field
              </Badge>
            )}
          </div>
        )}
      </div>
      {isCustom && (
        <p
          className="mb-1 font-mono text-[11px] break-all text-muted-foreground"
          style={LTR_STYLE}
        >
          {field.key}
        </p>
      )}
      <p
        className="font-mono text-sm break-all text-foreground"
        style={LTR_STYLE}
      >
        {preview}
        {overflows && "…"}
      </p>
      {overflows && (
        <>
          <Button
            variant="ghost"
            size="sm"
            className="mt-1 h-auto px-0 py-1 text-xs text-muted-foreground hover:bg-transparent"
            onClick={() => setShowFull(true)}
          >
            Show full (+{hiddenCount} chars)
          </Button>
          <Dialog open={showFull} onOpenChange={setShowFull}>
            {/* Viewer modal — Dialog (not AlertDialog) so backdrop
                click and Escape both dismiss. Semantically a
                read-only viewer, not a confirmation. */}
            <DialogContent className="data-[size=default]:max-w-md data-[size=default]:sm:max-w-md">
              <DialogHeader>
                <DialogTitle>{label}</DialogTitle>
                <DialogDescription>
                  {codePoints.length} characters
                </DialogDescription>
              </DialogHeader>
              <div
                className="max-h-[60vh] overflow-y-auto rounded-md border border-border bg-muted/30 p-3 font-mono text-sm break-all text-foreground"
                style={LTR_STYLE}
              >
                {field.value}
              </div>
              <DialogFooter>
                <DialogClose variant="default">Close</DialogClose>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </>
      )}
      {isCustom && (
        <Dialog open={showCustomInfo} onOpenChange={setShowCustomInfo}>
          <DialogContent className="data-[size=default]:max-w-md data-[size=default]:sm:max-w-md">
            <DialogHeader>
              <DialogMedia>
                <Info />
              </DialogMedia>
              <DialogTitle>Custom field name</DialogTitle>
              <DialogDescription>
                The name{" "}
                <code
                  className="font-mono text-foreground"
                  style={LTR_STYLE}
                >
                  {field.key}
                </code>{" "}
                isn't one we recognize as standard (passport-number,
                first-name, email, address, …). Make sure the value
                below matches what the name suggests before
                disclosing.
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <DialogClose variant="default">Got it</DialogClose>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
    </li>
  );
}
