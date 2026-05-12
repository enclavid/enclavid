// Frontend-bundled artifact silhouettes for the pre-capture intro
// screen.
//
// Dispatch is by name (text-ref string). The policy supplies the
// name (validated as a registered `text-ref` host-side), the
// frontend looks it up in `GLYPHS`. Two design points:
//
//   - **Why static React components, not policy-supplied SVG.**
//     Inline SVG is an XSS vector (script tags, event handlers,
//     foreignObject HTML); a sanitizer is fragile and ongoing-CVE
//     -prone. Keeping the icon surface attested-in-the-bundle
//     closes the door entirely.
//   - **Why graceful fallback on unknown names.** A new policy
//     can ask for icon names the running frontend doesn't yet
//     bundle (e.g. policy targets future "european-residence-permit"
//     before the frontend ship adds it). Unknown name → render
//     nothing, capture flow continues. New icons are a frontend
//     release, not a coupled WIT/host bump.
//
// Adding a new icon = add an entry to `GLYPHS` + a Glyph function.
// No WIT, proto, or host code changes. Frontend rebuild + PCR
// updates; policies that already register the matching text-ref
// start rendering it.
//
// Visual style: 96x96 viewBox, stroke-only, currentColor-inheriting
// (so the parent's `text-*` class drives the colour). Stroke 2.5
// reads cleanly at the 96px display size used on the intro screen
// while staying legible if rendered at half that. Faces inside
// photo placeholders are abstract — head circle + shoulders arc,
// no eyes/mouth — to avoid cartoony "smiley face" connotations
// and to keep the icon language KYC-serious.

type Props = {
  /// text-ref name as the policy registered + the host validated.
  /// `null` (or unknown) → no icon rendered.
  name: string | null;
  className?: string;
};

export function ArtifactIcon({ name, className }: Props) {
  if (!name) return null;
  const Glyph = GLYPHS[name];
  if (!Glyph) {
    // Unknown ref — graceful fallback. Policy was valid (host
    // verified membership in prepare-text-refs), but this frontend
    // release doesn't bundle a matching SVG. Render nothing.
    return null;
  }
  return (
    <Glyph
      className={className}
      aria-hidden
      viewBox="0 0 96 96"
      fill="none"
      stroke="currentColor"
      strokeWidth={2.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  );
}

type Glyph = (props: React.SVGProps<SVGSVGElement>) => React.JSX.Element;

const GLYPHS: Record<string, Glyph> = {
  passport: PassportGlyph,
  "id-card": IdCardGlyph,
  "drivers-license": DriversLicenseGlyph,
  selfie: SelfieGlyph,
};

// Passport open to the photo page — the layout users see when
// they follow the instruction "open to the photo page". Horizontal
// page (landscape, ICAO TD3 spread ratio ≈ 1.4), photo placeholder
// in the canonical upper-left position with an abstract head &
// shoulders inside, personal-data text lines running alongside the
// photo, and a two-row MRZ band along the bottom. We show the page
// view rather than a closed cover because the icon's job here is
// to cue the action ("here's what you'll be capturing"), not just
// the artifact category.
function PassportGlyph(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg {...props}>
      {/* Horizontal page */}
      <rect x="8" y="18" width="80" height="60" rx="2" />
      {/* Photo placeholder with abstract head & shoulders */}
      <rect x="14" y="24" width="24" height="28" rx="1.5" />
      <circle cx="26" cy="34" r="4" />
      <path d="M 15 50 Q 26 43 37 50" />
      {/* Personal-data text lines, right of photo */}
      <line x1="44" y1="28" x2="82" y2="28" />
      <line x1="44" y1="36" x2="76" y2="36" />
      <line x1="44" y1="44" x2="80" y2="44" />
      {/* MRZ band at the bottom of the page */}
      <line x1="14" y1="62" x2="82" y2="62" />
      <line x1="14" y1="70" x2="82" y2="70" />
    </svg>
  );
}

// Horizontal ID-1 card — the actual artifact the user will photograph.
// Photo placeholder on the left (with abstract head & shoulders inside),
// personal-data text lines to the right, and a short signature line
// at the bottom-left where most national IDs put a signature strip.
// Layout deliberately denser than the driver's license — a real
// national ID typically carries more visible fields (name, DOB, ID
// number, expiry).
function IdCardGlyph(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg {...props}>
      {/* Card */}
      <rect x="8" y="22" width="80" height="52" rx="4" />
      {/* Photo with abstract head & shoulders */}
      <rect x="14" y="28" width="22" height="32" rx="1.5" />
      <circle cx="25" cy="40" r="4" />
      <path d="M 15 58 Q 25 50 35 58" />
      {/* Personal-data text lines */}
      <line x1="42" y1="32" x2="82" y2="32" />
      <line x1="42" y1="40" x2="72" y2="40" />
      <line x1="42" y1="48" x2="80" y2="48" />
      <line x1="42" y1="56" x2="68" y2="56" />
      {/* Signature strip at the bottom-left */}
      <line x1="14" y1="68" x2="42" y2="68" />
    </svg>
  );
}

// Horizontal driver's license — same ID-1 outer card as a national
// ID, distinguished by the coloured "DRIVER LICENSE" header band
// real licenses (especially US/EU) carry across their top edge.
// Sparser data area than the national ID (DLs usually have fewer
// visible fields), photo shifted down to clear the banner.
function DriversLicenseGlyph(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg {...props}>
      {/* Card */}
      <rect x="8" y="22" width="80" height="52" rx="4" />
      {/* Header banner: divider line + short title indicator */}
      <line x1="8" y1="32" x2="88" y2="32" />
      <line x1="14" y1="27" x2="36" y2="27" />
      {/* Photo with abstract head & shoulders (shifted down) */}
      <rect x="14" y="38" width="22" height="28" rx="1.5" />
      <circle cx="25" cy="48" r="4" />
      <path d="M 15 64 Q 25 56 35 64" />
      {/* Personal-data text lines */}
      <line x1="42" y1="40" x2="80" y2="40" />
      <line x1="42" y1="48" x2="74" y2="48" />
      <line x1="42" y1="56" x2="78" y2="56" />
      <line x1="42" y1="64" x2="68" y2="64" />
    </svg>
  );
}

// Selfie — the user's own portrait. Standalone vertical photo
// (3:4-ish frame) with an abstract head & shoulders inside; same
// visual building block as the photo placeholders on the document
// icons, just promoted to first-class with no surrounding card or
// data fields. Sparseness IS the message — a selfie is just your
// face, no fields to fill.
function SelfieGlyph(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg {...props}>
      {/* Portrait photo */}
      <rect x="28" y="14" width="40" height="68" rx="3" />
      {/* Head */}
      <circle cx="48" cy="38" r="10" />
      {/* Shoulders */}
      <path d="M 28 70 Q 48 56 68 70" />
    </svg>
  );
}
