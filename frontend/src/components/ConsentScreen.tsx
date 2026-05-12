// Consent screen for Extract Mode — the ONLY surface where personal data is
// shown to the user before being released to the requesting service.
//
// Security constraints (see docs/match-mode-and-report.md):
// - value cell forced monospace (homoglyph attacks become visually apparent)
// - max width + overflow hidden + ellipsis (block overflow-based exfiltration)
// - whitespace: nowrap (no fake newlines)
// - direction ltr + unicodeBidi plaintext (neutralize RTL-override tricks)
// - text rendered as JSX children (React auto-escapes; no HTML injection)
//
// Sanitization of invisible/control/bidi codepoints is performed server-side
// in `crates/engine/src/sanitize.rs` before the fields reach this component.
//
// Custom-key visual treatment:
// Each field carries a policy-declared `key` text-ref. For keys not in
// `KNOWN_GOOD_KEYS` the row is highlighted (left border + tinted
// background) and the raw text-ref is shown alongside the label. This
// is the visibility check against a policy that tries to encode
// categorical data (country, gender, ...) via key cardinality —
// anything off-canon flags itself before the user taps Allow.

import { pickLocalized } from "@/lib/i18n";
import type { ConsentFieldView } from "@/types";

/// Canonical keys the consent UI treats as "ordinary". Adding a key
/// here is a frontend UX call (just suppresses the raw-ref display);
/// the backend is unaware. Keep snake_case-or-kebab-case spellings
/// matching what policies use as text-refs.
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
  onAllow: () => void;
  onDeny: () => void;
  onReport: () => void;
};

const valueStyle: React.CSSProperties = {
  fontFamily: "monospace",
  maxWidth: "300px",
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
  direction: "ltr",
  unicodeBidi: "plaintext",
};

const customRowStyle: React.CSSProperties = {
  borderLeft: "3px solid #d97706",
  backgroundColor: "rgba(217, 119, 6, 0.06)",
};

const customRefStyle: React.CSSProperties = {
  fontFamily: "monospace",
  fontSize: "0.75em",
  opacity: 0.75,
  marginLeft: "0.4em",
  direction: "ltr",
  unicodeBidi: "plaintext",
};

export function ConsentScreen({
  fields,
  reasonText,
  onAllow,
  onDeny,
  onReport,
}: ConsentScreenProps) {
  return (
    <div>
      <h2>Review what will be shared</h2>
      <p>{reasonText}</p>
      <p>
        Review carefully. Only tap Allow if you agree with every field below.
        If anything looks unexpected, tap Deny or Report.
      </p>

      <table>
        <tbody>
          {fields.map((f, i) => {
            const isCustom = !KNOWN_GOOD_KEYS.has(f.key);
            return (
              <tr key={i} style={isCustom ? customRowStyle : undefined}>
                <td>
                  {pickLocalized(f.label)}
                  {isCustom && <span style={customRefStyle}>({f.key})</span>}
                </td>
                <td style={valueStyle}>{f.value}</td>
              </tr>
            );
          })}
        </tbody>
      </table>

      <div>
        <button onClick={onAllow}>Allow</button>
        <button onClick={onDeny}>Deny</button>
        <button onClick={onReport}>Report</button>
      </div>
    </div>
  );
}
