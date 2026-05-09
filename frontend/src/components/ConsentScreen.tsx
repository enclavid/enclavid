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

export type DisplayField = {
  label: string;
  value: string;
};

export type ConsentScreenProps = {
  fields: DisplayField[];
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

export function ConsentScreen({ fields, onAllow, onDeny, onReport }: ConsentScreenProps) {
  return (
    <div>
      <h2>Review what will be shared</h2>
      <p>
        Review carefully. Only tap Allow if you agree with every field below.
        If anything looks unexpected, tap Deny or Report.
      </p>

      <table>
        <tbody>
          {fields.map((f, i) => (
            <tr key={i}>
              <td>{f.label}</td>
              <td style={valueStyle}>{f.value}</td>
            </tr>
          ))}
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
