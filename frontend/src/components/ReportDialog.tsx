// Anonymous report submission dialog.
//
// POSTs to /session/:id/report with the BearerKey the client already holds for
// the session. The TEE uses the key only to authenticate the submission (prove
// session participation) and strips the session_id before persisting the
// report — the platform cannot link reports back to specific users.

import { useState } from "react";

export type ReportReason =
  | "requesting_too_much_data"
  | "unexpected_fields"
  | "suspicious_values"
  | "other";

export type ReportDialogProps = {
  sessionId: string;
  bearerKey: string;
  fieldLabels?: string[];
  onClose: () => void;
  onSubmitted: () => void;
};

const REASONS: { value: ReportReason; label: string }[] = [
  { value: "requesting_too_much_data", label: "Requesting too much data" },
  { value: "unexpected_fields", label: "Unexpected fields" },
  { value: "suspicious_values", label: "Suspicious field values" },
  { value: "other", label: "Other" },
];

export function ReportDialog({
  sessionId,
  bearerKey,
  fieldLabels,
  onClose,
  onSubmitted,
}: ReportDialogProps) {
  const [reason, setReason] = useState<ReportReason>("requesting_too_much_data");
  const [details, setDetails] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function submit() {
    setSubmitting(true);
    try {
      const res = await fetch(`/session/${sessionId}/report`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${bearerKey}`,
        },
        body: JSON.stringify({
          reason,
          details: details || undefined,
          field_labels: fieldLabels,
        }),
      });
      if (res.ok) {
        onSubmitted();
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div>
      <h3>Report this verification</h3>
      <p>What concerns you?</p>

      {REASONS.map((r) => (
        <label key={r.value}>
          <input
            type="radio"
            name="reason"
            value={r.value}
            checked={reason === r.value}
            onChange={() => setReason(r.value)}
          />
          {r.label}
        </label>
      ))}

      <label>
        Optional details:
        <textarea value={details} onChange={(e) => setDetails(e.target.value)} />
      </label>

      <div>
        <button onClick={submit} disabled={submitting}>
          Submit Report
        </button>
        <button onClick={onClose} disabled={submitting}>
          Cancel
        </button>
      </div>
    </div>
  );
}
