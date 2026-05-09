// TypeScript mirrors of the public JSON wire types defined in
// `crates/api/src/dto.rs` and `crates/api/src/applicant/views.rs`.
// Keep these in sync — every shape change on the backend should land
// here in the same commit.

// --- Lifecycle ---

export type SessionStatus =
  | "unspecified"
  | "running"
  | "completed"
  | "failed"
  | "expired";

export type StatusResponse = {
  status: SessionStatus;
};

// --- Consent display fields (mirror dto::FieldKey) ---

export type DocumentRole = "passport" | "id_card" | "drivers_license" | "unknown";

export type FieldKey =
  | { key: "first-name" }
  | { key: "last-name" }
  | { key: "middle-name" }
  | { key: "date-of-birth" }
  | { key: "place-of-birth" }
  | { key: "nationality" }
  | { key: "sex" }
  | { key: "country-of-residence" }
  | { key: "document-number"; document: DocumentRole }
  | { key: "document-issuing-country"; document: DocumentRole }
  | { key: "document-issue-date"; document: DocumentRole }
  | { key: "document-expiry-date"; document: DocumentRole }
  | { key: "custom"; language: string; text: string }
  | { key: "unknown" };

// `key` is flattened into the same JSON object as `value` via
// `#[serde(flatten)]` on the Rust side — so the TS type is the union
// of FieldKey + a `value` string.
export type DisplayField = FieldKey & { value: string };

export type LocalizedText = {
  language: string;
  text: string;
};

// --- Suspended request shapes (mirror RequestView) ---

export type LivenessMode = "selfie_video" | "unknown";

export type CaptureItem =
  | { kind: "passport" }
  | { kind: "id_card" }
  | { kind: "drivers_license" }
  | { kind: "liveness"; mode: LivenessMode };

export type RequestView =
  | { kind: "passport" }
  | { kind: "id_card" }
  | { kind: "drivers_license" }
  | { kind: "liveness"; mode: LivenessMode }
  | { kind: "consent"; fields: DisplayField[]; reason: LocalizedText }
  | { kind: "verification_set"; alternatives: CaptureItem[][] };

// --- /connect, /input response (mirror SessionProgress) ---

export type Decision =
  | "approved"
  | "rejected"
  | "rejected_retryable"
  | "review";

export type SessionProgress =
  | { status: "completed"; decision: Decision }
  | { status: "awaiting_input"; request: RequestView };

// --- Attestation (mirror AttestationManifest) ---

export type AttestationReference = {
  source_url: string;
  commit_sha: string;
  expected_measurement: string;
};

export type AttestationManifest = {
  format: string;
  measurement: string;
  reference: AttestationReference;
};
