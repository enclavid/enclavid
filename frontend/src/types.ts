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

// --- Consent display fields (mirror dto::DisplayField) ---

/// One consented field as it appears on the applicant's consent
/// screen. `key` is the policy-declared text-ref — opaque string,
/// shown raw on the consent UI for non-canonical names (see
/// `KNOWN_GOOD_KEYS` in `components/ConsentScreen`). `label` is
/// already resolved to the applicant's locale by the server (per
/// the request's `Accept-Language` header). `value` is the actual
/// data.
///
/// Mirror of `dto::ConsentFieldView`. Distinct from the
/// sealed-envelope `DisplayField` shape (`{ key, value }` only) on
/// the consumer side — the frontend never reads the envelope, so
/// only this view shape is modelled here.
export type ConsentFieldView = {
  key: string;
  label: string;
  value: string;
};

// --- Suspended request shapes (mirror RequestView) ---

export type CameraFacing = "front" | "rear" | "any";

export type CaptureGuide =
  | { kind: "none" }
  | { kind: "rect"; aspect: number }
  | { kind: "oval" };

export type CaptureStep = {
  /// Optional icon name dispatched against the frontend's bundled
  /// SVG library. `null` skips the icon area entirely. Unknown
  /// names render as no icon (graceful fallback). Polici author
  /// picks one of the well-known names; frontend version controls
  /// the accepted set.
  icon: string | null;
  /// Pre-capture intro body, paired with `icon` on the intro
  /// screen for this step. Already resolved to user's locale.
  instructions: string;
  /// Short on-camera overlay text shown during capture.
  label: string;
  camera: CameraFacing;
  guide: CaptureGuide;
  /// Post-capture review-screen copy ("Make sure the MRZ is sharp,
  /// no glare"). Policy-supplied via `capture-step.review-hint` so
  /// each artifact type gets its own targeted check.
  review_hint: string;
};

export type MediaSpec = {
  label: string;
  captures: CaptureStep[];
};

export type RequestView =
  | {
      kind: "media";
      /// Overall artifact title surfaced on every screen of the
      /// capture flow as context ("Your passport").
      label: string;
      captures: CaptureStep[];
      /// Step indices already captured (subset of 0..captures.length).
      filled: number[];
      /// Slot id to POST the next step to (`/input/<slot_id>`).
      next_slot_id: string;
    }
  | {
      kind: "consent";
      fields: ConsentFieldView[];
      reason: string;
      /// Policy-supplied name of the party requesting verification
      /// ("Acme Trading"). Rendered prominently in the consent
      /// screen header so the applicant knows to whom the
      /// disclosure is being made — distinguishes the consumer
      /// (the receiving party) from the Enclavid platform (which
      /// runs the check but never reads the data).
      requester: string;
    }
  | { kind: "verification_set"; alternatives: MediaSpec[][] };

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
