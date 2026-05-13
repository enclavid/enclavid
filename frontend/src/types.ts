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

/// One translation row: the human-readable `text` in a specific
/// `language`. Frontend picks the row matching the user's locale
/// with fallback to `en` then any.
export type LocalizedString = {
  language: string;
  text: string;
};

/// Full translation set for one `text-ref`. Empty list = policy
/// declared no translations for this slot (defensive — engine traps
/// on unresolved refs before they reach this layer).
///
/// Mirror of `dto::Translations`. Named for what it actually
/// contains; the WIT-level concept `localized-text` is `{key +
/// translations}`, a different shape.
export type Translations = LocalizedString[];

/// One consented field as it appears on the applicant's consent
/// screen. `key` is the policy-declared text-ref — opaque string,
/// shown raw on the consent UI for non-canonical names (see
/// `KNOWN_GOOD_KEYS` in `components/ConsentScreen`). `label` is the
/// host-resolved multi-language text (`pickLocalized` picks the
/// user's locale). `value` is the actual data.
///
/// Mirror of `dto::ConsentFieldView`. Distinct from the
/// sealed-envelope `DisplayField` shape (`{ key, value }` only) on
/// the consumer side — the frontend never reads the envelope, so
/// only this view shape is modelled here.
export type ConsentFieldView = {
  key: string;
  label: Translations;
  value: string;
};

// --- Suspended request shapes (mirror RequestView) ---

export type CameraFacing = "front" | "rear" | "any";

export type CaptureGuide =
  | { kind: "none" }
  | { kind: "rect"; aspect: number }
  | { kind: "oval" };

export type CaptureStep = {
  /// Optional text-ref naming a frontend-bundled artifact icon.
  /// `null` skips the icon area entirely. Otherwise the frontend
  /// looks the name up in its bundled SVG library; unknown names
  /// render as no icon (graceful fallback across host releases —
  /// new policies can request new icons without breaking old
  /// frontends).
  icon: string | null;
  /// Pre-capture intro body, paired with `icon` on the intro
  /// screen for this step.
  instructions: Translations;
  /// Short on-camera overlay text shown during capture.
  label: Translations;
  camera: CameraFacing;
  guide: CaptureGuide;
  /// Post-capture review-screen copy ("Make sure the MRZ is sharp,
  /// no glare"). Policy-supplied via `capture-step.review-hint` so
  /// each artifact type gets its own targeted check.
  review_hint: Translations;
};

export type MediaSpec = {
  label: Translations;
  captures: CaptureStep[];
};

export type RequestView =
  | {
      kind: "media";
      /// Overall artifact title surfaced on every screen of the
      /// capture flow as context ("Your passport").
      label: Translations;
      captures: CaptureStep[];
      /// Step indices already captured (subset of 0..captures.length).
      filled: number[];
      /// Slot id to POST the next step to (`/input/<slot_id>`).
      next_slot_id: string;
    }
  | {
      kind: "consent";
      fields: ConsentFieldView[];
      reason: Translations;
      /// Policy-supplied name of the party requesting verification
      /// ("Acme Trading"). Rendered prominently in the consent
      /// screen header so the applicant knows to whom the
      /// disclosure is being made — distinguishes the consumer
      /// (the receiving party) from the Enclavid platform (which
      /// runs the check but never reads the data).
      requester: Translations;
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
