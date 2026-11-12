// TypeScript mirrors of the public JSON wire types defined in
// `crates/api/src/dto.rs` and `crates/api/src/applicant/views.rs`.
// Keep these in sync — every shape change on the backend should land
// here in the same commit.

// --- Lifecycle ---

export type SessionStatus =
  | "unspecified"
  | "running"
  | "completed"
  | "init_failed"
  | "expired";

export type StatusResponse = {
  status: SessionStatus;
};

// --- Consent display fields (mirror dto::DisplayField) ---

/// One consented field as it appears on the applicant's consent
/// screen. `key` is the policy-declared text-ref — opaque string,
/// always shown raw on the consent UI (the user is the sole auditor
/// on this screen; no canonical/custom distinction). `label` is
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

/// A shape drawn over the camera, which the page does not read (mirror
/// `ShapeView`).
export type Shape =
  /// A rectangle at the centre of the frame.
  | {
      kind: "rect";
      /// Its width:height aspect.
      aspect: number;
    }
  /// An oval at the centre of the frame.
  | {
      kind: "oval";
      /// As a fraction of the frame's shorter side.
      width: number;
      /// As a fraction of the frame's shorter side.
      height: number;
    };

/// What a photo's camera shows (mirror `PhotoGuideView`).
export type PhotoGuide =
  /// A shape the applicant fills, and says with the shutter they have.
  | {
      kind: "shape";
      shape: Shape;
      /// What the applicant fits into it, the policy's text.
      label: string;
    }
  /// A face the page finds in the oval it draws, and takes the photo of once
  /// it fills it.
  | {
      kind: "face";
      /// The oval's width, as a fraction of the frame's shorter side.
      width: number;
      /// Its height, as a fraction of the frame's shorter side.
      height: number;
    };

/// One thing a video asks (mirror `VideoGuideView`).
export type VideoGuide =
  /// A shape the applicant says with a button they have followed.
  | {
      kind: "shape";
      shape: Shape;
      /// What the applicant lines up with it, the policy's text.
      label: string;
      /// How long it is held after the button, in milliseconds.
      hold_ms: number;
    }
  /// A face the page finds at the centre of the frame, in an oval it draws.
  | {
      kind: "face";
      /// The oval's width, as a fraction of the frame's shorter side.
      width: number;
      /// Its height, as a fraction of the frame's shorter side.
      height: number;
      /// How long the face stays there, in milliseconds.
      hold_ms: number;
      /// The longest break in the hold the page forgives, in milliseconds.
      grace_ms: number;
    }
  /// A turn of the head the page reads.
  | {
      kind: "head_turn";
      /// How far, negative to the applicant's left.
      degrees: number;
      /// How long it is held, in milliseconds.
      hold_ms: number;
      /// The longest break in the hold the page forgives, in milliseconds.
      grace_ms: number;
    }
  /// A face the page finds in an oval, as for `face`, then lights with the
  /// screen around the oval, one colour after another.
  | {
      kind: "face_flashes";
      /// The oval's width, as a fraction of the frame's shorter side.
      width: number;
      /// Its height, as a fraction of the frame's shorter side.
      height: number;
      /// Each as `#rrggbb`, in the order shown.
      colors: string[];
      /// How long each is shown, in milliseconds.
      flash_ms: number;
      /// The longest break in the flashes the page forgives, in milliseconds.
      grace_ms: number;
    };

type CaptureStepCommon = {
  /// Optional icon name dispatched against the frontend's bundled
  /// SVG library. `null` skips the icon area entirely. The name is
  /// one of the host's own (`enclavid:host-icons/icons`).
  icon: string | null;
  /// Pre-capture intro body, paired with `icon` on the intro
  /// screen for this step. Already resolved to user's locale.
  instructions: string;
  /// Short on-camera overlay text shown during capture.
  label: string;
  camera: CameraFacing;
};

/// One step of a capture (mirror `CaptureStepView`), by what it records.
export type CaptureStep = CaptureStepCommon &
  (
    /// One frame.
    | {
        kind: "photo";
        /// What the camera shows, if anything.
        guide: PhotoGuide | null;
        /// Post-capture review-screen copy ("Make sure the MRZ is
        /// sharp, no glare"). Policy-supplied via `photo-spec.review-hint`
        /// so each artifact type gets its own targeted check; `null`: no
        /// review screen, the photo is sent as taken.
        review_hint: string | null;
      }
    /// A video, recorded while guides are shown.
    | {
        kind: "video";
        /// What the video asks, in order.
        guides: VideoGuide[];
      }
  );

export type PhotoStep = Extract<CaptureStep, { kind: "photo" }>;
export type VideoStep = Extract<CaptureStep, { kind: "video" }>;

/// A step of a prompt with a time limit the page has not started: what its
/// intro screen shows, not yet what it records — that comes with the start.
export type UnstartedStep = CaptureStepCommon & { kind?: undefined };

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
      /// Each step's capture is POSTed as it is taken, in order, to
      /// `/input/<awaiting_seq>/media-<step>`.
      captures: (CaptureStep | UnstartedStep)[];
      /// The step to show: the first whose capture is not sent yet.
      next_step: number;
      /// The most bytes the captures of the steps not sent yet may be
      /// together; past it the server answers 413.
      max_upload_bytes: number;
      /// The seconds the steps have together from their start; null for no
      /// limit.
      time_limit_secs: number | null;
      /// The milliseconds left of that limit, as the server counted them when
      /// it answered; null before the start, and where there is no limit.
      remaining_ms: number | null;
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
      /// Host-minted digest of this exact disclosure screen. Echoed
      /// back as `disclosure_hash` on the consent accept so the TEE
      /// can verify it still matches the disclosure it is about to
      /// seal — if the flow advanced since this screen was rendered
      /// (e.g. a stale tab), the accept is refused instead of sealing
      /// something the user never saw (show == seal).
      disclosure_digest: string;
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
  | {
      status: "awaiting_input";
      /// Which of the session's waits this is. The answer names it
      /// (`/input/<awaiting_seq>/<slot_id>`), so one composed for an
      /// earlier wait — a second tap, a second tab, a retry after a lost
      /// reply — is refused with the wait that is current.
      awaiting_seq: number;
      request: RequestView;
    };

