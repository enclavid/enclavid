use enclavid_host_bridge::{
    CameraFacing as ProtoCameraFacing, CaptureGroup as ProtoCaptureGroup,
    CaptureGuide as ProtoCaptureGuide, CaptureStep as ProtoCaptureStep, GuideNone, GuideOval,
    GuideRect, MediaRequest as ProtoMediaRequest, MediaSpec as ProtoMediaSpec, capture_guide,
    suspended,
};

use crate::enclavid::form::media::{
    AllOf, CameraFacing, CaptureGuide, CaptureStep, Clip, GroupResult, Host, MediaSpec,
};
use crate::host_state::HostState;
use crate::sanitize;

impl Host for HostState {
    /// Capture media according to `spec`. Returns one clip per
    /// `spec.captures` step in declaration order. Suspends the run
    /// until every step is filled — partial submissions land via
    /// `/input` and re-trigger this host fn until the data is
    /// complete.
    async fn prompt_media(&mut self, spec: MediaSpec) -> wasmtime::Result<Vec<Clip>> {
        validate_media_spec(&spec, &self.registered_text_refs)?;
        let proto_spec: ProtoMediaSpec = (&spec).into();

        let media_state = self
            .replay
            .current_suspended()
            .and_then(|s| s.request.as_ref())
            .and_then(|r| match r {
                suspended::Request::Media(m) => Some(m),
                _ => None,
            });

        let Some(media) = media_state else {
            // No suspended media for this call yet — suspend with the
            // empty clip map.
            return Err(suspended::Request::media(proto_spec).into());
        };

        // Replay-safety: if the policy's spec drifted between rounds
        // (different label, different captures), the cached clips are
        // attached to a stale request. Bail rather than silently mis-
        // bind clips to the new spec's steps.
        if media.spec.as_ref() != Some(&proto_spec) {
            return Err(wasmtime::Error::msg(
                "prompt-media spec changed between rounds",
            ));
        }

        let total_steps = spec.captures.len() as u32;
        let mut result: Vec<Clip> = Vec::with_capacity(total_steps as usize);
        for i in 0..total_steps {
            match media.clips.get(&i) {
                Some(c) if !c.frames.is_empty() => result.push(c.frames.clone()),
                _ => {
                    // Step `i` not yet captured — re-suspend, keeping
                    // whatever clips have already arrived so subsequent
                    // /input rounds can fill the remaining slots.
                    return Err(suspended::Request::media_with(
                        proto_spec,
                        media.clips.clone(),
                    )
                    .into());
                }
            }
        }
        Ok(result)
    }

    /// DNF of capture groups (OR of ANDs). Each `all-of` group lists
    /// the media specs the applicant must satisfy in order. Returns
    /// the captured clips for the alternative the applicant
    /// completed. Suspends until the applicant has filled enough
    /// specs to satisfy *some* alternative — `verification_set_data`
    /// is the running tape of `MediaRequest`s with their clip maps.
    async fn prompt_any_of(
        &mut self,
        any_of: Vec<AllOf>,
    ) -> wasmtime::Result<Vec<GroupResult>> {
        if any_of.is_empty() {
            return Err(wasmtime::Error::msg(
                "prompt_any_of called with no alternatives",
            ));
        }
        for (gi, group) in any_of.iter().enumerate() {
            if group.items.is_empty() {
                return Err(wasmtime::Error::msg(format!(
                    "prompt_any_of group {gi} is empty (no media specs)"
                )));
            }
            for spec in &group.items {
                validate_media_spec(spec, &self.registered_text_refs)?;
            }
        }
        let data = self
            .replay
            .current_suspended()
            .and_then(|s| s.request.as_ref())
            .and_then(|r| match r {
                suspended::Request::VerificationSet(vs) => vs.data.as_ref(),
                _ => None,
            });

        if let Some(data) = data {
            let results = data
                .items
                .iter()
                .map(media_request_to_result)
                .collect::<wasmtime::Result<Vec<_>>>()?;
            return Ok(results);
        }

        let proto_any_of = any_of.into_iter().map(all_of_to_proto).collect();
        Err(suspended::Request::verification_set(proto_any_of).into())
    }
}

/// Format + registration check for every text-ref inside a
/// `MediaSpec`. Same timing-based defence as `prompt_disclosure`:
/// every ref must be in the policy's frozen asset registry,
/// blocking runtime-crafted refs encoded with per-session user info.
///
/// `icon` is intentionally NOT checked — it's a free-form string
/// dispatched against the frontend's bundled SVG library. Unknown
/// names render with no icon (graceful fallback); polici doesn't
/// declare icons.
fn validate_media_spec(
    spec: &MediaSpec,
    registered: &std::collections::HashSet<String>,
) -> wasmtime::Result<()> {
    if spec.captures.is_empty() {
        return Err(wasmtime::Error::msg(
            "prompt_media / prompt_any_of spec has no capture steps",
        ));
    }
    sanitize::ensure_registered(&spec.label, registered, "prompt_media spec label")?;
    for step in &spec.captures {
        sanitize::ensure_registered(
            &step.instructions,
            registered,
            "prompt_media capture-step instructions",
        )?;
        sanitize::ensure_registered(
            &step.label,
            registered,
            "prompt_media capture-step label",
        )?;
        sanitize::ensure_registered(
            &step.review_hint,
            registered,
            "prompt_media capture-step review-hint",
        )?;
    }
    Ok(())
}

fn all_of_to_proto(g: AllOf) -> ProtoCaptureGroup {
    ProtoCaptureGroup {
        items: g.items.iter().map(ProtoMediaSpec::from).collect(),
    }
}

/// Materialise one finished `MediaRequest` (spec + full clips map)
/// into a `GroupResult`. Refuses incomplete payloads — the runtime
/// walking the verification-set keeps re-suspending until every
/// step of the chosen alternative has been filled, so seeing a hole
/// here is a host-side invariant break.
fn media_request_to_result(req: &ProtoMediaRequest) -> wasmtime::Result<GroupResult> {
    let spec = req.spec.as_ref().ok_or_else(|| {
        wasmtime::Error::msg("verification-set item missing media spec")
    })?;
    let total = spec.captures.len() as u32;
    let mut clips: Vec<Clip> = Vec::with_capacity(total as usize);
    for i in 0..total {
        match req.clips.get(&i) {
            Some(c) if !c.frames.is_empty() => clips.push(c.frames.clone()),
            _ => {
                return Err(wasmtime::Error::msg(
                    "verification-set item has unfilled capture step",
                ));
            }
        }
    }
    Ok(GroupResult { clips })
}

// --- WIT → proto conversions ---
//
// WIT types are generated inside this crate via `bindgen!`, so impls
// for `From<WitX> for ProtoY` are allowed (local trait parameter).

impl From<&MediaSpec> for ProtoMediaSpec {
    fn from(s: &MediaSpec) -> Self {
        Self {
            label_ref: s.label.clone(),
            captures: s.captures.iter().map(Into::into).collect(),
        }
    }
}

impl From<&CaptureStep> for ProtoCaptureStep {
    fn from(s: &CaptureStep) -> Self {
        Self {
            icon_ref: s.icon.clone(),
            instructions_ref: s.instructions.clone(),
            label_ref: s.label.clone(),
            camera: ProtoCameraFacing::from(s.camera) as i32,
            guide: Some(ProtoCaptureGuide::from(&s.guide)),
            review_hint_ref: s.review_hint.clone(),
        }
    }
}

impl From<CameraFacing> for ProtoCameraFacing {
    fn from(c: CameraFacing) -> Self {
        match c {
            CameraFacing::Front => Self::Front,
            CameraFacing::Rear => Self::Rear,
            CameraFacing::Any => Self::Any,
        }
    }
}

impl From<&CaptureGuide> for ProtoCaptureGuide {
    fn from(g: &CaptureGuide) -> Self {
        let kind = match g {
            CaptureGuide::None => capture_guide::Kind::None(GuideNone {}),
            CaptureGuide::Rect(aspect) => capture_guide::Kind::Rect(GuideRect { aspect: *aspect }),
            CaptureGuide::Oval => capture_guide::Kind::Oval(GuideOval {}),
        };
        Self { kind: Some(kind) }
    }
}
