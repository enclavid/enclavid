wit_bindgen::generate!({
    path: [
        "../../../../../wit/policy",
        "../../../../../wit/disclosure",
        "../../../../../wit/form",
        "wit",
    ],
    world: "enclavid:test-policy/policy",
    generate_all,
});

use enclavid::disclosure::disclosure::{prompt_disclosure, DisplayField};
use enclavid::form::media::{
    prompt_media, CameraFacing, CaptureGuide, CaptureStep, MediaSpec,
};
use exports::enclavid::policy::policy::{
    Decision, EvalArgs, Guest, LocalizedText, TextDecl, Translation,
};

struct TestPolicy;

// Constants the policy registers via `prepare-text-refs`. Every
// text-ref the policy passes to host fns at evaluate time must be
// declared here — the host enforces membership at every use-site.
// Declaring before any per-session input reaches the policy is what
// closes the runtime text-ref-crafting channel.
// `passport` is also the icon text-ref (registered as an identifier
// below); the frontend looks it up in its bundled SVG library.
// Same string can do double duty because text-refs are a single
// namespace — the engine just checks membership at each use-site.
const KEY_PASSPORT_ICON: &str = "passport";
const KEY_PASSPORT_TITLE: &str = "passport-title";
const KEY_PASSPORT_INSTRUCTIONS: &str = "passport-instructions";
const KEY_PASSPORT_STEP: &str = "passport-step";
const KEY_PASSPORT_REVIEW_HINT: &str = "passport-review-hint";
const KEY_CONSENT_REASON: &str = "consent-reason";
const KEY_PASSPORT_NUMBER: &str = "passport-number";
const KEY_PASSPORT_NUMBER_LABEL: &str = "passport-number-label";

impl Guest for TestPolicy {
    fn prepare_text_refs() -> Vec<TextDecl> {
        vec![
            // Identifier-only — machine key for the consent field;
            // shown raw on the consent screen for non-canonical
            // names but never resolved to a localized string.
            TextDecl::Identifier(KEY_PASSPORT_NUMBER.into()),
            // Identifier-only — icon name. Frontend dispatches it
            // against its bundled SVG library; engine just checks
            // membership here.
            TextDecl::Identifier(KEY_PASSPORT_ICON.into()),
            // Translatable labels / reasons — one `Localized` per
            // key, carrying the full translation set. Adding a new
            // language is one more `Translation` row inside the
            // same `LocalizedText` block.
            TextDecl::Localized(LocalizedText {
                key: KEY_PASSPORT_TITLE.into(),
                translations: vec![Translation {
                    language: "en".into(),
                    value: "Your passport".into(),
                }],
            }),
            TextDecl::Localized(LocalizedText {
                key: KEY_PASSPORT_INSTRUCTIONS.into(),
                translations: vec![Translation {
                    language: "en".into(),
                    value: "Have your passport ready, open to the photo page. We'll take a quick \
1-second capture — make sure you're in good lighting and the page lies flat."
                        .into(),
                }],
            }),
            TextDecl::Localized(LocalizedText {
                key: KEY_PASSPORT_STEP.into(),
                translations: vec![Translation {
                    language: "en".into(),
                    value: "Open to the photo page".into(),
                }],
            }),
            TextDecl::Localized(LocalizedText {
                key: KEY_PASSPORT_REVIEW_HINT.into(),
                translations: vec![Translation {
                    language: "en".into(),
                    value: "Check that the data page is sharp, with no glare or shadow over the text.".into(),
                }],
            }),
            TextDecl::Localized(LocalizedText {
                key: KEY_CONSENT_REASON.into(),
                translations: vec![Translation {
                    language: "en".into(),
                    value: "Identity verification for the test policy.".into(),
                }],
            }),
            TextDecl::Localized(LocalizedText {
                key: KEY_PASSPORT_NUMBER_LABEL.into(),
                translations: vec![Translation {
                    language: "en".into(),
                    value: "Passport number".into(),
                }],
            }),
        ]
    }

    fn evaluate(_args: Vec<(String, EvalArgs)>) -> Decision {
        // Single-shot passport capture: one step, rear camera,
        // ICAO TD3 aspect for the on-screen frame guide.
        let _clips = prompt_media(&MediaSpec {
            label: KEY_PASSPORT_TITLE.into(),
            captures: vec![CaptureStep {
                icon: Some(KEY_PASSPORT_ICON.into()),
                instructions: KEY_PASSPORT_INSTRUCTIONS.into(),
                label: KEY_PASSPORT_STEP.into(),
                camera: CameraFacing::Rear,
                guide: CaptureGuide::Rect(1.42),
                review_hint: KEY_PASSPORT_REVIEW_HINT.into(),
            }],
        });
        let consented = prompt_disclosure(
            &[DisplayField {
                key: KEY_PASSPORT_NUMBER.into(),
                label: KEY_PASSPORT_NUMBER_LABEL.into(),
                value: "123456".into(),
            }],
            KEY_CONSENT_REASON,
        );
        if consented {
            Decision::Approved
        } else {
            Decision::Rejected
        }
    }
}

export!(TestPolicy);
