# enclavid:well-known

Canonical KYC field strings, icons, and pre-baked capture flows for
Enclavid policies. Drop-in helpers so policy authors don't hand-roll
text-refs for standard data shapes.

## What it provides

- **`icons`** — canonical icon names (`passport`, `id-card`,
  `drivers-license`, `selfie`) for `CaptureStep.icon`.
- **`disclosure-fields`** — `DisplayField` constructors for 17 common
  KYC fields. Each function returns a `display-field` with `key` and
  `label` set to canonical text-ref strings.
- **`capture`** — `MediaSpec`/`CaptureStep` constructors for the four
  standard capture flows: passport, ID card, driver's license,
  selfie. `*-spec` returns a complete `media-spec` ready for
  `prompt-media`; multi-side documents include front+back as
  separate steps.

## Usage from a policy

```rust
use enclavid::well_known::{disclosure_fields, capture, icons};

// One-line passport capture (single step, rear camera, ICAO TD3 aspect):
let clips = prompt_media(&capture::passport());

// One-line consent screen:
let consented = prompt_disclosure(&[
    disclosure_fields::passport_number("P12345678".into()),
    disclosure_fields::given_name("John".into()),
    disclosure_fields::family_name("Smith".into()),
    disclosure_fields::date_of_birth("1990-01-15".into()),
], reason_ref, requester_ref);
```

`use enclavid::well_known::{disclosure_fields, capture, icons}` —
explicit scope keeps short names without collisions
(`disclosure_fields::passport_number` vs `disclosure::prompt_disclosure`).

## Required `policy.json` registrations

All text-refs returned by the plugin must be pre-registered in the
consuming policy's `policy.json`. Without registration, the host's
text-ref membership check traps at use site.

Drop the snippet below into your `policy.json` — adjust translations
to your wording. Add only the fields/captures you actually use; you
don't need every entry.

```json
{
  "version": 1,
  "disclosure_fields": [
    "passport-number",
    "id-card-number",
    "drivers-license-number",
    "document-issuing-country",
    "document-expiry",
    "document-issued",
    "given-name",
    "family-name",
    "full-name",
    "date-of-birth",
    "sex",
    "nationality",
    "residence-country",
    "address",
    "email",
    "phone",
    "tax-id"
  ],
  "localized": {
    "passport-number-label":          { "en": "Passport number" },
    "id-card-number-label":           { "en": "ID card number" },
    "drivers-license-number-label":   { "en": "Driver's license number" },
    "document-issuing-country-label": { "en": "Issuing country" },
    "document-expiry-label":          { "en": "Document expiry date" },
    "document-issued-label":          { "en": "Document issue date" },
    "given-name-label":               { "en": "Given name" },
    "family-name-label":              { "en": "Family name" },
    "full-name-label":                { "en": "Full name" },
    "date-of-birth-label":            { "en": "Date of birth" },
    "sex-label":                      { "en": "Sex" },
    "nationality-label":              { "en": "Nationality" },
    "residence-country-label":        { "en": "Country of residence" },
    "address-label":                  { "en": "Residence address" },
    "email-label":                    { "en": "Email" },
    "phone-label":                    { "en": "Phone" },
    "tax-id-label":                   { "en": "Tax ID" },

    "passport-title":          { "en": "Your passport" },
    "passport-instructions":   { "en": "Have your passport open to the photo page. We'll take a quick 1-second capture — make sure you're in good lighting and the page lies flat." },
    "passport-step":           { "en": "Open to the photo page" },
    "passport-review-hint":    { "en": "Check the data page is sharp, with no glare or shadow over the text." },

    "id-card-title":                  { "en": "Your ID card" },
    "id-card-front-instructions":     { "en": "Place the front of your ID card flat under good lighting." },
    "id-card-front-step":             { "en": "Front side" },
    "id-card-front-review-hint":      { "en": "Check the front is sharp and the photo is visible." },
    "id-card-back-instructions":      { "en": "Now flip the card over." },
    "id-card-back-step":              { "en": "Back side" },
    "id-card-back-review-hint":       { "en": "Check the back is sharp and free of glare." },

    "drivers-license-title":                { "en": "Your driver's license" },
    "drivers-license-front-instructions":   { "en": "Place the front of your license flat under good lighting." },
    "drivers-license-front-step":           { "en": "Front side" },
    "drivers-license-front-review-hint":    { "en": "Check the front is sharp and the photo is visible." },
    "drivers-license-back-instructions":    { "en": "Now flip the license over." },
    "drivers-license-back-step":            { "en": "Back side" },
    "drivers-license-back-review-hint":     { "en": "Check the back is sharp and free of glare." },

    "selfie-title":          { "en": "Selfie verification" },
    "selfie-instructions":   { "en": "Hold your face inside the oval. We'll capture a short clip — keep still." },
    "selfie-step":           { "en": "Look at the camera" },
    "selfie-review-hint":    { "en": "Check your face is centered and well-lit." }
  }
}
```

## OCI artifacts

Plugin is published as **two separate OCI artifacts** following the
two-artifact pattern:

- **WIT package** — `enclavid:well-known@0.1.0`. Interface
  contract only. Consumed by `wkg wit fetch` at policy build time.
- **Component** — `enclavid/plugins/well-known:0.1.0`. The wasm
  implementation. Referenced by policy lockfile, pulled by TEE at
  runtime.

## Build & publish

```bash
cd plugins/well-known

# 1. Populate wit/deps/ from registry
wkg wit fetch

# 2. Compile to wasm core module (wasm32-unknown-unknown keeps the
#    output free of WASI imports — needed because TEE wasmtime
#    Linker doesn't provide WASI to plugin components).
cargo build --target wasm32-unknown-unknown --release

# 3. Componentize the core module into a proper wasm component.
#    Required even though `wasm-tools component wit` can read the
#    WIT custom section directly from a module — `wkg publish` and
#    other tools need a real `(component ...)` structure to
#    introspect `component.exports` / `component.imports`.
wasm-tools component new \
    target/wasm32-unknown-unknown/release/well_known.wasm \
    -o target/well-known.component.wasm

# 4. Publish WIT package (interface contract, for `wkg wit fetch`)
wkg wit build --wit-dir wit -o target/well-known-wit.wasm
wkg publish target/well-known-wit.wasm
# → enclavid:well-known@0.1.0 (WIT package)

# 5. Publish component (implementation, for runtime)
wkg oci push --insecure <registry-host> \
    <registry-host>/enclavid/plugins/well-known:0.1.0 \
    target/well-known.component.wasm
# → enclavid/plugins/well-known:0.1.0 (component)
```

`wkg publish` of the component blob auto-extracts `component.exports`
and `component.imports` into the OCI config blob (`vnd.wasm.config.v0+json`)
when given a real component — make sure step 3 runs before step 5.

## Capture settings (baked in by each helper)

| Helper                      | Camera | Guide                          |
| --------------------------- | ------ | ------------------------------ |
| `passport()`                | rear   | rect(1.42) — ICAO TD3          |
| `id-card()` (front + back)  | rear   | rect(1.585) — ICAO TD1 (ID-1)  |
| `drivers-license()` (f+b)   | rear   | rect(1.585) — ID-1             |
| `selfie()`                  | front  | oval                           |

If your KYC flow needs different settings (e.g., non-standard
document aspect), construct `CaptureStep` manually instead of using
the helper — the helper is opinionated for the common case.
