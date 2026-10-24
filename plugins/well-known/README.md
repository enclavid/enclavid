# enclavid:well-known

Canonical KYC field strings and pre-baked capture flows for Enclavid
policies. Drop-in helpers so policy authors don't hand-roll text-refs
for standard data shapes. Icons are not this plugin's: a capture step
names one of the host's own (`enclavid:host-icons/icons`).

## What it provides

- **`disclosure-fields`** — `DisplayField` constructors for 17 common
  KYC fields. Each function returns a `display-field` whose `key` is the
  field's canonical name — the function's own, `passport-number` — and
  whose `label` is the plugin's text for it.
- **`capture`** — `MediaSpec`/`CaptureStep` constructors for the four
  standard capture flows: passport, ID card, driver's license,
  selfie. Each returns a complete `media-spec` ready for
  `action::render(prompt::media)`; multi-side documents include
  front+back as separate steps.

## Usage from a policy

```rust
use enclavid::well_known::{capture, disclosure_fields};

// One-line passport capture (single step, rear camera, ICAO TD3 aspect):
let action = Action::Render(Prompt::Media(capture::passport()));

// One-line consent screen:
let action = Action::Render(Prompt::ConsentDisclosure(Disclosure {
    fields: vec![
        disclosure_fields::passport_number("P12345678"),
        disclosure_fields::given_name("John"),
        disclosure_fields::family_name("Smith"),
        disclosure_fields::date_of_birth("1990-01-15"),
    ],
    reason,
    requester,
}));
```

## What a policy declares

Every text the plugin shows — the fields' labels, the captures'
titles, instructions and hints — is its own (`i18n/en.json`), so a
policy declares none of them.

A field's key reaches the consumer, so it is held to the policy's
disclosure fields: list the field of every helper you call, by the
helper's name, as a case of the `key` in your
`enclavid:host-ext/disclosure-fields`. A helper whose field the policy
didn't list traps at runtime. List only the fields you use:

```wit
package enclavid:host-ext@0.1.0 {
    interface disclosure-fields {
        use enclavid:host/types@0.1.0.{disclosure-field-ref};

        enum key {
            passport-number,
            id-card-number,
            drivers-license-number,
            document-issuing-country,
            document-expiry,
            document-issued,
            given-name,
            family-name,
            full-name,
            date-of-birth,
            sex,
            nationality,
            residence-country,
            address,
            email,
            phone,
            tax-id,
        }

        disclosure-field: func(key: key) -> disclosure-field-ref;
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

# 5. Embed the plugin's texts (`i18n/`), checked against the keys of
#    its `i18n` interface, and rename its texts' import to the slot its
#    catalog names. No disclosure fields — the policy is the single
#    bandwidth gate for those. `embed` also asserts this is a plugin (it
#    must NOT export `enclavid:policy/policy`) and rejects a core module
#    — so step 3 (componentize) is required before it.
enclavid plugin embed target/well-known.component.wasm \
    -o target/well-known.embedded.wasm

# (optional) lint the texts standalone:
enclavid plugin validate .

# 6. Push the embedded component. `oci push` is role-agnostic — the same
#    command pushes a policy. Auth comes from the docker-config chain
#    after `enclavid cloud login`, or pass `--auth "Bearer <token>"`.
enclavid oci push target/well-known.embedded.wasm \
    <registry-host>/enclavid/plugins/well-known:0.1.0
# → enclavid/plugins/well-known:0.1.0 (embedded component)
```

The component (steps 3–5) ships as a single `application/wasm` OCI
layer, integrity-pinned by digest; the TEE re-verifies the layer digest
on pull. Step 4's `wkg publish` of the WIT *package* is separate — it
publishes the interface contract so policies / other plugins can `wkg
wit fetch` it; it does not ship the implementation.

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
