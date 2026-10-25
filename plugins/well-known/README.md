# enclavid:well-known

Canonical KYC field labels and pre-baked capture flows for Enclavid
policies. Drop-in helpers so policy authors don't hand-roll text-refs
for standard data shapes. Icons are not this plugin's: a capture step
names one of the host's own (`enclavid:host-icons/icons`).

## What it provides

- **`disclosure-fields`** — `DisplayField` constructors for 17 common
  KYC fields. Each takes one of the policy's disclosure fields and a
  value, and returns a `display-field` of that field whose `label` is
  the plugin's text for it.
- **`capture`** — `MediaSpec`/`CaptureStep` constructors for the four
  standard capture flows: passport, ID card, driver's license,
  selfie. Each returns a complete `media-spec` ready for
  `action::render(prompt::media)`; multi-side documents include
  front+back as separate steps.
- **Its texts**, in its slot `enclavid-ext:well-known/i18n`: the
  labels and the captures' texts. A policy may import them to label
  fields of its own.

## Usage from a policy

```rust
use enclavid::well_known::{capture, disclosure_fields};
use enclavid_ext::policy::disclosure_fields::{Key as Field, disclosure_field};

// One-line passport capture (single step, rear camera, ICAO TD3 aspect):
let action = Action::Render(Prompt::Media(capture::passport()));

// One-line consent screen:
let action = Action::Render(Prompt::ConsentDisclosure(Disclosure {
    fields: vec![
        disclosure_fields::passport_number(disclosure_field(Field::PassportNumber), "P12345678"),
        disclosure_fields::given_name(disclosure_field(Field::GivenName), "John"),
        disclosure_fields::family_name(disclosure_field(Field::FamilyName), "Smith"),
        disclosure_fields::date_of_birth(disclosure_field(Field::DateOfBirth), "1990-01-15"),
    ],
    reason,
    requester,
}));
```

## What a policy declares

Every text the plugin shows — the fields' labels, the captures'
titles, instructions and hints — is its own (`i18n/en.json`), so a
policy declares none of them.

A field's key reaches the consumer, so it is the policy's: a case of
the `key` in its `enclavid-ext:policy/disclosure-fields`, which it
mints the field from and hands the helper. List the fields you
disclose, by convention named as the helpers are:

```wit
package enclavid-ext:policy@0.1.0 {
    interface disclosure-fields {
        use enclavid:host/types@0.1.0.{disclosure-field-ref};

        enum key {
            passport-number,
            given-name,
            family-name,
            date-of-birth,
        }

        disclosure-field: func(key: key) -> disclosure-field-ref;
    }
}
```

Its WIT is two packages: `enclavid:well-known` (`wit/`), the helpers,
and `enclavid-ext:well-known` (`ext/`), its texts. A policy vendors
both.

## OCI artifacts

Plugin is published as **two separate OCI artifacts** following the
two-artifact pattern:

- **WIT packages** — `enclavid:well-known@0.1.0` and its slot,
  `enclavid-ext:well-known@0.1.0`. Interface contracts only. Consumed
  by `wkg wit fetch` at policy build time.
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

# 4. Publish the WIT packages (interface contracts, for `wkg wit
#    fetch`): the helpers, and the texts in the plugin's slot, which the
#    helpers' world imports.
wkg wit build --wit-dir wit -o target/well-known-wit.wasm
wkg wit build --wit-dir ext -o target/well-known-ext-wit.wasm
wkg publish target/well-known-wit.wasm
wkg publish target/well-known-ext-wit.wasm
# → enclavid:well-known@0.1.0, enclavid-ext:well-known@0.1.0 (WIT packages)

# 5. Embed the plugin's texts (`i18n/`), checked against the keys of
#    its slot's `i18n` — `enclavid-ext:well-known`, named for its
#    package. No disclosure fields — the policy is the single bandwidth
#    gate for those. `embed` also asserts this is a plugin (it must NOT
#    export `enclavid:policy/policy`) and rejects a core module — so
#    step 3 (componentize) is required before it.
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
on pull. Step 4's `wkg publish` of the WIT *packages* is separate — it
publishes the interface contracts so policies / other plugins can `wkg
wit fetch` them; it does not ship the implementation.

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
