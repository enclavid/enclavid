# enclavid:well-known

Canonical KYC field labels, standard guides and pre-baked captures for
Enclavid policies. Drop-in helpers so policy authors don't hand-roll
text-refs for standard data shapes. Icons are not this plugin's: a
capture step names one of the host's own (`enclavid:host-icons/icons`).

## What it provides

- **`disclosure-fields`** — `DisplayField` constructors for 17 common
  KYC fields. Each takes one of the policy's disclosure fields and a
  value, and returns a `display-field` of that field whose `label` is
  the plugin's text for it.
- **`shapes`** — the shapes a document or a selfie is photographed
  in: a passport's page, an ID-1 card, and a selfie's oval for a
  selfie taken with the shutter, the page reading no face.
- **`video-guides`** — ready sets of video guides for a check, their
  values drawn from a seed the policy picks at random: `liveness`.
  The plugin draws nothing at random itself.
- **`photo`** — `MediaSpec`/`CaptureStep` constructors for the four
  standard photo captures: passport, ID card, driver's license,
  selfie. Each returns a complete `media-spec` ready for
  `action::render(prompt::media)`; multi-side documents include
  front+back as separate steps.
- **`video`** — the liveness video: one step asking the guides it is
  given, with a time limit.
- **Its texts**, in its slot `enclavid-ext:well-known/i18n`: the
  labels and the captures' texts. A policy may import them to label
  fields of its own.

## Usage from a policy

```rust
use enclavid::well_known::{disclosure_fields, photo};
use enclavid_ext::policy::disclosure_fields::{Key as Field, disclosure_field};

// One-line passport capture (single step, rear camera, ICAO TD3 aspect):
let action = Action::Render(Prompt::Media(photo::passport()));

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
        use enclavid:host/refs@0.1.0.{disclosure-field-ref};

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

| Helper                            | Camera | Guides                                       |
| --------------------------------- | ------ | -------------------------------------------- |
| `photo.passport()`                | rear   | rect(1.42) — ICAO TD3; review screen         |
| `photo.id-card()` (front + back)  | rear   | rect(1.585) — ICAO TD1 (ID-1); review screen |
| `photo.drivers-license()` (f+b)   | rear   | rect(1.585) — ID-1; review screen            |
| `photo.selfie()`                  | front  | face(0.5), taken by the page; review screen  |
| `video.liveness(guides)`          | front  | `guides`; 60 s for all of them               |

`video-guides` holds two sets, each drawn from a seed and starting with
the face in an oval 0.40–0.55 wide, held 0.8 s. The same seed gives both
the same oval.

- `liveness-turns(seed)` — then a turn of the head by 20–30° to one side,
  then to the other, each held 0.5 s.
- `liveness-colors(seed)` — then flashes of 5 bright colours in that oval,
  0.3 s each.

If your KYC flow needs different settings (e.g., non-standard
document aspect), construct `CaptureStep` manually instead of using
the helper — the helper is opinionated for the common case.
