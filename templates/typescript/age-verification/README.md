# An age check by selfie, in TypeScript on QuickJS

The applicant takes a selfie; the policy reads the age of the face in it; the
session ends approved when that age is at least the consumer's `min-age`, and
rejected when it is not. A selfie with no face the policy can read is asked
for again. Nothing is disclosed and nothing is kept: the consumer learns the
decision alone.

It is built and pushed as the [kyc template](../kyc/README.md) is, which also
covers props, texts, disclosure fields and the runtime:

```
npm install
npm run build
enclavid oci push dist/policy.wasm <registry>/<repository>:<tag>
```

## What is where

- `src/policy.ts` — the policy.
- `wit/world.wit` — what it imports (the plugins below and its props) and
  exports. It shows no texts of its own — the selfie's are well-known's — and
  discloses no field, so it has neither `i18n/` nor a list of fields.
- `wit/deps/` — the WIT it builds against: the platform's, and each plugin's
  package. The face plugins' packages name their slots, the models the host
  runs for them, so those come along too (`face-detect-models`,
  `face-age-models`); the policy imports neither.

## Plugins

The consumer pins an implementation of each when it creates a session:

- `enclavid:well-known` — the selfie's capture spec.
- `enclavid:vision` — the face's geometry, which the face plugins share. The
  selfie itself is decoded by the platform, into the image the face plugins
  read their patches of.
- `enclavid:face-detect` — finds the face. Its build with BlazeFace carries the
  model as a layer, `detector.onnx`.
- `enclavid:face-age` — reads the face's age. Its build with MiVOLO carries the
  model as layers, `age.onnx` and `age.onnx.data`.

The repository's `plugins/README.md` says how each is built and pushed.

## Props

```json
{ "policy": "…", "props": { "min-age": 18 } }
```

`min-age` is the age the face must be read as, at least, for the session to be
approved. A face's age is read to within a few years either way, so a check of
18 may ask for more.
