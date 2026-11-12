# An age check by selfie, in TypeScript on QuickJS

The applicant takes a selfie; the policy reads the age of the face in it; the
session ends approved when that age is at least the consumer's `min-age`, and
rejected when it is not. The page takes the selfie once the face fills its
oval; the policy reads the face against that oval again, and a selfie whose
face does not fill it — half a face, a face off to the side, two faces — is
asked for again. Nothing is disclosed and nothing is kept: the consumer learns
the decision alone.

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
  package. Well-known's package names the slot of its texts, so that comes
  along too (`well-known-texts`); the policy does not import it.

## Plugins

The consumer pins an implementation of each when it creates a session:

- `enclavid:well-known` — the selfie's capture spec, with the face guide whose
  oval the page takes it in.
- `enclavid:vision` — the face's geometry, which the face plugins share. The
  selfie itself is decoded by the platform, into the image the face plugins
  read their patches of.
- `enclavid:face-detect` — reads the face against the guide the selfie was
  taken to: whether it fills the oval, the only face there, and where it is.
- `enclavid:face-age` — reads the face's age.

Which model reads the face is the implementation's, chosen by the pin. The
repository's `plugins/README.md` says how the platform's are built and pushed.

## Props

```json
{ "policy": "…", "props": { "min-age": 18 } }
```

`min-age` is the age the face must be read as, at least, for the session to be
approved. A face's age is an estimate, as close as the face-age implementation
the session pins reads it, so a check of 18 may ask for more.
