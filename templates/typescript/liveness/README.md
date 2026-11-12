# A liveness check by video, in TypeScript on QuickJS

The applicant records a short video of well-known's guides of a check by
turns: their face in an oval of a size picked at random, then a turn of the
head to one side and to the other, the first side picked at random. The
session ends approved when the applicant followed every guide — the face held
in the oval, the head turned as asked — and the face held in the oval looks
live; rejected when not. A video not taken within its time limit is asked for
once more, with new values. Nothing is disclosed and nothing is kept: the
consumer learns the decision alone.

What it stops: a photo or a print held up to the camera, which does not turn
as asked; a replay on a screen, where the face-liveness implementation the
session pins reads it as not live; and a video recorded beforehand, since the
page is given the oval's size and the turns only once the applicant starts.
What it does not stop: a camera replaced by software that draws a face as it
is asked, nor a person other than the one a document shows: matching faces is
a plugin of its own.

It is built and pushed as the [kyc template](../kyc/README.md) is, which also
covers props, texts, disclosure fields and the runtime:

```
npm install
npm run build
enclavid oci push dist/policy.wasm <registry>/<repository>:<tag>
```

## What is where

- `src/policy.ts` — the policy. The constants at its top are what to tune: the
  attempts, and how live the face held in the oval must look. Whether each
  guide was followed is face-detect's to read.
- `wit/world.wit` — what it imports (the plugins below) and exports. It shows
  no texts of its own — the video's are well-known's — takes no props and
  discloses no field, so it has no slot.
- `wit/deps/` — the WIT it builds against: the platform's, and each plugin's
  package. Well-known's package names the slot of its texts, so that comes
  along too (`well-known-texts`); the policy does not import it.

## Plugins

The consumer pins an implementation of each when it creates a session:

- `enclavid:well-known` — the guides of a check by turns, drawn from a seed
  the policy picks at random for each attempt, and the video step that asks
  them.
- `enclavid:vision` — the face's geometry, which the face plugins share. The
  video itself is decoded by the platform, into the frames the face plugins
  read their patches of.
- `enclavid:face-detect` — reads the face in the frames of each guide: whether
  it filled the oval and turned as asked, by the rules the page holds the
  guides to, and where it was. Its guides are copies of the platform's, so the
  policy hands them over as they are.
- `enclavid:face-liveness` — how live the face held in the oval looks.

Which model reads the face is the implementation's, chosen by the pin. The
repository's `plugins/README.md` says how the platform's are built and pushed.
