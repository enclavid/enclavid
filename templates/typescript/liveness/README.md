# A liveness check by video, in TypeScript on QuickJS

The applicant records a short video: their face in an oval of a size picked at
random, held there while the screen flashes colours, then a turn of the head
to one side and to the other, the first side picked at random. The session ends
approved when every checked frame holds a face, the face filled the oval, it
turned as asked and it looks live; rejected when not. A video not taken within
its time limit is asked for once more, with new values. Nothing is disclosed
and nothing is kept: the consumer learns the decision alone.

The flashes are shown, not checked: what they cast on the face is read by a
check of its own, which this template does not run.

What it stops: a photo or a print held up to the camera, which does not turn
as asked; most replays on a screen, which MiniFASNet reads as not live; and a
video recorded beforehand, since the page is given the oval's size and the
turns only once the applicant starts. What it does not stop: a camera replaced
by software that draws a face as it is asked, nor a person other than the one
a document shows: matching faces is a plugin of its own.

It is built and pushed as the [kyc template](../kyc/README.md) is, which also
covers props, texts, disclosure fields and the runtime:

```
npm install
npm run build
enclavid oci push dist/policy.wasm <registry>/<repository>:<tag>
```

## What is where

- `src/policy.ts` — the policy. The constants at its top are what to tune: the
  attempts, the time limit, how live the frames must look, how closely the face
  must fill the oval, and how far it must turn.
- `i18n/en.json` — its texts: the video's title, instructions and label.
- `wit/world.wit` — what it imports (the plugins below, its texts and the
  step's icon) and exports. It discloses no field and takes no props.
- `wit/deps/` — the WIT it builds against: the platform's, and each plugin's
  package. The face plugins' packages name their slots, the models the host
  runs for them, so those come along too (`face-detect-models`,
  `face-liveness-models`); the policy imports neither.

## Plugins

The consumer pins an implementation of each when it creates a session:

- `enclavid:vision` — the face's geometry, which the face plugins share. The
  video itself is decoded by the platform, into the frames the face plugins
  read their patches of.
- `enclavid:face-detect` — finds the face in each frame. Its build with
  BlazeFace carries the model as a layer, `detector.onnx`; the policy reads the
  turns from BlazeFace's keypoints, in its order.
- `enclavid:face-liveness` — how live the face looks in the frontal frames. Its
  build with MiniFASNet carries the models as layers, `minifasnet-v2.onnx` and
  `minifasnet-v1se.onnx`.

The repository's `plugins/README.md` says how each is built and pushed.
