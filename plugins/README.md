# Plugins

Each directory here is one plugin: a WebAssembly component that a consumer
pins, by its package, when it creates a session, and that the enclave composes
with the policy. They are built for `wasm32-unknown-unknown` in this one
workspace.

| Plugin | Package | What it does |
|---|---|---|
| `well-known/` | `enclavid:well-known` | The standard guides, the capture specs (passport, selfie, the liveness video) and the labels of the KYC fields, in its own texts |
| `face-detect/` | `enclavid:face-detect` | Finds the face in an image, and reads it against the guides of a capture, by the page's own rules: a photo's static guide (`photo`), a video's guides (`video`), in its copies of the platform's guides (`guides`) |
| `face-age/` | `enclavid:face-age` | Estimates the age of the face found |
| `face-liveness/` | `enclavid:face-liveness` | Estimates whether the face found is a live person's, in one picture (`image`) or over a video's frames (`video`) |

The platform decodes a capture into the host's `image`; the face plugins
each read from it only the patch they ask for, at the size their model
takes. face-detect's `types` say what a face it finds is; face-age and
face-liveness take the same records, each in its own `types`, so a policy
hands a face over as it is.

## A plugin's directory

- `wit-public/` — its package, what it exports, which a policy imports: the
  contract, in `world.wit`. It is what is published, and what a policy's
  project copies or fetches.
- `wit/` — how this implementation is built: its slot, `enclavid-ext:<plugin>`
  — the keys of its texts, or the models the host runs for it — and the world
  it is built as, the contract with its slot. It is the implementation's own,
  and is not published.
- `i18n/` — its texts, one JSON file per language.
- `src/` — its code.
- `wkg.toml` — where its WIT dependencies come from, the contract from
  `wit-public/`; `wkg wit fetch` copies them into `wit/deps/`.

## Models

Each face plugin hands its crop to a model the host runs in a process of its
own. A model's files are layers pushed beside the component, named for the
function of the plugin's slot that hands the model out:

- face-detect: `detector.onnx` — MediaPipe's BlazeFace (short range) with its
  decoding in the graph, as `garavv/blazeface-onnx` exports it (`blaze.onnx`).
  Apache-2.0, by MediaPipe's model card.
- face-age: `age.onnx` and `age.onnx.data` — MiVOLO v2
  (`iitolstykh/mivolo_v2`, Apache-2.0), exported to ONNX with its weights as
  external data.
- face-liveness: `minifasnet-v2.onnx` and `minifasnet-v1se.onnx` —
  MiniFASNetV2 (`2.7_80x80_MiniFASNetV2.pth`) and
  MiniFASNetV1SE (`4_0_0_80x80_MiniFASNetV1SE.pth`) from
  `minivision-ai/Silent-Face-Anti-Spoofing` (Apache-2.0), exported to ONNX with
  `torch.onnx.export` at opset 13, a softmax added after each.

The model files are not in this repository.
`enclavid plugin validate <plugin> --models <dir>` checks a directory of them
against what the slot declares. The engine's tests run where no model is, on
the face plugins' contracts as `test-faces` implements them, in the
executor's test fixtures.

## Build and publish

```
cargo xtask build-plugins target/plugins
enclavid oci push target/plugins/well-known.wasm <registry>/<repository>/well-known:<tag>
enclavid oci push target/plugins/face-detect.wasm <registry>/<repository>/face-detect:<tag> --models <dir with detector.onnx>
enclavid oci push target/plugins/face-age.wasm <registry>/<repository>/face-age:<tag> --models <dir with age.onnx and age.onnx.data>
enclavid oci push target/plugins/face-liveness.wasm <registry>/<repository>/face-liveness:<tag> --models <dir with minifasnet-v2.onnx and minifasnet-v1se.onnx>
```

`build-plugins` builds each plugin as it is published, through the same
pipeline the engine's tests build them with.
