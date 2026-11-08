# Plugins

Each directory here is one plugin: a WebAssembly component that a consumer
pins, by its package, when it creates a session, and that the enclave composes
with the policy. They are built for `wasm32-unknown-unknown` in this one
workspace.

| Plugin | Package | What it does |
|---|---|---|
| `well-known/` | `enclavid:well-known` | The capture specs (passport, selfie) and the labels of the KYC fields, in its own texts |
| `vision/` | `enclavid:vision` | The face geometry every plugin that reads a face shares; types alone — the platform decodes captures into the host's `image` |
| `face-detect/` | `enclavid:face-detect` | Finds the face in an image |
| `face-age/` | `enclavid:face-age` | Estimates the age of the face found |
| `face-liveness/` | `enclavid:face-liveness` | Estimates whether the face found is a live person's, in one picture (`image`) or over a video's frames (`video`) |

The vision plugin is the only one that reads the capture's bytes. The face
plugins take the frame it decoded, and each reads from it only the patch it
asks for, at the size its model takes.

## A plugin's directory

- `wit/` — its package: what it exports, which a policy imports.
- `ext/` — its slot, `enclavid-ext:<plugin>`, if it has one: the keys of its
  texts, or the models the host runs for it.
- `i18n/` — its texts, one JSON file per language.
- `src/` — its code.
- `wkg.toml` — where its WIT dependencies come from; `wkg wit fetch` copies
  them into `wit/deps/`.

## Models

The face plugins are built without a model by default: a placeholder, which
the engine's tests run on. Built with its feature, each hands its crop to
a model the host runs in a process of its own. A model's files are layers
pushed beside the component, named for the function of the plugin's slot that
hands the model out:

- face-detect, `--features blazeface`: `detector.onnx` — MediaPipe's BlazeFace
  (short range) with its decoding in the graph, as `garavv/blazeface-onnx`
  exports it (`blaze.onnx`). Apache-2.0, by MediaPipe's model card.
- face-age, `--features mivolo`: `age.onnx` and `age.onnx.data` — MiVOLO v2
  (`iitolstykh/mivolo_v2`, Apache-2.0), exported to ONNX with its weights as
  external data.
- face-liveness, `--features minifasnet`: `minifasnet-v2.onnx` and
  `minifasnet-v1se.onnx` — MiniFASNetV2 (`2.7_80x80_MiniFASNetV2.pth`) and
  MiniFASNetV1SE (`4_0_0_80x80_MiniFASNetV1SE.pth`) from
  `minivision-ai/Silent-Face-Anti-Spoofing` (Apache-2.0), exported to ONNX with
  `torch.onnx.export` at opset 13, a softmax added after each.

The model files are not in this repository.
`enclavid plugin validate <plugin> --models <dir>` checks a directory of them
against what the slot declares.

## Build and publish

```
cargo xtask build-plugins target/plugins
enclavid oci push target/plugins/well-known.wasm <registry>/<repository>/well-known:<tag>
enclavid oci push target/plugins/vision.wasm <registry>/<repository>/vision:<tag>
enclavid oci push target/plugins/face-detect.wasm <registry>/<repository>/face-detect:<tag> --models <dir with detector.onnx>
enclavid oci push target/plugins/face-age.wasm <registry>/<repository>/face-age:<tag> --models <dir with age.onnx and age.onnx.data>
enclavid oci push target/plugins/face-liveness.wasm <registry>/<repository>/face-liveness:<tag> --models <dir with minifasnet-v2.onnx and minifasnet-v1se.onnx>
```

`build-plugins` builds each plugin as it is published — the face plugins with
their feature — through the same pipeline the engine's tests build them with.
