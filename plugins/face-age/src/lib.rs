//! `enclavid:face-age` — facial age estimation from a selfie clip.
//!
//! The plugin reads the capture frames host-side via the `clip` resource
//! (the pixel bytes never enter the policy's memory) and returns an
//! `age-estimate` the policy acts on. Inference lives behind the
//! [`estimate_from_frames`] seam — the single point where a real
//! in-sandbox model drops in: DCT-scaled JPEG decode, a face crop on the
//! capture oval, and a tract-run ONNX age net (per model behind a build
//! feature; the model is embedded in this artifact and covered by its OCI
//! digest). Today that seam holds a deterministic STUB so the composition
//! + clip-read path is exercised end-to-end before the model lands.

mod infer;

// getrandom has no backend on wasm32-unknown-unknown (no OS, no WASI, no
// JS). tract pulls it only for hashmap seeding over trusted (embedded
// model) keys, so a deterministic no-op is safe — this plugin needs no
// entropy. Registering it lets the target link. Native builds (unit
// tests) use the OS backend, so this is wasm-only.
#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(no_entropy);
#[cfg(target_arch = "wasm32")]
fn no_entropy(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    buf.fill(0);
    Ok(())
}

wit_bindgen::generate!({
    path: "wit",
    world: "enclavid:face-age/face-age@0.1.0",
    generate_all,
});

use enclavid::host::types::Clip;
use exports::enclavid::face_age::check::{AgeEstimate, Guest};

struct FaceAge;

impl Guest for FaceAge {
    fn estimate(selfie: &Clip) -> AgeEstimate {
        // Pull the whole clip and run the in-sandbox pipeline (DCT decode
        // → crop → resize → normalize → tract). `None` means no frame
        // decoded — an unusable capture — which the policy reads as
        // confidence 0 and turns into a retake.
        match infer::estimate_age(&selfie.frames()) {
            Some(age) => AgeEstimate {
                age,
                confidence: 0.5,
            },
            None => AgeEstimate {
                age: 0.0,
                confidence: 0.0,
            },
        }
    }
}

export!(FaceAge);
