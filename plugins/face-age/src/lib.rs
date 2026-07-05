//! `enclavid:face-age` — facial age estimation from a selfie clip.
//!
//! The plugin reads the capture frames host-side via the `clip` resource
//! (the pixel bytes never enter the policy's memory) and returns an `age`
//! the policy acts on. The pipeline lives in [`infer`]: generic ONNX
//! runtime (`onnx-core`) + image prep (`vision`) + a compile-time model
//! PROFILE (the only face-age-specific part: input format + model + output
//! decode). Default builds run a no-op placeholder graph (no weights); the
//! `age-googlenet` feature embeds the real reference model.

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
    fn estimate(selfie: &Clip) -> Option<AgeEstimate> {
        // `None` = no frame decoded (unusable capture) → the policy asks
        // for a retake. The in-sandbox pipeline (DCT decode → crop →
        // normalize → tract) runs on the frames, which stay host-side.
        infer::estimate_age(&selfie.frames()).map(|age| AgeEstimate { age })
    }
}

export!(FaceAge);
