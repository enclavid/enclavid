//! `enclavid:test-models` — a policy that runs its slot's models and returns
//! what they gave as its state: each output tensor's dimensions, then its
//! elements, little-endian, in order — `linear`'s, `split`'s three by name,
//! then `widen`'s. It hands `linear` out twice, so the round serves the second
//! from the first's process.

wit_bindgen::generate!({
    path: "wit",
    world: "enclavid:test-models/policy@0.1.0",
    generate_all,
});

use enclavid::host::tensors::{TensorF32, TensorU8};
use enclavid::policy::types::{Action, Decision, Event};
use enclavid_ext::policy::models;
use exports::enclavid::policy::policy::Guest;

struct TestModels;

impl Guest for TestModels {
    fn handle(_state: Vec<u8>, _event: Event) -> (Vec<u8>, Action) {
        let x: Vec<f32> = (0..6).map(|i| i as f32 * 0.5).collect();
        let x = TensorF32::new(&[2, 3], &x);
        let first = models::linear().run(&x);
        let again = models::linear().run(&x);
        assert_eq!(first.data(), again.data(), "one process, one answer");

        let a = TensorF32::new(&[4], &[1.0, 2.0, 3.0, 4.0]);
        let b = TensorF32::new(&[4], &[0.5, 0.25, 0.125, 0.0625]);
        let parts = models::split().run(&a, &b);

        let bytes = TensorU8::new(&[3], &[0, 7, 255]);
        let wide = models::widen().run(&bytes);

        let mut state = Vec::new();
        for tensor in [first, parts.a, parts.b, parts.sum, wide] {
            state.extend(tensor.dims().into_iter().flat_map(u64::to_le_bytes));
            state.extend(tensor.data().into_iter().flat_map(f32::to_le_bytes));
        }
        (state, Action::Finish(Decision::Approved))
    }
}

export!(TestModels);
