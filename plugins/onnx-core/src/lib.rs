//! Generic in-sandbox ONNX inference via tract — reusable by any vision ML
//! plugin. Loads a model (real ONNX or a no-op placeholder), runs a flat
//! tensor, returns the raw output floats. Knows nothing about images or
//! WIT: the plugin supplies the preprocessed tensor and interprets the
//! output (channel order / normalization / output decode are the plugin's
//! model-specific concern). This crate hides tract behind [`Model`] /
//! [`load`] / [`noop`] / [`run`] so plugins need no direct tract dependency.

use tract_onnx::prelude::*;
use tract_onnx::tract_core::ops::math;

/// A loaded, runnable model.
pub type Model = TypedRunnableModel<TypedModel>;

pub use tract_onnx::prelude::TractResult;

/// Load an ONNX model from bytes and optimize it into a runnable.
pub fn load(bytes: &[u8]) -> TractResult<Model> {
    tract_onnx::onnx()
        .model_for_read(&mut &bytes[..])?
        .into_optimized()?
        .into_runnable()
}

/// A shape-correct no-op model (`input * 2`, `shape` in and out) so a
/// pipeline runs end-to-end before a real model is embedded — the output
/// simply mirrors the input. (tract typed binary ops require RANK match,
/// so the scalar constant is a rank-N all-ones shape.)
pub fn noop(shape: &[usize]) -> TractResult<Model> {
    let mut model = TypedModel::default();
    let input = model.add_source("input", f32::fact(shape))?;
    let ones = vec![1usize; shape.len()];
    let two = model.add_const("two", Tensor::from_shape(&ones, &[2.0f32])?)?;
    let scaled = model.wire_node("scale", math::mul(), &[input, two])?;
    model.set_output_outlets(&[scaled[0]])?;
    model.into_runnable()
}

/// Run a flat tensor (`shape` + row-major `data`) through the model and
/// return the raw first output as floats.
pub fn run(model: &Model, shape: &[usize], data: Vec<f32>) -> TractResult<Vec<f32>> {
    let input = Tensor::from_shape(shape, &data)?;
    let outputs = model.run(tvec![input.into_tvalue()])?;
    Ok(outputs[0].as_slice::<f32>()?.to_vec())
}
