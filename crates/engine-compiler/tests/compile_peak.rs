//! What a compile holds at its peak, against the data its composition carries:
//! about three times — the fused component, and wasmtime's memory image and
//! object on their way to the cwasm — and no more. What the compile-worker's
//! memory max is sized by. Linux only: the peak read is the process's own,
//! reset once the inputs are built.

#![cfg(target_os = "linux")]

use engine_compiler::Compiler;
use engine_types::composition::PluginInstance;
use wasm_encoder::{
    Component, ConstExpr, DataSection, InstanceSection, MemorySection, MemoryType, Module,
    ModuleArg, ModuleSection,
};

const DATA: usize = 128 << 20;

/// A component instantiating one module whose memory starts with `len`
/// non-zero bytes, so the whole segment stays in the memory image.
fn weights(len: usize) -> Vec<u8> {
    let mut module = Module::new();
    let mut memories = MemorySection::new();
    memories.memory(MemoryType {
        minimum: (len as u64).div_ceil(65536),
        maximum: None,
        memory64: false,
        shared: false,
        page_size_log2: None,
    });
    module.section(&memories);
    let mut data = DataSection::new();
    data.active(0, &ConstExpr::i32_const(0), std::iter::repeat_n(0x5a, len));
    module.section(&data);
    drop(data);
    let mut component = Component::new();
    component.section(&ModuleSection(&module));
    drop(module);
    let mut instances = InstanceSection::new();
    instances.instantiate(0, std::iter::empty::<(&str, ModuleArg)>());
    component.section(&instances);
    component.finish()
}

fn status(field: &str) -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find(|l| l.starts_with(field)).unwrap();
    let kib: u64 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
    kib << 10
}

#[test]
fn a_compile_holds_its_data_about_three_times_at_its_peak() {
    let compiler = Compiler::new().unwrap();
    let before = status("VmRSS:");
    let policy = Component::new().finish();
    let plugins = vec![PluginInstance {
        package: "test:weights".into(),
        wasm: weights(DATA),
    }];
    // From here the peak is what is resident now — the inputs — and whatever
    // the compile adds to it.
    std::fs::write("/proc/self/clear_refs", "5").unwrap();
    let cwasm = compiler.compile_to_parts(policy, plugins).unwrap().cwasm;
    let peak = status("VmHWM:") - before;
    assert!(cwasm.len() > DATA, "the data is in the cwasm");
    assert!(
        peak < DATA as u64 * 7 / 2,
        "{} MiB held at the peak for {} MiB of data",
        peak >> 20,
        DATA >> 20,
    );
}
