//! A round loads its composition's cwasm without copying it: the code is mapped
//! from the file, and so is each linear memory's first image, so data a round
//! only reads is the file's pages rather than its own. What the sizing of a
//! round, and of the cache that holds the file, rests on. Linux only: it reads
//! the process's own mappings.

#![cfg(target_os = "linux")]

use engine_compiler::Compiler;
use engine_executor::{Executor, PluginInstance};
use wasm_encoder::{
    Component as Encoded, ConstExpr, DataSection, InstanceSection, MemorySection, MemoryType,
    Module, ModuleArg, ModuleSection,
};
use wasmtime::Store;
use wasmtime::component::Linker;

const DATA: usize = 64 << 20;

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
    let mut component = Encoded::new();
    component.section(&ModuleSection(&module));
    drop(module);
    let mut instances = InstanceSection::new();
    instances.instantiate(0, std::iter::empty::<(&str, ModuleArg)>());
    component.section(&instances);
    component.finish()
}

fn anonymous() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find(|l| l.starts_with("RssAnon:")).unwrap();
    let kib: u64 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
    kib << 10
}

fn mappings_of(needle: &str) -> usize {
    std::fs::read_to_string("/proc/self/maps")
        .unwrap()
        .lines()
        .filter(|l| l.contains(needle))
        .count()
}

#[test]
fn loading_a_cwasm_maps_its_data_rather_than_copying_it() {
    let plugins = vec![PluginInstance {
        package: "test:weights".into(),
        wasm: weights(DATA),
    }];
    let cwasm = Compiler::new()
        .unwrap()
        .compile_to_parts(Encoded::new().finish(), plugins)
        .unwrap()
        .cwasm;
    let path = std::env::temp_dir().join(format!("load-copies-{}.cwasm", std::process::id()));
    std::fs::write(&path, &cwasm).unwrap();
    drop(cwasm);

    let before = anonymous();
    let component = Executor::new()
        .unwrap()
        .deserialize_component_file(&path)
        .unwrap();
    let mut store = Store::new(component.engine(), ());
    store.set_fuel(u64::MAX).unwrap();
    let _instance = Linker::<()>::new(component.engine())
        .instantiate(&mut store, &component)
        .unwrap();
    let grown = anonymous().saturating_sub(before);
    let from_file = mappings_of(path.to_str().unwrap());
    let own_image = mappings_of("wasm-memory-image");
    std::fs::remove_file(&path).unwrap();

    assert_eq!(own_image, 0, "wasmtime made an image of its own");
    assert!(from_file > 0, "the cwasm is mapped from its file");
    assert!(
        grown < DATA as u64 / 4,
        "{} MiB of anonymous memory for {} MiB of data",
        grown >> 20,
        DATA >> 20,
    );
}
