fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("../../proto/blob_store.proto")?;
    tonic_build::compile_protos("../../proto/list_store.proto")?;
    tonic_build::compile_protos("../../proto/state.proto")?;
    tonic_build::compile_protos("../../proto/report.proto")?;
    Ok(())
}
