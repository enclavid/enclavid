fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("../../proto/session_store.proto")?;
    tonic_build::compile_protos("../../proto/report_store.proto")?;
    tonic_build::compile_protos("../../proto/state.proto")?;
    tonic_build::compile_protos("../../proto/report.proto")?;
    tonic_build::compile_protos("../../proto/registry.proto")?;
    tonic_build::compile_protos("../../proto/auth.proto")?;
    Ok(())
}
