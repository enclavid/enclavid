fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Only the sealed domain types remain prost-generated. The wire
    // protos (auth/registry/session_store) were replaced by serde DTOs
    // in `broker-protocol`. No tonic / service codegen.
    prost_build::compile_protos(&["../../proto/state.proto"], &["../../proto"])?;
    Ok(())
}
